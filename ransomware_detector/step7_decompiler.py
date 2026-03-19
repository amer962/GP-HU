# -*- coding: utf-8 -*-
"""
STEP 7 — AI Decompiler (Machine Code → Pseudocode)
====================================================
بعد ما Kill Chain يوقف الرانسوم وير ويعمل memory dump:
    1. يستخرج binary code من الـ dump أو الـ exe
    2. يفككه (disassemble) إلى assembly
    3. يقسّمه لـ functions
    4. يرسله لـ Claude API يترجمه لـ pseudocode مقروء
    5. يولّد تقرير يشرح:
       - شو بيعمل الرانسوم وير
       - خوارزمية التشفير المستخدمة
       - مفاتيح التشفير إذا وجدت
       - نقاط الضعف (للمساعدة في فك التشفير)

المتطلبات:
    pip install capstone pefile requests

الاستخدام:
    decompiler = AIDecompiler()
    report = decompiler.analyze(exe_path="malware.exe")
    report = decompiler.analyze(dump_path="dumps/malware_1234.dmp")
"""

import os
import sys
import json
import time
import struct
import logging
import hashlib
import requests
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────
# Anthropic API
# ─────────────────────────────────────────────────────────
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL   = "claude-sonnet-4-20250514"

# ─────────────────────────────────────────────────────────
class Disassembler:
    """
    يفكك الـ binary إلى assembly instructions باستخدام capstone.
    """

    def __init__(self):
        try:
            import capstone
            self.cs_x86  = capstone.Cs(capstone.CS_ARCH_X86,  capstone.CS_MODE_32)
            self.cs_x64  = capstone.Cs(capstone.CS_ARCH_X86,  capstone.CS_MODE_64)
            self.cs_x86.detail = True
            self.cs_x64.detail = True
            self.capstone = capstone
            self.available = True
        except ImportError:
            logger.warning("capstone غير مثبّت — pip install capstone")
            self.available = False

    def disassemble_bytes(self, code: bytes, base_addr: int = 0,
                          mode: str = 'x64', max_insns: int = 200) -> list:
        """
        يفكك bytes إلى قائمة instructions.
        """
        if not self.available:
            return []

        cs = self.cs_x64 if mode == 'x64' else self.cs_x86
        instructions = []

        try:
            for insn in cs.disasm(code, base_addr):
                instructions.append({
                    'addr':     hex(insn.address),
                    'mnemonic': insn.mnemonic,
                    'op_str':   insn.op_str,
                    'asm':      f"{insn.mnemonic} {insn.op_str}".strip(),
                    'bytes':    insn.bytes.hex(),
                })
                if len(instructions) >= max_insns:
                    break
        except Exception as e:
            logger.error(f"Disassembly error: {e}")

        return instructions

    def format_asm_block(self, instructions: list) -> str:
        """يحوّل قائمة instructions لـ string مقروء"""
        lines = []
        for insn in instructions:
            lines.append(f"  {insn['addr']:>12}:  {insn['asm']:<40}  ; {insn['bytes']}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────
class PEAnalyzer:
    """
    يحلل PE (Portable Executable) ملفات — .exe و .dll
    يستخرج:
    - الـ imports (API calls اللي بيستخدمها)
    - الـ sections (code, data, ...)
    - الـ strings المضمّنة
    - معلومات الـ header
    """

    def __init__(self):
        try:
            import pefile
            self.pefile    = pefile
            self.available = True
        except ImportError:
            logger.warning("pefile غير مثبّت — pip install pefile")
            self.available = False

    def analyze(self, file_path: str) -> dict:
        result = {
            'path':         file_path,
            'is_pe':        False,
            'arch':         'unknown',
            'imports':      [],
            'sections':     [],
            'strings':      [],
            'entry_point':  None,
            'file_size':    0,
            'sha256':       '',
            'suspicious_imports': [],
        }

        if not self.available or not os.path.exists(file_path):
            return result

        # SHA256
        with open(file_path, 'rb') as f:
            data = f.read()
        result['sha256']    = hashlib.sha256(data).hexdigest()
        result['file_size'] = len(data)

        try:
            pe = self.pefile.PE(file_path)
            result['is_pe'] = True

            # Architecture
            if pe.FILE_HEADER.Machine == 0x8664:
                result['arch'] = 'x64'
            elif pe.FILE_HEADER.Machine == 0x14c:
                result['arch'] = 'x86'

            # Entry point
            result['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

            # Imports
            suspicious = {
                'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey', 'CryptAcquireContext',
                'NtProtectVirtualMemory', 'NtAllocateVirtualMemory',
                'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
                'RegSetValueEx', 'DeleteFile', 'MoveFileEx',
                'ShellExecute', 'InternetOpen', 'HttpSendRequest',
                'FindFirstFile', 'FindNextFile', 'SetFileAttributes',
            }

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    funcs = []
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode('utf-8', errors='ignore')
                            funcs.append(name)
                            if any(s.lower() in name.lower() for s in suspicious):
                                result['suspicious_imports'].append(f"{dll_name}!{name}")
                    result['imports'].append({'dll': dll_name, 'functions': funcs[:20]})

            # Sections
            for section in pe.sections:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                result['sections'].append({
                    'name':    name,
                    'size':    section.SizeOfRawData,
                    'virtual': hex(section.VirtualAddress),
                    'entropy': round(section.get_entropy(), 2),
                })

            # Strings
            result['strings'] = self._extract_strings(data)[:50]

            pe.close()

        except Exception as e:
            logger.error(f"PE analysis error: {e}")

        return result

    def get_code_bytes(self, file_path: str, max_bytes: int = 4096) -> tuple:
        """يرجع bytes من section الـ code مع base address"""
        if not self.available:
            return b'', 0, 'x64'
        try:
            pe   = self.pefile.PE(file_path)
            arch = 'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86'
            for section in pe.sections:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                if '.text' in name or name == 'CODE':
                    data = section.get_data()[:max_bytes]
                    base = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                    pe.close()
                    return data, base, arch
            # fallback: entry point
            ep_offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            data = pe.__data__[ep_offset: ep_offset + max_bytes]
            base = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
            pe.close()
            return data, base, arch
        except Exception as e:
            logger.error(f"get_code_bytes error: {e}")
            return b'', 0, 'x64'

    def _extract_strings(self, data: bytes, min_len: int = 6) -> list:
        import re
        ascii_strings = re.findall(rb'[\x20-\x7e]{%d,}' % min_len, data)
        result = []
        for s in ascii_strings[:100]:
            try:
                decoded = s.decode('ascii')
                result.append(decoded)
            except Exception:
                pass
        return list(set(result))[:50]


# ─────────────────────────────────────────────────────────
class AIDecompiler:
    """
    يجمع Disassembler + PEAnalyzer ويرسل لـ Claude API
    ليولّد pseudocode وتقرير تحليلي.
    """

    def __init__(self, reports_dir: str = "decompiled",
                 api_key: str = None):
        self.reports_dir  = reports_dir
        self.api_key      = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.disassembler = Disassembler()
        self.pe_analyzer  = PEAnalyzer()
        os.makedirs(reports_dir, exist_ok=True)

    def analyze(self, exe_path: str = None,
                dump_path: str = None,
                process_name: str = "unknown") -> dict:
        """
        الدالة الرئيسية — تحلل الملف وتولّد التقرير.
        """
        target = exe_path or dump_path
        if not target or not os.path.exists(target):
            logger.error(f"الملف غير موجود: {target}")
            return {}

        print(f"\n[AIDecompiler] تحليل: {os.path.basename(target)}")
        print(f"[AIDecompiler] الحجم: {os.path.getsize(target):,} bytes")

        report = {
            'timestamp':    datetime.now().isoformat(),
            'file':         target,
            'process_name': process_name,
            'pe_analysis':  {},
            'assembly':     [],
            'ai_analysis':  {},
            'report_path':  '',
        }

        # ── 1. تحليل PE ────────────────────────────────
        if exe_path:
            print("[AIDecompiler] تحليل PE header...")
            pe_info = self.pe_analyzer.analyze(exe_path)
            report['pe_analysis'] = pe_info

            if pe_info.get('suspicious_imports'):
                print(f"[AIDecompiler] ⚠  {len(pe_info['suspicious_imports'])} Suspicious imports:")
                for imp in pe_info['suspicious_imports'][:10]:
                    print(f"    - {imp}")

        # ── 2. Disassembly ─────────────────────────────
        if self.disassembler.available and exe_path:
            print("[AIDecompiler] فكّ تشفير الـ assembly...")
            code_bytes, base_addr, arch = self.pe_analyzer.get_code_bytes(exe_path)
            if code_bytes:
                instructions = self.disassembler.disassemble_bytes(
                    code_bytes, base_addr, mode=arch, max_insns=150
                )
                report['assembly'] = instructions
                print(f"[AIDecompiler] {len(instructions)} instruction")

        # ── 3. AI Analysis ─────────────────────────────
        print("[AIDecompiler] إرسال للـ AI للتحليل...")
        ai_result = self._ask_claude(report)
        report['ai_analysis'] = ai_result

        # ── 4. حفظ التقرير ────────────────────────────
        ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"decompiled_{process_name}_{ts}.json"
        report_path = os.path.join(self.reports_dir, report_name)
        report['report_path'] = report_path

        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        # حفظ تقرير نصي مقروء
        readable_path = report_path.replace('.json', '.txt')
        self._save_readable_report(report, readable_path)

        print(f"[AIDecompiler] ✅ التقرير محفوظ: {readable_path}")

        # طبع ملخص
        if ai_result.get('summary'):
            print(f"\n{'='*60}")
            print("  تحليل الـ AI:")
            print(f"{'='*60}")
            print(ai_result['summary'][:800])
            print(f"{'='*60}\n")

        return report

    def _ask_claude(self, report: dict) -> dict:
        """
        يرسل المعلومات لـ Claude ويطلب تحليل.
        """
        if not self.api_key:
            logger.warning("ANTHROPIC_API_KEY غير موجود — التحليل بدون AI")
            return self._basic_analysis(report)

        # بناء الـ prompt
        pe  = report.get('pe_analysis', {})
        asm = report.get('assembly', [])

        asm_text = ""
        if asm:
            asm_text = "\n".join(
                f"  {i['addr']}: {i['asm']}" for i in asm[:80]
            )

        imports_text = ""
        if pe.get('suspicious_imports'):
            imports_text = "\n".join(f"  - {x}" for x in pe['suspicious_imports'])

        strings_text = ""
        if pe.get('strings'):
            interesting = [s for s in pe['strings']
                          if any(k in s.lower() for k in
                                 ['encrypt', 'crypt', 'key', 'ransom', 'bitcoin',
                                  'tor', 'onion', 'payment', 'file', 'delete'])]
            strings_text = "\n".join(f"  - {s}" for s in interesting[:20])

        sections_text = ""
        if pe.get('sections'):
            for sec in pe['sections']:
                ent = sec.get('entropy', 0)
                flag = " ← PACKED/ENCRYPTED (high entropy)!" if ent > 7.0 else ""
                sections_text += f"  {sec['name']:10} size={sec['size']:>8} entropy={ent}{flag}\n"

        prompt = f"""أنت محلل أمن معلومات متخصص في تحليل البرمجيات الخبيثة.

تحليل ملف مشبوه: {report.get('process_name', 'unknown')}
الحجم: {pe.get('file_size', 0):,} bytes
SHA256: {pe.get('sha256', 'N/A')}
Architecture: {pe.get('arch', 'unknown')}
Entry Point: {pe.get('entry_point', 'N/A')}

=== Sections ===
{sections_text or 'N/A'}

=== Suspicious API Imports ===
{imports_text or 'لا يوجد imports مشبوهة'}

=== Interesting Strings ===
{strings_text or 'لا يوجد strings مشبوهة'}

=== Assembly (Entry Point) ===
{asm_text[:2000] or 'N/A'}

بناءً على هاي المعلومات، قدّم تحليلاً شاملاً يتضمن:
1. **نوع البرمجية**: هل هو ransomware؟ أي عائلة؟
2. **خوارزمية التشفير**: AES/RSA/ChaCha20/غيره؟ كيف يشفّر الملفات؟
3. **آلية الانتشار**: كيف يعمل؟
4. **نقاط مهمة في الـ assembly**: شو يفعل الكود في بداية التشغيل؟
5. **إمكانية فك التشفير**: هل يمكن استعادة الملفات؟
6. **توصيات**: خطوات للتعامل مع هذا التهديد.

أجب باللغة العربية بشكل واضح ومفصّل."""

        try:
            headers = {
                "x-api-key":         self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            }
            payload = {
                "model":      ANTHROPIC_MODEL,
                "max_tokens": 2000,
                "messages":   [{"role": "user", "content": prompt}]
            }

            resp = requests.post(
                ANTHROPIC_API_URL,
                headers=headers,
                json=payload,
                timeout=60
            )
            resp.raise_for_status()
            data    = resp.json()
            summary = data['content'][0]['text']

            return {
                'summary':    summary,
                'model':      ANTHROPIC_MODEL,
                'prompt_len': len(prompt),
                'status':     'success',
            }

        except requests.exceptions.ConnectionError:
            logger.warning("لا يوجد اتصال بالإنترنت — تحليل محلي فقط")
            return self._basic_analysis(report)
        except Exception as e:
            logger.error(f"Claude API error: {e}")
            return self._basic_analysis(report)

    def _basic_analysis(self, report: dict) -> dict:
        """
        تحليل محلي بدون AI — بناءً على patterns معروفة.
        """
        pe      = report.get('pe_analysis', {})
        imports = pe.get('suspicious_imports', [])
        strings = pe.get('strings', [])
        sections = pe.get('sections', [])

        findings = []

        # كشف خوارزمية التشفير
        crypto_apis = [i for i in imports if any(
            x in i for x in ['Crypt', 'BCrypt', 'NCrypt']
        )]
        if crypto_apis:
            findings.append(f"يستخدم Windows Crypto APIs: {', '.join(crypto_apis[:3])}")

        # كشف high entropy sections (مضغوط/مشفّر)
        packed = [s for s in sections if s.get('entropy', 0) > 7.0]
        if packed:
            findings.append(f"قسم ذو entropy عالي (likely packed): {[s['name'] for s in packed]}")

        # كشف process injection
        inject_apis = [i for i in imports if any(
            x in i for x in ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread']
        )]
        if inject_apis:
            findings.append(f"محتمل Process Injection: {inject_apis}")

        # كشف ransom strings
        ransom_strings = [s for s in strings if any(
            k in s.lower() for k in ['ransom', 'bitcoin', 'payment', 'encrypt', 'tor']
        )]
        if ransom_strings:
            findings.append(f"Ransom-related strings: {ransom_strings[:3]}")

        summary = "=== تحليل محلي (بدون AI) ===\n\n"
        if findings:
            summary += "النتائج:\n"
            for f in findings:
                summary += f"  • {f}\n"
        else:
            summary += "لم يتم اكتشاف patterns مشبوهة واضحة.\n"

        summary += f"\nملاحظة: لتحليل AI كامل، أضف ANTHROPIC_API_KEY\n"
        summary += f"  set ANTHROPIC_API_KEY=your_key_here\n"

        return {
            'summary': summary,
            'model':   'local_analysis',
            'status':  'local_only',
        }

    def _save_readable_report(self, report: dict, path: str):
        """يحفظ تقرير نصي مقروء"""
        pe = report.get('pe_analysis', {})
        ai = report.get('ai_analysis', {})

        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"{'='*70}\n")
            f.write(f"  تقرير تحليل البرمجية الخبيثة\n")
            f.write(f"  التاريخ: {report['timestamp']}\n")
            f.write(f"  الملف: {report['file']}\n")
            f.write(f"{'='*70}\n\n")

            f.write(f"SHA256: {pe.get('sha256', 'N/A')}\n")
            f.write(f"الحجم:  {pe.get('file_size', 0):,} bytes\n")
            f.write(f"النوع:  {pe.get('arch', 'unknown')}\n\n")

            if pe.get('suspicious_imports'):
                f.write("=== API Calls المشبوهة ===\n")
                for imp in pe['suspicious_imports']:
                    f.write(f"  - {imp}\n")
                f.write("\n")

            if pe.get('sections'):
                f.write("=== Sections ===\n")
                for sec in pe['sections']:
                    ent = sec.get('entropy', 0)
                    flag = " ← مشفّر/مضغوط!" if ent > 7.0 else ""
                    f.write(f"  {sec['name']:12} entropy={ent}{flag}\n")
                f.write("\n")

            if ai.get('summary'):
                f.write("=== تحليل الـ AI ===\n")
                f.write(ai['summary'])
                f.write("\n")

            if report.get('assembly'):
                f.write("\n=== Assembly (أول 50 instruction) ===\n")
                for insn in report['assembly'][:50]:
                    f.write(f"  {insn['addr']:>12}: {insn['asm']}\n")
