FROM python:3.11-slim

WORKDIR /app

# Install dependencies - no hash checking, trusted hosts
COPY requirements_api.txt .
RUN pip install --no-cache-dir --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements_api.txt

# Copy model files and API
COPY models/                    ./models/
COPY api.py                     .
COPY step2_feature_extractor.py .

EXPOSE 8000

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
