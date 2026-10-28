FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng tesseract-ocr-sin tesseract-ocr-tam && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt backend/requirements.txt
COPY ml/requirements.txt ml/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt -r ml/requirements.txt
COPY backend backend
COPY ml/artifacts ml/artifacts
COPY apps/dashboard apps/dashboard
RUN useradd --uid 10001 --create-home scamshield && mkdir /data && chown scamshield:scamshield /data && chmod 700 /data
USER scamshield
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
