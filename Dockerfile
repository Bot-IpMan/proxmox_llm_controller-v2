# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# 1) Спочатку залежності
COPY controller/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2) Потім код
COPY controller/app.py .

ENV PORT=8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
