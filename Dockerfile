FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libzbar0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 9026

ENV PYTHONUNBUFFERED=1
# SATGATEWAY_KEY must be provided at runtime — do not hardcode

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9026"]
