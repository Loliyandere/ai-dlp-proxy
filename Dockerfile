FROM python:3.11-slim

WORKDIR /app

# Cài dependencies hệ thống
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Cài Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download spacy model (cho Presidio)
RUN python -m spacy download en_core_web_sm

# Copy toàn bộ source
COPY . .

# Tạo thư mục log
RUN mkdir -p logs

ENV PYTHONPATH=/app

EXPOSE 8080

CMD ["mitmdump", \
     "--listen-host", "0.0.0.0", \
     "--listen-port", "8080", \
     "-s", "addons/dlp_addon.py"]