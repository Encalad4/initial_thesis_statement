FROM python:3.11-slim

# Install system dependencies and Ollama
RUN apt-get update && apt-get install -y \
    curl \
    git \
    zstd \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://ollama.com/install.sh | sh

# App directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy startup script
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Copy application code
COPY src /app/src

CMD ["/app/start.sh"]