# langgraph-app/Dockerfile
FROM python:3.11-slim

# Install system dependencies including zstd and Ollama
RUN apt-get update && apt-get install -y \
    curl \
    zstd \
    && rm -rf /var/lib/apt/lists/*

# Install Ollama
RUN curl -fsSL https://ollama.com/install.sh | sh

# Create app directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create a script to start both Ollama and your app
RUN echo '#!/bin/bash\n\
# Start Ollama in background\n\
ollama serve &\n\
\n\
# Wait for Ollama to be ready\n\
sleep 5\n\
\n\
# Pull models\n\
ollama pull phi3:3.8b\n\
ollama pull qwen2.5:1.5b\n\
\n\
# Keep container running (or start your app)\n\
tail -f /dev/null' > /app/start.sh && chmod +x /app/start.sh

# Command to run the startup script
CMD ["/app/start.sh"]