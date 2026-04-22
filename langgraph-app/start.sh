#!/bin/bash
set -e

echo "Starting Ollama..."
ollama serve &

echo "Waiting for Ollama to become available..."
until curl -s http://127.0.0.1:11434/api/tags >/dev/null; do
  sleep 2
done

echo "Ollama is ready."

echo "Starting application..."
python -u -m src.main