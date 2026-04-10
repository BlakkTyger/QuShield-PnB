#!/bin/bash

# Configuration
OLLAMA_HOST=${OLLAMA_HOST:-"ollama"}
OLLAMA_PORT=${OLLAMA_PORT:-"11434"}
MODELS=("llama3.1:8b" "nomic-embed-text")

echo "--- Initializing Ollama Models ---"
echo "Target: http://$OLLAMA_HOST:$OLLAMA_PORT"

# Function to check if Ollama is ready
wait_for_ollama() {
    local retries=30
    local count=0
    while ! curl -s "http://$OLLAMA_HOST:$OLLAMA_PORT/api/tags" > /dev/null; do
        ((count++))
        if [ $count -ge $retries ]; then
            echo "Error: Ollama timed out."
            exit 1
        fi
        echo "Waiting for Ollama to be ready ($count/$retries)..."
        sleep 2
    done
    echo "Ollama is ready."
}

# Pull models
wait_for_ollama

for model in "${MODELS[@]}"; do
    echo "Checking model: $model"
    if curl -s "http://$OLLAMA_HOST:$OLLAMA_PORT/api/tags" | grep -q "$model"; then
        echo "Model $model already exists."
    else
        echo "Pulling model $model..."
        curl -X POST "http://$OLLAMA_HOST:$OLLAMA_PORT/api/pull" -d "{\"name\": \"$model\"}"
        echo "Done pulling $model."
    fi
done

echo "--- Ollama Initialization Complete ---"
