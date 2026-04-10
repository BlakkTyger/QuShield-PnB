# QuShield-PnB Deployment Guide

This guide provides step-by-step instructions to deploy the QuShield-PnB application using Docker. It is designed for users with "0-knowledge" of Docker.

## Prerequisites

1.  **Docker & Docker Compose**: Ensure you have Docker installed.
    *   [Install Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/Mac)
    *   [Install Docker for Linux](https://docs.docker.com/engine/install/)
2.  **API Keys (Recommended for Cloud Mode)**:
    *   **Groq API Key**: Get one at [console.groq.com](https://console.groq.com/).
    *   **Jina AI API Key**: Get one at [jina.ai](https://jina.ai/embeddings/). (Optional but recommended for RAG features).

## Step 1: Prepare Environment Variables

1.  Locate the `.env` file in the project root.
2.  Ensure `GROQ_API_KEY` is set:
    ```bash
    GROQ_API_KEY=gsk_your_key_here
    JINA_API_KEY=jina_your_key_here
    ```
3.  (Optional) For OpenAI features (Pro tier), set `OPENAI_API_KEY`.

## Step 2: Spin Up the Stack

Open your terminal, navigate to the project root directory, and run:

```bash
docker compose up -d --build
```

### What this command does:
*   `--build`: Build the production-ready images for the Frontend and Backend.
*   `-d`: Run in "detached" mode (in the background).
*   **Automatic Initialization**: 
    *   Sets up a PostgreSQL database.
    *   Initializes the backend and frontend services.
    *   Configures networking between containers.

## Step 3: Verify Deployment

Check the status of your containers:

```bash
docker compose ps
```

You should see 3 services running:
1.  `qushield_backend` (Port 8000)
2.  `qushield_frontend` (Port 3000)
3.  `qushield_db` (Port 5432)

### Accessing the App:
*   **Frontend**: Open [http://localhost:3000](http://localhost:3000) in your browser.
*   **Backend API**: Access [http://localhost:8000/docs](http://localhost:8000/docs) for interactive documentation.

## Step 4: AI Feature Testing

Once everything is up, the AI will default to **Cloud Mode**.
1.  Navigate to the **Dashboard** in the Frontend.
2.  Trigger a **Quick Scan** of a domain (e.g., `pnb.bank.in`).
3.  Once the scan is complete, go to the **AI Security Analyst** (Chat) section.
4.  Ask a question: "What are the quantum risks for this asset?"

## Advanced: Local Development (Ollama)

If you wish to run the app with local LLMs (Ollama), use the local profile:

```bash
docker compose -f docker-compose.local.yml up -d
```

> [!NOTE]
> This requires significant system resources (GPU recommended) and will automatically pull large model files.

---
*Generated for QuShield-PnB Phase 10 — Integration & Cloud Completion.*
