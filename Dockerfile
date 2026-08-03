FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for tree-sitter and git
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev]" && \
    pip install --no-cache-dir -e ".[semgrep]"

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 codeguard && chown -R codeguard:codeguard /app
USER codeguard

# Default command (overridden by docker-compose)
CMD ["uvicorn", "src.api.app:create_app", "--host", "0.0.0.0", "--port", "8000", "--factory"]
