FROM python:3.11-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project metadata first (layer caching)
COPY pyproject.toml .
RUN pip install --no-cache-dir pip -U

# Install only runtime deps (skip dev/test for lighter image)
RUN pip install --no-cache-dir \
    fastapi>=0.110.0 \
    "uvicorn[standard]>=0.27.0" \
    "celery[redis]>=5.3.0" \
    redis>=5.0.0 \
    langgraph>=0.2.0 \
    langchain-core>=0.3.0 \
    pydantic>=2.6.0 \
    pydantic-settings>=2.1.0 \
    httpx>=0.27.0 \
    gitpython>=3.1.40 \
    tree-sitter>=0.21.0 \
    tree-sitter-python>=0.21.0 \
    semgrep>=1.60.0 \
    jinja2>=3.1.0 \
    structlog>=24.0.0 \
    pyyaml>=6.0.0 \
    typer>=0.9.0 \
    python-dotenv>=1.0.0

# Copy all source code
COPY . .

# Default command
CMD ["uvicorn", "src.api.app:create_app", "--host", "0.0.0.0", "--port", "8000", "--factory"]
