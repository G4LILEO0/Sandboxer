FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# "[dev]" adds test tooling for local development and CI images.
ARG EXTRAS=""

WORKDIR /app
COPY pyproject.toml ./
COPY sandbox ./sandbox
RUN pip install ".${EXTRAS}"
COPY alembic.ini ./
COPY tests ./tests

RUN useradd --system --uid 10001 --no-create-home app \
    && mkdir -p /data/artifacts /data/quarantine
# The API runs as "app"; the worker image runs as root for the Docker socket (compose.yaml).
USER app

EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn --factory sandbox.api.main:create_app --host 0.0.0.0 --port 8000"]
