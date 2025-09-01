# Let the base be swappable to keep you unblocked if a tag drifts.
ARG PYTHON_BASE=registry.access.redhat.com/ubi9/python-311
FROM ${PYTHON_BASE}

# Create app user & dirs
WORKDIR /opt/app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System deps (psycopg2 needs libpq; UBI images already have basics)
# If using python:3.11-slim instead, you may need: apt-get update && apt-get install -y build-essential libpq-dev

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default port for gunicorn binding in compose
EXPOSE 8000

# Gunicorn command is provided in docker-compose.yml