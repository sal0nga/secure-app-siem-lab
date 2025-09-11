# Let the base be swappable to keep you unblocked if a tag drifts.
ARG PYTHON_BASE=registry.access.redhat.com/ubi9/python-311
FROM ${PYTHON_BASE}

# Create app user & dirs
WORKDIR /opt/app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System deps (psycopg2 needs libpq; UBI images already have basics)
# If using python:3.11-slim instead, you may need: apt-get update && apt-get install -y build-essential libpq-dev

# Copy requirements from project root (compose build context should be repo root)
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy only the app source from the repository into the image workdir
COPY app ./app
COPY wsgi.py ./wsgi.py

# Default port for gunicorn binding in compose
ENV PORT=8443
EXPOSE 8443
# Ensure OpenSSL is available in the UBI9 image (needed to generate a self-signed cert)
RUN microdnf install -y openssl && microdnf clean all

# Dev/CI-only: generate a short-lived self-signed TLS cert for app.local
RUN mkdir -p /opt/certs && \
    openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
      -keyout /opt/certs/dev.key -out /opt/certs/dev.crt \
      -subj "/CN=app.local"
CMD ["sh","-c","exec python -m gunicorn -k gthread --threads ${GTHREADS:-4} --workers ${GWORKERS:-2} --timeout ${GTIMEOUT:-60} --bind 0.0.0.0:${PORT} --keyfile /opt/certs/dev.key --certfile /opt/certs/dev.crt wsgi:app"]
# Gunicorn command is provided in docker-compose.yml