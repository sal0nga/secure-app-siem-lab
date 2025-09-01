import os
import json
import logging
from pathlib import Path
from flask import Flask, jsonify
from sqlalchemy import create_engine, text

def create_logger():
    log_dir = Path("/var/log/app")
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_dir / "app.log")
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    handler.setFormatter(fmt)

    logger = logging.getLogger("app")
    logger.setLevel(getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()))
    logger.addHandler(handler)
    # Also log to stdout for `docker compose logs`
    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    logger.addHandler(stream)
    return logger

def create_db_engine():
    url = os.getenv("DATABASE_URL", "")
    if not url:
        return None

    connect_args = {}
    if url.startswith("postgresql"):
        # Fail fast if Postgres isn't ready
        connect_args["connect_timeout"] = int(os.getenv("DB_CONNECT_TIMEOUT", "2"))
        # Also cap statement runtime to 1s inside Postgres
        connect_args["options"] = f"-c statement_timeout={os.getenv('DB_STATEMENT_TIMEOUT_MS', '1000')}"

    return create_engine(url, pool_pre_ping=True, future=True, connect_args=connect_args)

def create_app():
    app = Flask(__name__)
    logger = create_logger()
    engine = create_db_engine()

    @app.get("/")
    def index():
        logger.info("index hit")
        return jsonify({"ok": True, "service": "app", "msg": "hello"})

    @app.get("/healthz")
    def healthz():
        db_ok = None
        if engine:
          try:
              with engine.connect() as conn:
                  conn.execute(text("SELECT 1"))
              db_ok = True
          except Exception as e:
              logger.warning("DB health check failed: %s", e)
              db_ok = False
        payload = {"ok": True, "db_ok": db_ok}
        # 200 by design for readiness; db_ok shows state.
        return jsonify(payload), 200

    return app

app = create_app()