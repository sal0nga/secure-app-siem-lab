# app/__init__.py
import uuid
from flask import Flask, g
from .routes.health import bp as health_bp
from .routes.tickets import bp as tickets_bp
from .routes.admin import bp as admin_bp

def create_app():
    app = Flask(__name__)

    @app.before_request
    def assign_trace_id():
        g.trace_id = str(uuid.uuid4())

    app.register_blueprint(health_bp)                 # /healthz
    app.register_blueprint(tickets_bp, url_prefix="/tickets")
    app.register_blueprint(admin_bp,   url_prefix="/admin")
    return app

# Gunicorn/Wsgi entrypoint convenience:
app = create_app()