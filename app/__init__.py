# app/__init__.py
import uuid, os
from flask import Flask, g
from .routes.health import bp as health_bp
from .routes.tickets import bp as tickets_bp
from .routes.admin import bp as admin_bp
from .routes.oidc import bp as oidc_bp            # ← add
from .auth import verify_request_token

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-not-secret")  # for future state/csrf use

    @app.before_request
    def assign_trace_id():
        g.trace_id = str(uuid.uuid4())

    @app.before_request
    def parse_token():
        verify_request_token()

    @app.after_request
    def add_trace_header(resp):
        tid = getattr(g, "trace_id", None)
        if tid:
            resp.headers["X-Trace-Id"] = tid
        return resp

    app.register_blueprint(health_bp)
    app.register_blueprint(tickets_bp, url_prefix="/tickets")
    app.register_blueprint(admin_bp,  url_prefix="/admin")
    app.register_blueprint(oidc_bp,   url_prefix="/oidc")  # ← add
    return app

app = create_app()