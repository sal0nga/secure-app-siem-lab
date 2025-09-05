# app/routes/admin.py
from flask import Blueprint, jsonify, make_response, g, request
from ..auth import require_roles, current_roles
from ..logging_utils import log_event

bp = Blueprint("admin", __name__)

@bp.post("")
@require_roles(["admin"])
def do_admin_thing():
    out = make_response(jsonify(ok=True, action="admin-op"), 200)
    log_event(
        "admin_post",
        outcome="allowed",
        status=200,
        resp_bytes=len(out.get_data()),
        user=getattr(g, "user", None),
        sub=getattr(g, "sub", None),
        session_id=getattr(g, "session_id", None),
        roles=current_roles(),
        mfa=getattr(g, "mfa", None),
    )
    return out

# Denials are handled by the decorator’s 403; add an after_request to log them
@bp.after_request
def log_denials(resp):
    if request.method == "POST" and request.path.rstrip("/") == "/admin" and resp.status_code == 403:
        log_event(
            "admin_post",
            outcome="denied",
            reason="missing_role",
            status=resp.status_code,
            resp_bytes=len(resp.get_data()),
            user=getattr(g, "user", None),
            sub=getattr(g, "sub", None),
            session_id=getattr(g, "session_id", None),
            roles=current_roles(),
            mfa=getattr(g, "mfa", None),
            authn_error=getattr(g, "authn_error", None),
        )
    return resp