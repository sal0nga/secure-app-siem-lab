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
    if request.method == "POST" and resp.status_code == 403:
        path = request.path.rstrip("/")
        if path in ("/admin", "/admin/roles"):
            event = "admin_post" if path == "/admin" else "role_change"
            log_event(
                event,
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


# New admin-only route to log role changes
@bp.post("/roles")
@require_roles(["admin"])
def change_roles():
    data = request.get_json(silent=True) or {}
    target_sub = data.get("target_sub")
    add_roles = data.get("add_roles", []) or []
    remove_roles = data.get("remove_roles", []) or []

    if not target_sub:
        out = make_response(jsonify(error="bad_request", missing="target_sub"), 400)
        log_event(
            "role_change",
            outcome="failure",
            reason="missing_target_sub",
            status=400,
            resp_bytes=len(out.get_data()),
            user=getattr(g, "user", None),
            sub=getattr(g, "sub", None),
            session_id=getattr(g, "session_id", None),
            roles=current_roles(),
        )
        return out

    out = make_response(jsonify(accepted=True), 202)
    log_event(
        "role_change",
        outcome="allowed",
        status=202,
        resp_bytes=len(out.get_data()),
        user=getattr(g, "user", None),
        sub=getattr(g, "sub", None),
        session_id=getattr(g, "session_id", None),
        roles=current_roles(),
        target_sub=target_sub,
        add_roles=add_roles,
        remove_roles=remove_roles,
    )
    return out