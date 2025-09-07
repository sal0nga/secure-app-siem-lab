# app/routes/oidc.py
from flask import Blueprint, request, jsonify, make_response, g
from ..logging_utils import log_event

bp = Blueprint("oidc", __name__)

@bp.get("/callback")
def oidc_callback():
    code = request.args.get("code")
    state = request.args.get("state")

    if not code or not state:
        missing = "code" if not code else "state"
        reason = f"missing_{missing}"
        out = make_response(jsonify(error="bad_request", missing=missing), 400)
        log_event(
            "oidc_callback",
            outcome="failure",
            reason=reason,
            status=400,
            resp_bytes=len(out.get_data()),
            user=getattr(g, "user", None),
            sub=getattr(g, "sub", None),
            session_id=getattr(g, "session_id", None),
        )
        return out

    # We’re not exchanging the code here—Phase 03 only needs the log.
    out = make_response(jsonify(ok=True, received="code"), 200)
    log_event(
        "oidc_callback",
        outcome="success",
        status=200,
        resp_bytes=len(out.get_data()),
        user=getattr(g, "user", None),
        sub=getattr(g, "sub", None),
        session_id=getattr(g, "session_id", None),
    )
    return out