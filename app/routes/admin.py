from flask import Blueprint, jsonify, make_response
from ..auth import require_roles
from ..logging_utils import log_event

bp = Blueprint("admin", __name__)

@bp.post("")
@require_roles(["admin"])  # will be enforced once we wire real roles
def do_admin_thing():
    out = make_response(jsonify(ok=True, action="admin-op"), 200)
    log_event("admin_post", outcome="allowed", status=200, resp_bytes=len(out.get_data()))
    return out