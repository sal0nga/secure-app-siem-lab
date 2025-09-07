from flask import Blueprint, jsonify, make_response
from ..logging_utils import log_event

bp = Blueprint("health", __name__)

@bp.get("/healthz")
def healthz():
    resp = jsonify(status="ok")
    out = make_response(resp, 200)
    log_event("health_check", outcome="success", status=200, resp_bytes=len(out.get_data()))
    return out