from flask import Blueprint, jsonify, request, make_response
from ..logging_utils import log_event

bp = Blueprint("tickets", __name__)

@bp.get("")
def list_tickets():
    items = []
    out = make_response(jsonify(items=items), 200)
    log_event("tickets_list", outcome="success", status=200, resp_bytes=len(out.get_data()))
    return out

@bp.post("")
def create_ticket():
    data = request.get_json(silent=True) or {}
    result = {"id": "tkt_1", **data}
    out = make_response(jsonify(result), 201)
    log_event("ticket_create", outcome="success", status=201, resp_bytes=len(out.get_data()))
    return out