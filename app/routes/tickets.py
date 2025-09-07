from flask import Blueprint, jsonify, request, make_response
from ..logging_utils import log_event, is_large_response

bp = Blueprint("tickets", __name__)

@bp.get("")
def list_tickets():
    items = []  # stubbed
    out = make_response(jsonify(items=items), 200)
    resp_len = len(out.get_data())
    kwargs = dict(outcome="success", status=200, resp_bytes=resp_len)
    if is_large_response(resp_len):
        kwargs["reason"] = "large_response"
    log_event("tickets_list", **kwargs)
    return out

@bp.post("")
def create_ticket():
    data = request.get_json(silent=True) or {}
    result = {"id": "tkt_1", **data}
    out = make_response(jsonify(result), 201)
    resp_len = len(out.get_data())
    kwargs = dict(outcome="success", status=201, resp_bytes=resp_len)
    if is_large_response(resp_len):
        kwargs["reason"] = "large_response"
    log_event("ticket_create", **kwargs)
    return out