# app/auth.py
from functools import wraps
from flask import request, jsonify, g
# Next increment: parse JWT from Authorization, set g.user, g.roles, g.mfa, etc.

def _current_roles():
    # Temporary: fall back to a stub role until we wire Keycloak
    return getattr(g, "roles", ["stub"])

def require_roles(required):
    required = set(required)
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            roles = set(_current_roles())
            if not required.issubset(roles):
                # log happens in route; quick 403 here
                return jsonify(error="forbidden", missing=list(required - roles)), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator