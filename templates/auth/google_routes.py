# misc_routes.py

from flask import Blueprint, jsonify

google_auth_bp = Blueprint('google_auth', __name__)

@google_auth_bp.route('/auth_check')
def auth_check():
    return jsonify({"message": "This is a route from the google auth blueprint!"})
