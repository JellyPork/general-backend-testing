# misc_routes.py

from flask import Blueprint, jsonify

misc_bp = Blueprint('misc', __name__)

@misc_bp.route('/misc')
def misc():
    return jsonify({"message": "This is a route from the misc blueprint!"})
