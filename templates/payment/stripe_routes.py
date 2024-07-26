# misc_routes.py

from flask import Blueprint, jsonify

payment_bp = Blueprint('payment', __name__)

@payment_bp.route('/payment_check')
def payment_check():
    return jsonify({"message": "This is a route from the payment blueprint!"})
