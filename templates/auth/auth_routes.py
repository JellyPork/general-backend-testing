# auth_routes.py
from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, jwt_required
from models.models import User
from templates.database.extensions import db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/auth_check')
def auth_check():
    return jsonify({"message": "This is a route from the auth blueprint!"})

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        if existing_user.google_id:
            return jsonify({"message": "User already registered with Google. Please use Google to log in."}), 400
        else:
            return jsonify({"message": "User already exists"}), 400

    new_user = User(username=username, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    return jsonify({"message": "Invalid credentials"}), 401
