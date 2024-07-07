from flask import Blueprint, request, jsonify
from models import User, bcrypt

auth = Blueprint('auth', __name__)

@auth.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid input"}), 400
    
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if User.find_by_username(username):
        return jsonify({"error": "Username already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(username=username, password=hashed_password)
    user_id = user.save()

    if not user_id:
        return jsonify({"error": "Failed to create user"}), 500

    return jsonify({
        "message": "User created successfully",
        "_id": str(user_id),
        "username": user.username
    }), 201

@auth.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid input"}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = User.find_by_username(username)
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Invalid username or password"}), 401

    return jsonify({
        "message": "Sign-in successful",
        "_id": str(user._id),
        "username": user.username
    }), 200
