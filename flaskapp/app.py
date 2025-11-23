from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# Hardcoded user data (for example purposes only)
users = {
    "admin": generate_password_hash("secret123")  # Replace with a real hashed password in production
}

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username not in users:
        return jsonify({"success": False, "message": "Invalid username"}), 401

    if not check_password_hash(users[username], password):
        return jsonify({"success": False, "message": "Incorrect password"}), 401

    return jsonify({"success": True, "message": "Login successful!"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)

