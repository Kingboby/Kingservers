from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)

# SQLite Database Configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# User Model (Database Table)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    active = db.Column(db.Boolean, default=True)  # Account status (Active/Banned)

# Create the database tables
with app.app_context():
    db.create_all()

# Route: User Login
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password_hash, password):
        if user.active:
            return jsonify({"status": "success", "message": "Login successful"}), 200
        else:
            return jsonify({"status": "failed", "message": "Account revoked"}), 403
    return jsonify({"status": "failed", "message": "Invalid credentials"}), 401

# Route: Add New User (Admin Use)
@app.route("/add_user", methods=["POST"])
def add_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    # Check if user exists
    if User.query.filter_by(username=username).first():
        return jsonify({"status": "failed", "message": "User already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = User(username=username, password_hash=hashed_password, active=True)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"status": "success", "message": "User created successfully"}), 201

# Route: Disable User (Admin Use)
@app.route("/disable_user", methods=["POST"])
def disable_user():
    data = request.json
    username = data.get("username")

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"status": "failed", "message": "User not found"}), 404

    user.active = False  # Disable the account
    db.session.commit()

    return jsonify({"status": "success", "message": f"User {username} disabled"}), 200

# Route: Enable User (Admin Use)
@app.route("/enable_user", methods=["POST"])
def enable_user():
    data = request.json
    username = data.get("username")

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"status": "failed", "message": "User not found"}), 404

    user.active = True  # Enable the account
    db.session.commit()

    return jsonify({"status": "success", "message": f"User {username} enabled"}), 200

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
