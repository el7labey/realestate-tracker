from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'realestate-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ===== Models =====
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(20))  # admin / viewer

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ===== Routes =====
@app.route("/")
@login_required
def home():
    if current_user.role == "viewer":
        return redirect(url_for("viewer"))
    return redirect(url_for("admin"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and bcrypt.checkpw(
            request.form["password"].encode("utf-8"),
            user.password.encode("utf-8")
        ):
            login_user(user)
            return redirect(url_for("home"))
    return render_template("login.html")

@app.route("/admin")
@login_required
def admin():
    if current_user.role != "admin":
        return redirect(url_for("viewer"))
    return "Admin Dashboard"

@app.route("/viewer")
@login_required
def viewer():
    return "Viewer Dashboard"

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ===== First-time setup =====
@app.before_first_request
def setup():
    db.create_all()
    if not User.query.filter_by(username="abdallah").first():
        admin_pass = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode("utf-8")
        viewer_pass = bcrypt.hashpw(b"hamad", bcrypt.gensalt()).decode("utf-8")
        db.session.add(User(username="abdallah", password=admin_pass, role="admin"))
        db.session.add(User(username="hamad", password=viewer_pass, role="viewer"))
        db.session.commit()

if __name__ == "__main__":
    app.run()
