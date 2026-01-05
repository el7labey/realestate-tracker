from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required,
    logout_user, current_user
)
import bcrypt
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'realestate-secret-key'

# ===== PostgreSQL (Render) =====
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ===== Models =====
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(20))  # admin / viewer


class Deal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_name = db.Column(db.String(100))
    bank_name = db.Column(db.String(100))
    employee_name = db.Column(db.String(100))
    last_update = db.Column(db.String(300))
    update_date = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ===== Routes =====
@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and bcrypt.checkpw(
            request.form["password"].encode(),
            user.password.encode()
        ):
            login_user(user)
            return redirect(url_for("admin" if user.role == "admin" else "viewer"))
    return render_template("login.html")


@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    if current_user.role != "admin":
        return redirect(url_for("viewer"))

    if request.method == "POST":
        deal = Deal(
            client_name=request.form["client_name"],
            bank_name=request.form["bank_name"],
            employee_name=request.form["employee_name"],
            last_update=request.form["last_update"]
        )
        db.session.add(deal)
        db.session.commit()

    deals = Deal.query.order_by(Deal.update_date.desc()).all()
    return render_template("admin.html", deals=deals)


@app.route("/viewer")
@login_required
def viewer():
    deals = Deal.query.order_by(Deal.update_date.desc()).all()
    return render_template("viewer.html", deals=deals)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ===== Initial Setup =====
with app.app_context():
    db.create_all()

    if not User.query.filter_by(username="abdallah").first():
        admin_pass = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode()
        viewer_pass = bcrypt.hashpw(b"hamad", bcrypt.gensalt()).decode()

        db.session.add(User(username="abdallah", password=admin_pass, role="admin"))
        db.session.add(User(username="hamad", password=viewer_pass, role="viewer"))
        db.session.commit()


if __name__ == "__main__":
    app.run()
