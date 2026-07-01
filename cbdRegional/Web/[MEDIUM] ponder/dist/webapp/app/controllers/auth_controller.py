from functools import wraps

from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.models.user import User


auth_bp = Blueprint("auth", __name__)


@auth_bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")
    g.user = User.find_by_id(user_id) if user_id else None


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("Please log in first.", "error")
            return redirect(url_for("auth.login"))
        return view(**kwargs)

    return wrapped_view


@auth_bp.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username:
            flash("Username is required.", "error")
        elif not password:
            flash("Password is required.", "error")
        elif User.find_by_username(username):
            flash("Username is already registered.", "error")
        else:
            user_id = User.create(username, password)
            session.clear()
            session["user_id"] = user_id
            flash("Account created.", "success")
            return redirect(url_for("gifs.index"))

    return render_template("auth/register.html")


@auth_bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.find_by_username(username)

        if user is None or not User.check_password(user, password):
            flash("Invalid username or password.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            flash("Logged in.", "success")
            return redirect(url_for("gifs.index"))

    return render_template("auth/login.html")


@auth_bp.route("/logout", methods=("POST",))
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("auth.login"))
