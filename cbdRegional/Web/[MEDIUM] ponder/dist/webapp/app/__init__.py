import os

from flask import Flask, flash, redirect, url_for
from werkzeug.exceptions import RequestEntityTooLarge

from .controllers.auth_controller import auth_bp
from .controllers.gif_controller import gif_bp
from .controllers.report_controller import report_bp
from .database import init_app as init_database


def _int_env(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def create_app(test_config=None):
    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder="views/templates",
        static_folder="static",
    )
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(32).hex()),
        DATABASE=os.path.join(app.instance_path, "ponder.sqlite3"),
        UPLOAD_FOLDER=os.path.join(app.instance_path, "uploads"),
        MAX_UPLOAD_BYTES=1 * 1024 * 1024,
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        ALLOWED_EXTENSIONS={"gif", "png", "jpg", "jpeg", "webp"},
        BOT_URL=os.environ.get("BOT_URL", "http://127.0.0.1:3001"),
        FLAG=os.environ.get("FLAG", "FLAG{redacted}"),
        ADMIN_USERNAME=os.environ.get("ADMIN_USERNAME"),
        ADMIN_PASSWORD=os.environ.get("ADMIN_PASSWORD"),
        ADMIN_UPLOAD_FILENAME=os.environ.get("ADMIN_UPLOAD_FILENAME", "admin-private.gif"),
        TRUSTED_PROXY_COUNT=max(0, _int_env("TRUSTED_PROXY_COUNT", 3)),
        SESSION_COOKIE_SAMESITE='Lax'
    )

    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    @app.errorhandler(RequestEntityTooLarge)
    def handle_request_too_large(_error):
        flash("Uploaded files must be 1 MB or smaller.", "error")
        return redirect(url_for("gifs.upload"))

    init_database(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(gif_bp)
    app.register_blueprint(report_bp)

    return app
