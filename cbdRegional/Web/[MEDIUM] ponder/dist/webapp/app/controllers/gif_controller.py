import os
import uuid

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.utils import secure_filename

from app.controllers.auth_controller import login_required
from app.models.gif import Gif


gif_bp = Blueprint("gifs", __name__)


def allowed_file(filename):
    if "." not in filename:
        return False
    extension = filename.rsplit(".", 1)[1].lower()
    return extension in current_app.config["ALLOWED_EXTENSIONS"]


def uploaded_file_size(file):
    if file.content_length:
        return file.content_length

    try:
        position = file.stream.tell()
        file.stream.seek(0, os.SEEK_END)
        size = file.stream.tell()
        file.stream.seek(position)
        return size
    except (AttributeError, OSError):
        return request.content_length or 0


@gif_bp.route("/")
def index():
    own_gifs = Gif.for_user(g.user["id"]) if g.user else []
    return render_template("gifs/index.html", own_gifs=own_gifs)


@gif_bp.route("/upload", methods=("GET", "POST"))
@login_required
def upload():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        file = request.files.get("image")

        if not title:
            flash("Title is required.", "error")
        elif file is None or not file.filename:
            flash("Choose a GIF or image to upload.", "error")
        elif not allowed_file(file.filename):
            flash("Only gif, png, jpg, jpeg, and webp files are allowed.", "error")
        elif uploaded_file_size(file) > current_app.config["MAX_UPLOAD_BYTES"]:
            flash("Uploaded files must be 1 MB or smaller.", "error")
        else:
            original_filename = secure_filename(file.filename)
            extension = original_filename.rsplit(".", 1)[1].lower()
            stored_filename = f"{uuid.uuid4().hex}.{extension}"
            destination = os.path.join(current_app.config["UPLOAD_FOLDER"], stored_filename)
            file.save(destination)

            Gif.create(
                user_id=g.user["id"],
                title=title,
                original_filename=original_filename,
                stored_filename=stored_filename,
                mimetype=f"image/{extension}",
            )
            flash("Image uploaded.", "success")
            return redirect(url_for("gifs.index"))

    return render_template("gifs/upload.html")


@gif_bp.route("/search")
@login_required
def search():
    query = request.args.get("q", "").strip()
    matches = Gif.search_gifs(query, g.user["id"]) if query else None
    return render_template(
        "gifs/search.html",
        query=query,
        matches=matches,
        single_match=matches is not None and len(matches) == 1,
    )

@gif_bp.route("/gifs/<int:gif_id>/raw")
def raw(gif_id):
    user_id = g.user["id"] if g.user else None
    image = Gif.find_owned_by_id(gif_id, user_id)
    if image is None:
        return image_not_found_response()
    return send_gif_file(image)


def send_gif_file(image):
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], image["stored_filename"])
    if not os.path.exists(path):
        return image_not_found_response()

    return send_file(
        path,
        mimetype=image["mimetype"],
        as_attachment=False,
        download_name=image["original_filename"],
        max_age=0,
    )


def image_not_found_response():
    svg = """<svg xmlns="http://www.w3.org/2000/svg" width="640" height="360" viewBox="0 0 640 360" role="img" aria-label="404 image not found">
  <rect width="640" height="360" fill="#f7f8fa"/>
  <rect x="24" y="24" width="592" height="312" rx="16" fill="#ffffff" stroke="#dfe4ea" stroke-width="2"/>
  <text x="320" y="157" text-anchor="middle" font-family="Arial, Helvetica, sans-serif" font-size="72" font-weight="700" fill="#b42318">404</text>
  <text x="320" y="218" text-anchor="middle" font-family="Arial, Helvetica, sans-serif" font-size="28" font-weight="700" fill="#18202f">Image not found</text>
</svg>
"""
    return Response(svg, status=404, mimetype="image/svg+xml")
