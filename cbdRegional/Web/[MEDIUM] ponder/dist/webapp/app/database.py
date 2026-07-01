import sqlite3

from flask import current_app, g
from werkzeug.security import generate_password_hash


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS gifs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    stored_filename TEXT UNIQUE NOT NULL,
    mimetype TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_gifs_title ON gifs (title);
CREATE INDEX IF NOT EXISTS idx_gifs_owner ON gifs (user_id);

CREATE TABLE IF NOT EXISTS migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

ADMIN_SEED_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00"
    b"\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,"
    b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)


def get_db():
    if "db" not in g:
        connection = sqlite3.connect(current_app.config["DATABASE"])
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.db = connection
    return g.db


def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db():
    get_db().executescript(SCHEMA)
    run_migrations()
    get_db().commit()


def run_migrations():
    apply_migration("001_seed_admin_account_and_upload", seed_admin_account_and_upload)


def apply_migration(name, migration):
    db = get_db()
    existing = db.execute("SELECT 1 FROM migrations WHERE name = ?", (name,)).fetchone()
    if existing:
        return

    applied = migration()
    if applied is not False:
        db.execute("INSERT OR IGNORE INTO migrations (name) VALUES (?)", (name,))


def seed_admin_account_and_upload():
    username = current_app.config.get("ADMIN_USERNAME")
    password = current_app.config.get("ADMIN_PASSWORD")
    if not username or not password:
        return False

    db = get_db()
    password_hash = generate_password_hash(password)
    db.execute(
        "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash),
    )

    user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    admin_id = user["id"]
    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (password_hash, admin_id),
    )

    stored_filename = "admin_seed.gif"
    original_filename = current_app.config.get("ADMIN_UPLOAD_FILENAME", "admin-private.gif")
    title = current_app.config.get("FLAG", "FLAG{redacted}")
    destination = f"{current_app.config['UPLOAD_FOLDER']}/{stored_filename}"

    with open(destination, "wb") as seed_file:
        seed_file.write(ADMIN_SEED_GIF)

    db.execute(
        """
        INSERT OR IGNORE INTO gifs
            (user_id, title, original_filename, stored_filename, mimetype)
        VALUES (?, ?, ?, ?, ?)
        """,
        (admin_id, title, original_filename, stored_filename, "image/gif"),
    )
    db.execute(
        """
        UPDATE gifs
        SET user_id = ?, title = ?, original_filename = ?, mimetype = ?
        WHERE stored_filename = ?
        """,
        (admin_id, title, original_filename, "image/gif", stored_filename),
    )

    return True


def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
