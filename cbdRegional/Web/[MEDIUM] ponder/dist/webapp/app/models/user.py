from werkzeug.security import check_password_hash, generate_password_hash

from app.database import get_db


class User:
    @staticmethod
    def create(username, password):
        cursor = get_db().execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
        get_db().commit()
        return cursor.lastrowid

    @staticmethod
    def find_by_id(user_id):
        if user_id is None:
            return None
        return get_db().execute(
            "SELECT id, username, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

    @staticmethod
    def find_by_username(username):
        return get_db().execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    @staticmethod
    def check_password(user, password):
        return check_password_hash(user["password_hash"], password)
