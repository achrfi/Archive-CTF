from app.database import get_db


class Gif:
    @staticmethod
    def create(user_id, title, original_filename, stored_filename, mimetype):
        cursor = get_db().execute(
            """
            INSERT INTO gifs
                (user_id, title, original_filename, stored_filename, mimetype)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, title, original_filename, stored_filename, mimetype),
        )
        get_db().commit()
        return cursor.lastrowid

    @staticmethod
    def for_user(user_id):
        return get_db().execute(
            """
            SELECT gifs.*, users.username
            FROM gifs
            JOIN users ON users.id = gifs.user_id
            WHERE gifs.user_id = ?
            ORDER BY gifs.created_at DESC, gifs.id DESC
            """,
            (user_id,),
        ).fetchall()

    @staticmethod
    def search_gifs(query, user_id):
        pattern = f"%{query}%"
        return get_db().execute(
            """
            SELECT gifs.*, users.username
            FROM gifs
            JOIN users ON users.id = gifs.user_id
            WHERE gifs.user_id = ?
              AND (gifs.title LIKE ? OR gifs.original_filename LIKE ?)
            ORDER BY
              CASE WHEN gifs.title = ? THEN 0 ELSE 1 END,
              gifs.created_at ASC,
              gifs.id ASC
            """,
            (user_id, pattern, pattern, query),
        ).fetchall()

    @staticmethod
    def match_count(query, user_id, limit=2):
        pattern = f"%{query}%"
        row = get_db().execute(
            """
            SELECT COUNT(*) AS match_count
            FROM (
                SELECT gifs.id
                FROM gifs
                WHERE gifs.user_id = ?
                  AND (gifs.title LIKE ? OR gifs.original_filename LIKE ?)
                LIMIT ?
            )
            """,
            (user_id, pattern, pattern, limit),
        ).fetchone()
        return row["match_count"]

    @staticmethod
    def find_owned_by_id(gif_id, user_id):
        if user_id is None:
            return None
        return get_db().execute(
            """
            SELECT gifs.*, users.username
            FROM gifs
            JOIN users ON users.id = gifs.user_id
            WHERE gifs.id = ? AND gifs.user_id = ?
            LIMIT 1
            """,
            (gif_id, user_id),
        ).fetchone()
