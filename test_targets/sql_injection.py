def get_user(uid):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (uid,))
    return cursor.fetchone()