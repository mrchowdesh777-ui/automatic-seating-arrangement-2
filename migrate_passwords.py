# ============================================
# MIGRATE PLAINTEXT PASSWORDS TO HASHED PASSWORDS
# Run this ONCE if you already have a users table with plaintext
# passwords (e.g. from the old database.sql sample admin row).
# Safe to run more than once — already-hashed passwords are skipped.
# Usage:  python migrate_passwords.py
# ============================================
import mysql.connector
from werkzeug.security import generate_password_hash

def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="seating_db"
    )

# Werkzeug hashes always start with one of these method prefixes.
HASH_PREFIXES = ("pbkdf2:", "scrypt:", "argon2")

def main():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT user_id, username, password FROM users")
    users = cursor.fetchall()

    migrated = 0
    for user in users:
        pw = user['password'] or ""
        if pw.startswith(HASH_PREFIXES):
            continue  # already hashed
        hashed = generate_password_hash(pw)
        cursor.execute("UPDATE users SET password=%s WHERE user_id=%s", (hashed, user['user_id']))
        migrated += 1
        print(f"Hashed password for user: {user['username']}")

    db.commit()
    db.close()
    print(f"\nDone. {migrated} password(s) migrated, {len(users) - migrated} already hashed.")

if __name__ == '__main__':
    main()
