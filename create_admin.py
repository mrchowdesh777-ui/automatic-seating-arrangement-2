# ============================================
# CREATE ADMIN ACCOUNT
# Run this once to create your first login.
# Usage:  python create_admin.py
# ============================================
import getpass
import mysql.connector
from werkzeug.security import generate_password_hash

def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="seating_db"
    )

def main():
    print("=== Create Admin Account ===")
    full_name = input("Full name: ").strip()
    username  = input("Username: ").strip()
    email     = input("Email: ").strip()

    while True:
        password = getpass.getpass("Password (min 6 characters, hidden while typing): ")
        confirm  = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match, try again.\n")
            continue
        if len(password) < 6:
            print("Password must be at least 6 characters, try again.\n")
            continue
        break

    hashed = generate_password_hash(password)

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE username=%s OR email=%s", (username, email))
    if cursor.fetchone():
        print("A user with that username or email already exists. Aborting.")
        db.close()
        return

    cursor.execute(
        "INSERT INTO users (full_name, username, email, password, role) VALUES (%s,%s,%s,%s,%s)",
        (full_name, username, email, hashed, 'admin')
    )
    db.commit()
    db.close()
    print(f'\nAdmin account "{username}" created. You can now log in and use the Users page to add more accounts.')

if __name__ == '__main__':
    main()
