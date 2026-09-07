"""Add the user approval status column to an existing seating_db.

Run this once if your database was created before the Admin Approval feature:
    python migrate_approval.py
"""
import mysql.connector

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="seating_db"
)
cursor = db.cursor()

cursor.execute("""
    SELECT COUNT(*)
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA='seating_db'
      AND TABLE_NAME='users'
      AND COLUMN_NAME='status'
""")
exists = cursor.fetchone()[0]

if not exists:
    cursor.execute(
        "ALTER TABLE users ADD COLUMN status VARCHAR(20) DEFAULT 'approved' AFTER role"
    )
    db.commit()
    print("Approval feature added. Existing users are marked Approved.")
else:
    print("The status column already exists. No changes needed.")

cursor.close()
db.close()
