-- ============================================
-- AUTOMATIC SEATING ARRANGEMENT SYSTEM
-- MySQL Database Setup Script
-- Run this FIRST before starting the app
-- ============================================

-- Step 1: Create the database
CREATE DATABASE IF NOT EXISTS seating_db;
USE seating_db;

-- Step 2: Create ROOMS table
CREATE TABLE IF NOT EXISTS rooms (
    room_id   INT AUTO_INCREMENT PRIMARY KEY,
    room_name VARCHAR(100) NOT NULL,
    num_rows  INT NOT NULL,
    num_cols  INT NOT NULL,
    capacity  INT NOT NULL
);

-- Step 3: Create BRANCHES table
CREATE TABLE IF NOT EXISTS branches (
    branch_id      INT AUTO_INCREMENT PRIMARY KEY,
    branch_name    VARCHAR(50) NOT NULL,
    total_students INT DEFAULT 0
);

-- Step 4: Create STUDENTS table
CREATE TABLE IF NOT EXISTS students (
    student_id INT AUTO_INCREMENT PRIMARY KEY,
    pin_number VARCHAR(30) NOT NULL,
    branch_id  INT NOT NULL,
    FOREIGN KEY (branch_id) REFERENCES branches(branch_id)
);

-- Step 5: Create ALLOTMENT table
CREATE TABLE IF NOT EXISTS allotment (
    seat_id     INT AUTO_INCREMENT PRIMARY KEY,
    room_id     INT NOT NULL,
    row_no      INT NOT NULL,
    col_no      INT NOT NULL,
    student_id  INT,
    pin_number  VARCHAR(30),
    branch_name VARCHAR(50),
    FOREIGN KEY (room_id) REFERENCES rooms(room_id)
);
-- Step 6: NEW - Create USERS table for login
CREATE TABLE IF NOT EXISTS users (
    user_id    INT AUTO_INCREMENT PRIMARY KEY,
    full_name  VARCHAR(100) NOT NULL,
    username   VARCHAR(50)  UNIQUE NOT NULL,
    email      VARCHAR(100) UNIQUE NOT NULL,
    password   VARCHAR(255) NOT NULL,
    role       VARCHAR(20)  DEFAULT 'teacher',
    status     VARCHAR(20)  DEFAULT 'approved',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Step 7: Create your admin account
-- Passwords must be hashed (never stored as plain text), which can't be
-- done in a plain SQL script. After running this file, create your first
-- admin login by running:
--
--     python create_admin.py
--
-- (If you're upgrading a database that already has the old plaintext
-- admin row from a previous version of this file, run migrate_passwords.py
-- instead to hash it in place.)

-- Done! Now run: python create_admin.py, then python app.py

-- If the users table already exists from an older version, run this once:
-- ALTER TABLE users ADD COLUMN status VARCHAR(20) DEFAULT 'approved';
