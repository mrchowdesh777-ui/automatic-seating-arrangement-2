# ============================================
# AUTOMATIC SEATING ARRANGEMENT SYSTEM
# app.py - Updated with Create User + Forgot Password
# SECURITY HARDENED VERSION
# ============================================

import os
import time
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
import mysql.connector
import csv
import io
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from algorithm import generate_seating

app = Flask(__name__)

# ---- SECRET KEY ----
# Never hardcode this. Set it as an environment variable before running:
#   Windows (cmd):   set SEATING_SECRET_KEY=some-long-random-string
#   Windows (ps):    $env:SEATING_SECRET_KEY="some-long-random-string"
#   Linux/Mac:       export SEATING_SECRET_KEY=some-long-random-string
# If it's not set, a random key is generated each run (this will log
# everyone out whenever the server restarts, which is fine for local
# testing but NOT what you want in real deployment).
app.secret_key = os.environ.get("SEATING_SECRET_KEY") or os.urandom(32).hex()

app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

# ---- SESSION / COOKIE HARDENING ----
app.config['SESSION_COOKIE_HTTPONLY'] = True     # JS on the page can't read the cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'    # blocks most cross-site request forgery
# Only send the cookie over HTTPS. Turn this on once you deploy behind HTTPS
# (leave it False for local http://localhost testing, or the cookie won't be sent at all).
app.config['SESSION_COOKIE_SECURE'] = os.environ.get("SEATING_HTTPS", "false").lower() == "true"

ALLOWED_EXTENSIONS = {'csv', 'txt', 'xlsx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="seating_db"
    )
    return db

# ============================================
# ACCESS CONTROL HELPERS
# ============================================
def login_required(view_func):
    """Blocks the route unless someone is logged in."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapped

def admin_required(view_func):
    """Blocks the route unless the logged-in user's role is admin."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('You do not have permission to do that.', 'error')
            return redirect(url_for('dashboard'))
        return view_func(*args, **kwargs)
    return wrapped

# ============================================
# BASIC LOGIN RATE LIMITING (brute-force guard)
# ============================================
# In-memory only (resets on restart). Good enough to stop naive password
# guessing scripts. For a real deployment, use Flask-Limiter + Redis instead.
_failed_attempts = {}   # key -> [count, locked_until_timestamp]
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60

def _attempt_key():
    # Track by username+IP so one bad actor can't lock out a real user forever,
    # but repeated guesses against one account from anywhere still get slowed.
    return f"{request.form.get('username','')}"

def is_locked_out(key):
    entry = _failed_attempts.get(key)
    if not entry:
        return False
    count, locked_until = entry
    if locked_until and time.time() < locked_until:
        return True
    return False

def register_failed_attempt(key):
    count, locked_until = _failed_attempts.get(key, [0, 0])
    count += 1
    if count >= MAX_ATTEMPTS:
        locked_until = time.time() + LOCKOUT_SECONDS
        count = 0
    _failed_attempts[key] = [count, locked_until]

def clear_failed_attempts(key):
    _failed_attempts.pop(key, None)

# ============================================
# ROUTE 1: LOGIN
# ============================================
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        key = _attempt_key()

        if is_locked_out(key):
            flash('Too many failed attempts. Please wait a minute and try again.', 'error')
            return render_template('login.html', active_tab='login')

        db = get_db()
        cursor = db.cursor(dictionary=True)

        # Look up the user by username only — never put the password in the
        # SQL query. Compare it separately against the stored hash.
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        db.close()

        if user and check_password_hash(user['password'], password):
            if user.get('status', 'approved') != 'approved':
                clear_failed_attempts(key)
                if user.get('status') == 'rejected':
                    flash('Your registration was rejected by the Admin.', 'error')
                else:
                    flash('Your account is waiting for Admin approval.', 'error')
                return render_template('login.html', active_tab='login')
            clear_failed_attempts(key)
            session.clear()
            session['logged_in'] = True
            session['user_id']   = user['user_id']
            session['username']  = user['username']
            session['full_name'] = user['full_name']
            session['role']      = user['role']
            return redirect(url_for('dashboard'))
        else:
            register_failed_attempt(key)
            flash('Invalid username or password!', 'error')

    return render_template('login.html', active_tab='login')

# ============================================
# ROUTE 2: LOGOUT
# ============================================
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ============================================
# ROUTE 3: USER MANAGEMENT (Admin only)
# ============================================
@app.route('/users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    db = get_db()
    cursor = db.cursor(dictionary=True)

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add':
            # Accounts created directly by an Admin are approved immediately.
            full_name        = request.form['full_name'].strip()
            new_username     = request.form['new_username'].strip()
            email            = request.form['email'].strip()
            new_password     = request.form['new_password']
            confirm_password = request.form['confirm_password']
            role             = request.form['role']

            if role not in ('teacher', 'admin'):
                role = 'teacher'

            if len(new_username) < 3:
                flash('Username must be at least 3 characters!', 'error')
            elif new_password != confirm_password:
                flash('Passwords do not match!', 'error')
            elif len(new_password) < 6:
                flash('Password must be at least 6 characters!', 'error')
            else:
                cursor.execute("SELECT * FROM users WHERE username=%s", (new_username,))
                if cursor.fetchone():
                    flash(f'Username "{new_username}" already exists!', 'error')
                else:
                    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
                    if cursor.fetchone():
                        flash('This email is already registered!', 'error')
                    else:
                        hashed = generate_password_hash(new_password)
                        cursor.execute(
                            """INSERT INTO users
                               (full_name, username, email, password, role, status)
                               VALUES (%s,%s,%s,%s,%s,'approved')""",
                            (full_name, new_username, email, hashed, role)
                        )
                        db.commit()
                        flash(f'User "{new_username}" created and approved!', 'success')

        elif action == 'approve':
            user_id = request.form['user_id']
            cursor.execute(
                "UPDATE users SET status='approved' WHERE user_id=%s",
                (user_id,)
            )
            db.commit()
            flash('User approved successfully!', 'success')

        elif action == 'reject':
            user_id = request.form['user_id']
            # Keep the record so the Admin can see that the request was rejected.
            cursor.execute(
                "UPDATE users SET status='rejected' WHERE user_id=%s AND role='teacher'",
                (user_id,)
            )
            db.commit()
            flash('User registration rejected!', 'success')

        elif action == 'delete':
            user_id = request.form['user_id']
            if str(user_id) == str(session.get('user_id')):
                flash("You can't delete your own account while logged in as it.", 'error')
            else:
                cursor.execute("DELETE FROM users WHERE user_id=%s", (user_id,))
                db.commit()
                flash('User deleted!', 'success')

    cursor.execute("""SELECT user_id, full_name, username, email, role, status, created_at
                      FROM users ORDER BY
                      CASE WHEN status='pending' THEN 0 ELSE 1 END, user_id""")
    all_users = cursor.fetchall()
    db.close()
    return render_template('users.html', users=all_users)

# ============================================
# ROUTE 4: NEW USER REGISTRATION
# ============================================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name'].strip()
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if len(username) < 3:
            flash('Username must be at least 3 characters!', 'error')
        elif password != confirm_password:
            flash('Passwords do not match!', 'error')
        elif len(password) < 6:
            flash('Password must be at least 6 characters!', 'error')
        else:
            db = get_db()
            cursor = db.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
            username_exists = cursor.fetchone()
            cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
            email_exists = cursor.fetchone()

            if username_exists:
                flash('Username already exists!', 'error')
            elif email_exists:
                flash('This email is already registered!', 'error')
            else:
                # The very first registered account becomes the initial Admin.
                # Every later self-registered account is a Teacher and must be
                # approved by an existing Admin before it can log in.
                cursor.execute("SELECT COUNT(*) AS user_count FROM users")
                user_count = cursor.fetchone()['user_count']

                hashed = generate_password_hash(password)
                if user_count == 0:
                    role = 'admin'
                    status = 'approved'
                    success_message = 'First account created as Admin. You can now log in.'
                else:
                    role = 'teacher'
                    status = 'pending'
                    success_message = 'Registration submitted! Please wait for Admin approval before logging in.'

                cursor.execute(
                    """INSERT INTO users
                       (full_name, username, email, password, role, status)
                       VALUES (%s,%s,%s,%s,%s,%s)""",
                    (full_name, username, email, hashed, role, status)
                )
                db.commit()
                db.close()
                flash(success_message, 'success')
                return redirect(url_for('login'))

            db.close()

    return render_template('register.html')

# ============================================
# ROUTE 5: FORGOT PASSWORD - Verify identity
# ============================================
# ============================================
@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    forgot_username = request.form['forgot_username'].strip()
    forgot_email    = request.form['forgot_email'].strip()

    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Check if username + email match in database
    cursor.execute(
        "SELECT * FROM users WHERE username=%s AND email=%s",
        (forgot_username, forgot_email)
    )
    user = cursor.fetchone()
    db.close()

    if user:
        # Save username in session for password reset step
        session['reset_user'] = forgot_username
        flash('Identity verified! Now set your new password below.', 'success')
        return render_template('login.html', active_tab='forgot', show_reset=True)
    else:
        flash('Username and email do not match our records!', 'error')
        return render_template('login.html', active_tab='forgot', show_reset=False)

# ============================================
# ROUTE 5: RESET PASSWORD - Save new password
# ============================================
@app.route('/reset_password', methods=['POST'])
def reset_password():
    # Check session
    if not session.get('reset_user'):
        flash('Session expired. Please try again.', 'error')
        return redirect(url_for('login'))

    new_password     = request.form['new_password']
    confirm_password = request.form['confirm_password']

    if new_password != confirm_password:
        flash('Passwords do not match!', 'error')
        return render_template('login.html', active_tab='forgot', show_reset=True)

    if len(new_password) < 6:
        flash('Password must be at least 6 characters!', 'error')
        return render_template('login.html', active_tab='forgot', show_reset=True)

    # Get username from session and clear it
    username = session.pop('reset_user')
    hashed = generate_password_hash(new_password)

    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "UPDATE users SET password=%s WHERE username=%s",
        (hashed, username)
    )
    db.commit()
    db.close()

    flash(f'Password reset successfully! Login with your new password.', 'success')
    return redirect(url_for('login'))

# ============================================
# ROUTE 6: DASHBOARD
# ============================================
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) as count FROM rooms")
    room_count = cursor.fetchone()['count']
    cursor.execute("SELECT COUNT(*) as count FROM branches")
    branch_count = cursor.fetchone()['count']
    cursor.execute("SELECT COUNT(*) as count FROM students")
    student_count = cursor.fetchone()['count']
    cursor.execute("SELECT COUNT(*) as count FROM allotment")
    allotment_count = cursor.fetchone()['count']
    db.close()
    return render_template('dashboard.html',
        room_count=room_count, branch_count=branch_count,
        student_count=student_count, allotment_count=allotment_count)

# ============================================
# ROUTE 7: ROOMS
# ============================================
@app.route('/rooms', methods=['GET', 'POST'])
@login_required
def rooms():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            room_name = request.form['room_name']
            rows = int(request.form['rows'])
            cols = int(request.form['cols'])
            capacity = rows * cols
            cursor.execute(
                "INSERT INTO rooms (room_name, num_rows, num_cols, capacity) VALUES (%s,%s,%s,%s)",
                (room_name, rows, cols, capacity))
            db.commit()
            flash(f'Room "{room_name}" added!', 'success')
        elif action == 'delete':
            room_id = request.form['room_id']
            try:
                cursor.execute("DELETE FROM allotment WHERE room_id=%s", (room_id,))
                cursor.execute("DELETE FROM rooms WHERE room_id=%s", (room_id,))
                db.commit()
                flash('Room deleted!', 'success')
            except Exception as e:
                db.rollback()
                flash(f'Error: {str(e)}', 'error')
    cursor.execute("SELECT * FROM rooms ORDER BY room_id")
    all_rooms = cursor.fetchall()
    db.close()
    return render_template('rooms.html', rooms=all_rooms)

# ============================================
# ROUTE 8: BRANCHES
# ============================================
@app.route('/branches', methods=['GET', 'POST'])
@login_required
def branches():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            branch_name = request.form['branch_name'].upper()
            cursor.execute("SELECT * FROM branches WHERE branch_name=%s", (branch_name,))
            if cursor.fetchone():
                flash(f'Branch "{branch_name}" already exists!', 'error')
            else:
                cursor.execute("INSERT INTO branches (branch_name, total_students) VALUES (%s,%s)", (branch_name, 0))
                db.commit()
                flash(f'Branch "{branch_name}" added!', 'success')
        elif action == 'delete':
            branch_id = request.form['branch_id']
            cursor.execute("DELETE FROM students WHERE branch_id=%s", (branch_id,))
            cursor.execute("DELETE FROM branches WHERE branch_id=%s", (branch_id,))
            db.commit()
            flash('Branch deleted!', 'success')
    cursor.execute("""SELECT b.*, COUNT(s.student_id) as actual_students
        FROM branches b LEFT JOIN students s ON b.branch_id=s.branch_id
        GROUP BY b.branch_id ORDER BY b.branch_id""")
    all_branches = cursor.fetchall()
    db.close()
    return render_template('branches.html', branches=all_branches)

# ============================================
# ROUTE 9: UPLOAD STUDENTS (Paste)
# ============================================
@app.route('/upload_students', methods=['GET', 'POST'])
@login_required
def upload_students():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    if request.method == 'POST':
        branch_id = request.form['branch_id']
        pin_list_raw = request.form['pin_list']
        pins = [p.strip() for p in pin_list_raw.replace('\n', ',').split(',') if p.strip()]
        cursor.execute("DELETE FROM students WHERE branch_id=%s", (branch_id,))
        data = [(pin, branch_id) for pin in pins]
        cursor.executemany("INSERT INTO students (pin_number, branch_id) VALUES (%s,%s)", data)
        cursor.execute("UPDATE branches SET total_students=%s WHERE branch_id=%s", (len(pins), branch_id))
        db.commit()
        flash(f'{len(pins)} students uploaded!', 'success')
    cursor.execute("SELECT * FROM branches ORDER BY branch_id")
    all_branches = cursor.fetchall()
    cursor.execute("SELECT branch_id, COUNT(*) as count FROM students GROUP BY branch_id")
    counts = {row['branch_id']: row['count'] for row in cursor.fetchall()}
    db.close()
    return render_template('upload_students.html', branches=all_branches, counts=counts)

# ============================================
# ROUTE 10: UPLOAD FILE (CSV/Excel)
# ============================================
@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    branch_id = request.form.get('branch_id')
    if not branch_id:
        flash('Please select a branch!', 'error')
        return redirect(url_for('upload_students'))
    if 'keylist_file' not in request.files:
        flash('No file selected!', 'error')
        return redirect(url_for('upload_students'))
    file = request.files['keylist_file']
    if file.filename == '' or not allowed_file(file.filename):
        flash('Invalid file!', 'error')
        return redirect(url_for('upload_students'))
    db = get_db()
    cursor = db.cursor(dictionary=True)
    pins = []
    filename = file.filename.lower()
    try:
        if filename.endswith('.csv') or filename.endswith('.txt'):
            content = file.stream.read().decode('UTF-8')
            stream = io.StringIO(content)
            if ',' in content:
                for row in csv.reader(stream):
                    for cell in row:
                        cell = cell.strip()
                        if cell: pins.append(cell)
            else:
                for line in content.splitlines():
                    line = line.strip()
                    if line: pins.append(line)
        elif filename.endswith('.xlsx'):
            import openpyxl
            wb = openpyxl.load_workbook(file)
            ws = wb.active
            for row in ws.iter_rows(min_row=1, values_only=True):
                if row[0]: pins.append(str(row[0]).strip())
        if not pins:
            flash('No PIN numbers found!', 'error')
            return redirect(url_for('upload_students'))
        cursor.execute("DELETE FROM students WHERE branch_id=%s", (branch_id,))
        data = [(pin, branch_id) for pin in pins]
        cursor.executemany("INSERT INTO students (pin_number, branch_id) VALUES (%s,%s)", data)
        cursor.execute("UPDATE branches SET total_students=%s WHERE branch_id=%s", (len(pins), branch_id))
        db.commit()
        flash(f'{len(pins)} students uploaded from "{file.filename}"!', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    db.close()
    return redirect(url_for('upload_students'))

# ============================================
# ROUTE 11: GENERATE SEATING PLAN
# ============================================
@app.route('/generate', methods=['GET', 'POST'])
@login_required
def generate():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    if request.method == 'POST':
        cursor.execute("DELETE FROM allotment")
        db.commit()
        cursor.execute("SELECT * FROM rooms ORDER BY room_id")
        all_rooms = cursor.fetchall()
        cursor.execute("SELECT * FROM branches ORDER BY branch_id")
        all_branches = cursor.fetchall()
        students_by_branch = {}
        for branch in all_branches:
            cursor.execute(
                "SELECT pin_number, student_id FROM students WHERE branch_id=%s ORDER BY student_id",
                (branch['branch_id'],))
            students_by_branch[branch['branch_name']] = cursor.fetchall()
        branch_names = [b['branch_name'] for b in all_branches]
        allotment_result = generate_seating(branch_names, students_by_branch, all_rooms)
        for entry in allotment_result:
            cursor.execute(
                "INSERT INTO allotment (room_id, row_no, col_no, student_id, pin_number, branch_name) VALUES (%s,%s,%s,%s,%s,%s)",
                (entry['room_id'], entry['num_row'], entry['num_col'], entry['student_id'], entry['pin'], entry['branch']))
        db.commit()
        flash(f'Seating plan generated! {len(allotment_result)} seats assigned.', 'success')
        return redirect(url_for('view_chart'))
    cursor.execute("SELECT * FROM rooms")
    all_rooms = cursor.fetchall()
    cursor.execute("""SELECT b.*, COUNT(s.student_id) as actual_students
        FROM branches b LEFT JOIN students s ON b.branch_id=s.branch_id GROUP BY b.branch_id""")
    all_branches = cursor.fetchall()
    db.close()
    return render_template('generate.html', rooms=all_rooms, branches=all_branches)

# ============================================
# ROUTE 12: VIEW SEATING CHART
# ============================================
@app.route('/view_chart')
@login_required
def view_chart():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM rooms ORDER BY room_id")
    all_rooms = cursor.fetchall()
    seating_data = {}
    for room in all_rooms:
        cursor.execute(
            "SELECT * FROM allotment WHERE room_id=%s ORDER BY row_no, col_no",
            (room['room_id'],))
        seats = cursor.fetchall()
        grid = {}
        for seat in seats:
            grid[(seat['row_no'], seat['col_no'])] = seat
        seating_data[room['room_id']] = {'room': room, 'grid': grid}
    db.close()
    return render_template('seating_chart.html', seating_data=seating_data)

if __name__ == '__main__':
    # Debug mode shows stack traces and lets attackers run arbitrary code
    # through the browser if the server is ever reachable from outside your
    # own machine. It defaults to OFF now. Turn it on only for local dev:
    #   set SEATING_DEBUG=true   (Windows)   /   export SEATING_DEBUG=true (Linux/Mac)
    debug_mode = os.environ.get("SEATING_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)
