import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import random
from email.message import EmailMessage

# ---------------------- CREATE DB IF NOT EXISTS ----------------------
if not os.path.exists("college_explorer.db"):
    conn = sqlite3.connect("college_explorer.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS college_connect (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            location TEXT,
            infrastructure TEXT,
            fees TEXT,
            events TEXT,
            placements TEXT
        )
    ''')
    conn.commit()
    conn.close()

# ---------------------- FLASK CONFIG ----------------------
app = Flask(__name__)
app.secret_key = 'chandu123@#'
db = sqlite3.connect("college_explorer.db", check_same_thread=False)
cursor = db.cursor()

# ---------------------- EMAIL OTP FUNCTION ----------------------
def send_otp_to_email(recipient_email, otp):
    EMAIL_ADDRESS = "chandu134t@gmail.com"
    EMAIL_PASSWORD = "qloo zxbz sujq darw"

    msg = EmailMessage()
    msg['Subject'] = 'Your College Explorer OTP Verification'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = recipient_email
    msg.set_content(f"Your OTP is: {otp}")

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending OTP: {e}")
        return False

# ---------------------- ROUTES ----------------------

@app.route('/')
def home():
    return redirect(url_for('login_form'))

# ---------- Signup ----------
@app.route('/signup', methods=['GET', 'POST'])
def signup_form():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        if not email.endswith('@gmail.com'):
            return render_template('signup.html', error="❌ Only Gmail addresses are accepted.")

        otp = str(random.randint(100000, 999999))
        if send_otp_to_email(email, otp):
            session['temp_user'] = {'name': name, 'email': email, 'password': password}
            session['otp'] = otp
            session['resend_count'] = 0
            return redirect(url_for('verify_otp'))
        else:
            return render_template('signup.html', error="❌ Failed to send OTP.")
    return render_template('signup.html')

# ---------- OTP Verification ----------
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'temp_user' not in session:
        return redirect(url_for('signup_form'))

    if request.method == 'POST':
        if 'resend' in request.form:
            if session['resend_count'] >= 3:
                return render_template('verify_otp.html', error="❌ Resend limit reached.")
            otp = str(random.randint(100000, 999999))
            if send_otp_to_email(session['temp_user']['email'], otp):
                session['otp'] = otp
                session['resend_count'] += 1
                return render_template('verify_otp.html', success="✅ OTP resent.")
            else:
                return render_template('verify_otp.html', error="❌ Failed to resend OTP.")

        if request.form.get('otp') == session.get('otp'):
            user = session['temp_user']
            hashed_password = generate_password_hash(user['password'])

            try:
                cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                               (user['name'], user['email'], hashed_password))
                db.commit()
                session.pop('temp_user', None)
                session.pop('otp', None)
                session.pop('resend_count', None)
                return redirect(url_for('login_form'))
            except Exception as e:
                return render_template('verify_otp.html', error=f"❌ Error: {e}")
        else:
            return render_template('verify_otp.html', error="❌ Invalid OTP.")
    return render_template('verify_otp.html')

# ---------- Login ----------
@app.route('/login', methods=['GET', 'POST'])
def login_form():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user[3], password):  # user[3] is password
            session['user_id'] = user[0]
            session['name'] = user[1]
            return redirect(url_for('colleges'))
        else:
            return render_template('index.html', error="❌ Invalid email or password.")
    return render_template('index.html')

# ---------- Logout ----------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_form'))

# ---------- College Listings ----------
@app.route('/colleges')
def colleges():
    if 'user_id' not in session:
        return redirect(url_for('login_form'))

    search = request.args.get('search', '')
    location = request.args.get('location', '')
    fees = request.args.get('fees', '')

    query = "SELECT * FROM college_connect WHERE 1=1"
    params = []

    if search:
        query += " AND (name LIKE ? OR location LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    if location:
        query += " AND location = ?"
        params.append(location)

    cursor.execute(query, tuple(params))
    colleges_data = cursor.fetchall()
    return render_template('colleges.html', colleges=colleges_data)

# ---------- Forgot Password ----------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        if not user:
            return render_template('forgot_password.html', error="❌ Email not found.")

        otp = str(random.randint(100000, 999999))
        session['reset_email'] = email
        session['reset_otp'] = otp
        session['reset_resend_count'] = 0

        if send_otp_to_email(email, otp):
            return redirect(url_for('verify_reset_otp'))
        else:
            return render_template('forgot_password.html', error="❌ Failed to send OTP.")
    return render_template('forgot_password.html')

# ---------- Reset OTP ----------
@app.route('/verify-reset-otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if request.method == 'POST':
        if 'resend' in request.form:
            if session.get('reset_resend_count', 0) >= 3:
                return render_template('verify_reset_otp.html', error="❌ Resend limit reached.")
            otp = str(random.randint(100000, 999999))
            if send_otp_to_email(session['reset_email'], otp):
                session['reset_otp'] = otp
                session['reset_resend_count'] += 1
                return render_template('verify_reset_otp.html', success="✅ OTP resent.")
            else:
                return render_template('verify_reset_otp.html', error="❌ Failed to resend OTP.")

        if request.form['otp'] == session.get('reset_otp'):
            return redirect(url_for('reset_password'))
        else:
            return render_template('verify_reset_otp.html', error="❌ Invalid OTP.")
    return render_template('verify_reset_otp.html')

# ---------- Reset Password ----------
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        hashed_password = generate_password_hash(new_password)
        email = session.get('reset_email')

        try:
            cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
            db.commit()
            session.clear()
            flash("✅ Password reset successful.", "success")
            return redirect(url_for('login_form'))
        except Exception as e:
            return render_template('reset_password.html', error=f"❌ {str(e)}")
    return render_template('reset_password.html')

# ---------------------- RUN ----------------------
if __name__ == '__main__':
    app.run(debug=True)
