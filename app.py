from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from bson.regex import Regex
from pymongo import MongoClient
import smtplib
import random
from email.message import EmailMessage

app = Flask(__name__)
app.secret_key = 'chandu123@#'

uri = "mongodb+srv://chanduyt58:zTmpDrcURvYoNYrx@cluster0.brsszq1.mongodb.net/"
client = MongoClient(uri)
db = client["college-explorer"]
collection = db["college_connect"]
collection_colleges = db["college"]

# ---------------- HOME ----------------
@app.route('/')
def home():
    return "🎓 Welcome to College Explorer (Flask + MongoDB working!)"

# ---------------- SIGNUP ----------------
@app.route('/signup', methods=['GET'])
def signup_form():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup_submit():
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
        return render_template('signup.html', error="❌ Failed to send OTP. Please try again later.")

def send_otp_to_email(recipient_email, otp):
    EMAIL_ADDRESS = "chandu134t@gmail.com"
    EMAIL_PASSWORD = "qloo zxbz sujq darw"

    msg = EmailMessage()
    msg['Subject'] = 'Your College Explorer OTP Verification'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = recipient_email
    msg.set_content(f"Your OTP to verify your email is: {otp}")

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending OTP: {e}")
        return False

# ---------------- OTP VERIFICATION ----------------
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'temp_user' not in session:
        return redirect(url_for('signup_form'))

    if request.method == 'POST':
        if 'resend' in request.form:
            if session.get('resend_count', 0) >= 3:
                return render_template('verify_otp.html', error="❌ You have reached the maximum OTP resend attempts.")

            otp = str(random.randint(100000, 999999))
            email = session['temp_user']['email']

            if send_otp_to_email(email, otp):
                session['otp'] = otp
                session['resend_count'] += 1
                session.modified = True
                return render_template('verify_otp.html', success="✅ OTP resent to your Gmail successfully.")
            else:
                return render_template('verify_otp.html', error="❌ Failed to resend OTP. Please try again later.")

        entered_otp = request.form.get('otp', '')
        if entered_otp == session.get('otp'):
            user = session.get('temp_user')
            hashed_password = generate_password_hash(user['password'])

            try:
                collection.insert_one({"email": user['email'], "name": user['name'], "password": hashed_password})
                session.pop('otp', None)
                session.pop('temp_user', None)
                session.pop('resend_count', None)
                return redirect(url_for('login_form'))
            except Exception as e:
                return render_template('verify_otp.html', error=f"❌ Signup failed: {str(e)}")
        else:
            return render_template('verify_otp.html', error="❌ Invalid OTP.")

    return render_template('verify_otp.html')

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET'])
def login_form():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_submit():
    email = request.form['email']
    password = request.form['password']

    try:
        user = collection.find_one({"email": email})

        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['name'] = user['name']
            return redirect(url_for('colleges'))
        else:
            return render_template('login.html', error="❌ Invalid email or password.")
    except Exception as e:
        return render_template('login.html', error=f"❌ Login Error: {str(e)}")

# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        name = session['name']
        return f"<h2>🎉 Welcome, {name}!</h2><br><a href='/logout'>Logout</a><br><a href='/colleges'>Explore Colleges</a>"
    else:
        return redirect(url_for('login_form'))

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_form'))

# ---------------- COLLEGES ----------------
@app.route('/colleges')
def colleges():
    search = request.args.get('search', '').strip()
    location = request.args.get('location', '').strip()
    fees_filter = request.args.get('fees', '').strip()

    query = {}

    if search:
        regex = Regex(f".*{search}.*", "i")
        query["$or"] = [{"name": regex}, {"location": regex}]

    if location:
        query["location"] = location

    if fees_filter:
        if fees_filter == "low":
            query["fees_numeric"] = {"$lt": 70000}
        elif fees_filter == "medium":
            query["fees_numeric"] = {"$gte": 70000, "$lte": 100000}
        elif fees_filter == "high":
            query["fees_numeric"] = {"$gt": 100000}

    try:
        colleges_data = list(collection_colleges.find(query))
        return render_template('colleges.html', colleges=colleges_data)
    except Exception as e:
        return f"❌ Error fetching colleges: {str(e)}"

# ---------------- FORGOT PASSWORD ----------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = collection.find_one({"email": email})
        if not user:
            return render_template('forgot_password.html', error="❌ Email not registered.")

        otp = str(random.randint(100000, 999999))
        session['reset_email'] = email
        session['reset_otp'] = otp
        session['reset_resend_count'] = 0

        if send_otp_to_email(email, otp):
            return redirect(url_for('verify_reset_otp'))
        else:
            return render_template('forgot_password.html', error="❌ Failed to send OTP.")
    return render_template('forgot_password.html')

@app.route('/verify-reset-otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if request.method == 'POST':
        if 'resend' in request.form:
            if session.get('reset_resend_count', 0) >= 3:
                return render_template('verify_reset_otp.html', error="❌ OTP resend limit reached.")

            otp = str(random.randint(100000, 999999))
            email = session.get('reset_email')

            if send_otp_to_email(email, otp):
                session['reset_otp'] = otp
                session['reset_resend_count'] += 1
                return render_template('verify_reset_otp.html', success="✅ OTP resent to your Gmail.")
            else:
                return render_template('verify_reset_otp.html', error="❌ Failed to resend OTP.")

        entered_otp = request.form['otp']
        if 'reset_otp' in session and entered_otp == session['reset_otp']:
            return redirect(url_for('reset_password'))
        else:
            return render_template('verify_reset_otp.html', error="❌ Invalid OTP.")

    return render_template('verify_reset_otp.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        hashed_password = generate_password_hash(new_password)
        email = session.get('reset_email')
        try:
            collection.update_one({"email": email}, {"$set": {"password": hashed_password}})
            session.pop('reset_email', None)
            session.pop('reset_otp', None)
            session.pop('reset_resend_count', None)
            flash("✅ Password reset successful. Please login.", "success")
            return redirect(url_for('login_form'))
        except Exception as e:
            return render_template('reset_password.html', error=f"❌ Failed to reset password: {str(e)}")

    return render_template('reset_password.html')

# ---------------- RUN APP ----------------
if __name__ == '__main__':
    app.run(debug=True, port=5001)
