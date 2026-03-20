from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app import mysql
import bcrypt
from app.utils.crypto import hash_sha256, encrypt_aes256, decrypt_aes256
import random
from datetime import datetime, timedelta
from flask_mail import Message
from app import mail

bp = Blueprint("auth", __name__, url_prefix="/auth")

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(user_email, otp):
    msg = Message(
        subject="Your OTP Code",
        recipients=[user_email],
        body=f"Your OTP is: {otp}. It is valid for 5 minutes."
    )
    mail.send(msg)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Email and password are required.", "danger")
            return redirect(url_for("auth.login"))

        try:
            cur = mysql.connection.cursor()
            cur.execute(
                "SELECT u.user_id, u.full_name, u.password_hash, a.status FROM users u LEFT JOIN accounts a ON u.user_id = a.user_id WHERE u.email = %s",
                (email,),
            )
            user = cur.fetchone()
            cur.close()
        except Exception as e:
            flash(f"Database error: {e}", "danger")
            return redirect(url_for("auth.login"))

        if not user:
            flash("Invalid email or password.", "danger")
            return redirect(url_for("auth.login"))

        if user[3] == 'suspended':
            flash("Your account is suspended. You can't login.", "danger")
            return redirect(url_for("auth.login"))

        stored_hash = user[2]
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode("utf-8")

        hashed_attempt = hash_sha256(password)
        if bcrypt.checkpw(hashed_attempt.encode("utf-8"), stored_hash):
            otp = generate_otp()
            session['otp'] = otp
            session['otp_expiry'] = (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            session['temp_user'] = user[0]
            session['temp_full_name'] = user[1]
            session['temp_email'] = email
            session['otp_attempts'] = 0

            try:
                send_otp_email(email, otp)
            except Exception as e:
                flash(f"Failed to send OTP: {e}", "danger")
                return redirect(url_for("auth.login"))

            return redirect(url_for("auth.verify_otp"))

        flash("Invalid email or password.", "danger")
        return redirect(url_for("auth.login"))

    return render_template("login.html")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")

        if not full_name or not email or not password:
            flash("Name, email and password are required.", "danger")
            return redirect(url_for("auth.register"))

        hashed_pwd = hash_sha256(password)
        hashed = bcrypt.hashpw(hashed_pwd.encode("utf-8"), bcrypt.gensalt())
        enced_phone = encrypt_aes256(phone)

        try:
            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO users (full_name, email, phone, password_hash) "
                "VALUES (%s, %s, %s, %s)",
                (full_name, email, enced_phone, hashed),
            )
            user_id = cur.lastrowid
            mysql.connection.commit()
            
            # Auto create account for new user
            import random
            account_number = ''.join(['%d' % random.randint(0, 9) for num in range(20)])
            enced_acc = encrypt_aes256(account_number)
            cur.execute(
                "INSERT INTO accounts (user_id, account_number, balance) VALUES (%s, %s, 0.00)",
                (user_id, enced_acc)
            )
            mysql.connection.commit()
            cur.close()
            flash("Registration successful with account created. Please log in.", "success")
            return redirect(url_for("auth.login"))
        except Exception as e:
            flash(f"Registration failed: {e}", "danger")
            return redirect(url_for("auth.register"))

    return render_template("register.html")


@bp.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if 'otp' not in session:
        flash("No active login session. Please login.", "danger")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        user_otp = request.form.get("otp")
        
        # Check Expiry
        expiry = datetime.strptime(session['otp_expiry'], "%Y-%m-%d %H:%M:%S")
        if datetime.now() > expiry:
            flash("OTP expired", "danger")
            session.pop('otp', None)
            return redirect(url_for("auth.login"))

        if user_otp == session.get('otp'):
            # login complete
            user_id = session.get('temp_user')
            
            cur = mysql.connection.cursor()
            cur.execute("SELECT status FROM accounts WHERE user_id=%s LIMIT 1", (user_id,))
            acc_status = cur.fetchone()
            if acc_status and acc_status[0] == 'suspended':
                flash("Your account is suspended. You can't login.", "danger")
                session.clear()
                return redirect(url_for('auth.login'))
            cur.close()
            
            session['user_id'] = user_id
            session['full_name'] = session.get('temp_full_name')
            session['email'] = session.get('temp_email')
            session['is_admin'] = False
            
            session.pop('otp', None)
            session.pop('temp_user', None)
            session.pop('temp_full_name', None)
            session.pop('temp_email', None)
            session.pop('otp_expiry', None)
            session.pop('otp_attempts', None)

            # Auto create account if not exists
            cur = mysql.connection.cursor()
            cur.execute("SELECT account_id FROM accounts WHERE user_id=%s", (user_id,))
            account = cur.fetchone()
            if not account:
                import random
                account_number = "SB" + str(random.randint(1000000000,9999999999))
                enced_acc = encrypt_aes256(account_number)
                cur.execute(
                    "INSERT INTO accounts (user_id, account_number, balance, status) VALUES (%s,%s,%s,%s)",
                    (user_id, enced_acc, 0, "active")
                )
                mysql.connection.commit()
            cur.close()

            flash("Login successful!", "success")
            return redirect(url_for("dashboard.index"))
        else:
            attempts = session.get('otp_attempts', 0) + 1
            session['otp_attempts'] = attempts
            if attempts >= 3:
                flash("Too many failed attempts. Account locked. Please login again.", "danger")
                session.clear()
                return redirect(url_for("auth.login"))
            else:
                flash(f"Invalid OTP. {3 - attempts} attempts remaining.", "danger")

    return render_template("otp.html")


@bp.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("auth.login"))

