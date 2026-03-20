from flask import Blueprint, render_template, request, redirect, url_for, session, current_app, flash
from functools import wraps
from datetime import datetime
from app.utils.crypto import decrypt_aes256

dashboard_bp = Blueprint('dashboard', __name__)

def login_required(f):
    """Require login session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            flash("Please log in first.", "warning")
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@dashboard_bp.route('/dashboard')
@login_required
def index():
    user_id = session['user_id']
    mysql = current_app.mysql
    cur = mysql.connection.cursor()
    try:
        # Get user info and account balance
        cur.execute("SELECT full_name FROM users WHERE user_id = %s", (user_id,))
        user = cur.fetchone()
        full_name = user[0] if user else 'Unknown'

        cur.execute("""
            SELECT account_number, balance FROM accounts 
            WHERE user_id = %s AND status = 'active'
        """, (user_id,))
        account = cur.fetchone()
        if account and account[0]:
            decrypted_acc = decrypt_aes256(account[0])
            account_number = "XXXX" + decrypted_acc[-4:] if len(decrypted_acc) >= 4 else decrypted_acc
        else:
            account_number = None
        balance = float(account[1]) if account and account[1] else 0.

        # Recent transactions
        cur.execute("""
            SELECT type, amount, status, created_at FROM transactions 
            WHERE account_id = (SELECT account_id FROM accounts WHERE user_id = %s LIMIT 1)
            ORDER BY created_at DESC LIMIT 5
        """, (user_id,))
        recent_txns = []
        for r in cur.fetchall():
            recent_txns.append({
                'type': r[0] or '—',
                'amount': f"{float(r[1]):,.2f}",
                'status': r[2] or '—',
                'date': r[3].strftime('%b %d, %Y') if r[3] else '—'
            })
    finally:
        cur.close()
    return render_template('dashboard.html', 
                          full_name=full_name, 
                          account_number=account_number,
                          balance=f"{balance:,.2f}",
                          recent_txns=recent_txns,
                          active_page='dashboard')

@dashboard_bp.route('/accounts')
@login_required
def accounts():

    user_id = session['user_id']
    mysql = current_app.mysql
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT account_number,balance
        FROM accounts
        WHERE user_id=%s
        LIMIT 1
    """,(user_id,))

    account = cur.fetchone()

    cur.close()

    if account:
        decrypted_acc = decrypt_aes256(account[0]) if account[0] else ""
        account_number = "XXXX" + decrypted_acc[-4:] if len(decrypted_acc) >= 4 else decrypted_acc
        balance = f"{float(account[1]):,.2f}"
    else:
        account_number = "—"
        balance = "0.00"

    return render_template(
        "accounts.html",
        account_number=account_number,
        balance=balance,
        account_type="Savings",
        active_page="accounts"
    )

@dashboard_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session['user_id']
    mysql = current_app.mysql
    
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        phone = request.form.get('phone', '').strip()
        if full_name:
            cur = mysql.connection.cursor()
            try:
                # We also need to encrypt phone if we are storing it encrypted
                from app.utils.crypto import encrypt_aes256
                enced_phone = encrypt_aes256(phone)
                cur.execute("UPDATE users SET full_name = %s, phone = %s WHERE user_id = %s", (full_name, enced_phone, user_id))
                mysql.connection.commit()
                session['full_name'] = full_name
                flash("Profile updated successfully.", "success")
            except Exception as e:
                flash(f"Error updating profile: {e}", "danger")
            finally:
                cur.close()
        return redirect(url_for('dashboard.profile'))

    cur = mysql.connection.cursor()

    # user info
    cur.execute(
        "SELECT full_name, email, phone FROM users WHERE user_id=%s",
        (user_id,)
    )
    user = cur.fetchone()

    # account info
    cur.execute(
        "SELECT account_number, created_at FROM accounts WHERE user_id=%s LIMIT 1",
        (user_id,)
    )
    account = cur.fetchone()
    cur.close()

    from app.utils.crypto import decrypt_aes256
    decrypted_phone = decrypt_aes256(user[2]) if user and user[2] else ""
    
    profile_data = {
        "full_name": user[0],
        "email": user[1],
        "phone": decrypted_phone
    }

    if account and account[0]:
        decrypted_acc = decrypt_aes256(account[0])
        account_number = "XXXX" + decrypted_acc[-4:] if len(decrypted_acc) >= 4 else decrypted_acc
    else:
        account_number = "—"
        
    account_created = account[1] if account else None

    return render_template(
        "profile.html",
        profile=profile_data,
        account_number=account_number,
        account_created=account_created,
        active_page="profile"
    )

@dashboard_bp.route('/deposit', methods=['GET', 'POST'])
@login_required
def deposit():
    user_id = session['user_id']
    if request.method == 'POST':
        amount = request.form.get('amount')
        if amount:
            try:
                amount = float(amount)
                if amount > 0:
                    mysql = current_app.mysql
                    cur = mysql.connection.cursor()
                    # Assume first active account
                    cur.execute("SELECT account_id FROM accounts WHERE user_id = %s AND status = 'active' LIMIT 1", (user_id,))
                    account = cur.fetchone()
                    if account:
                        account_id = account[0]
                        cur.execute("""
                            INSERT INTO transactions (account_id, type, amount, status) 
                            VALUES (%s, 'deposit', %s, 'completed')
                        """, (account_id, amount))
                        cur.execute("UPDATE accounts SET balance = balance + %s WHERE account_id = %s", (amount, account_id))
                        mysql.connection.commit()
                        cur.close()
                        flash(f"Deposited ${amount:,.2f} successfully!", "success")
                        return redirect(url_for('dashboard.index'))
                    cur.close()
                flash("Invalid amount or no active account.", "danger")
            except ValueError:
                flash("Invalid amount.", "danger")
    return render_template('deposit.html', active_page='deposit')

@dashboard_bp.route('/withdraw')
@login_required
def withdraw():
    return render_template(
        "withdraw.html",
        active_page="withdraw"
    )
