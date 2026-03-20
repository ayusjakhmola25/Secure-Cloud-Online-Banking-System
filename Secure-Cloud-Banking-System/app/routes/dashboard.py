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
        # Get user info including last_login
        cur.execute("SELECT full_name, last_login FROM users WHERE user_id = %s", (user_id,))
        user = cur.fetchone()
        full_name = user[0] if user else 'Unknown'
        last_login = user[1].strftime('%b %d, %I:%M %p') if user and user[1] else '—'

        # Get account info
        cur.execute("""
            SELECT account_number, balance FROM accounts 
            WHERE user_id = %s AND status = 'active'
        """, (user_id,))
        account = cur.fetchone()

        if account and account[0]:
            decrypted_acc = decrypt_aes256(account[0])
            masked_account = "XXXX" + decrypted_acc[-4:] if len(decrypted_acc) >= 4 else decrypted_acc
            full_account_number = decrypted_acc
        else:
            masked_account = None
            full_account_number = None
        balance = float(account[1]) if account and account[1] else 0.0

        # Get account_id for transaction queries
        cur.execute("SELECT account_id FROM accounts WHERE user_id = %s LIMIT 1", (user_id,))
        acc_row = cur.fetchone()
        account_id = acc_row[0] if acc_row else None

        # Compute financial stats from real data
        total_income = 0.0
        total_expenses = 0.0
        transaction_count = 0
        recent_txns = []

        if account_id:
            # Total income (deposits)
            cur.execute("""
                SELECT COALESCE(SUM(amount), 0) FROM transactions 
                WHERE account_id = %s AND type = 'deposit' AND status = 'completed'
            """, (account_id,))
            total_income = float(cur.fetchone()[0])

            # Total expenses (withdrawals + sent transfers)
            cur.execute("""
                SELECT COALESCE(SUM(amount), 0) FROM transactions 
                WHERE account_id = %s AND type IN ('withdraw', 'transfer') AND status = 'completed'
            """, (account_id,))
            total_expenses = float(cur.fetchone()[0])

            # Transaction count
            cur.execute("SELECT COUNT(*) FROM transactions WHERE account_id = %s", (account_id,))
            transaction_count = cur.fetchone()[0]

            # Recent transactions with descriptions
            cur.execute("""
                SELECT type, amount, status, created_at, description FROM transactions 
                WHERE account_id = %s
                ORDER BY created_at DESC LIMIT 5
            """, (account_id,))
            for r in cur.fetchall():
                recent_txns.append({
                    'type': r[0] or '—',
                    'amount': f"${float(r[1]):,.2f}",
                    'status': r[2] or '—',
                    'date': r[3].strftime('%b %d, %Y') if r[3] else '—',
                    'description': r[4] if r[4] else r[0].capitalize() if r[0] else '—'
                })

        net_flow = total_income - total_expenses

    finally:
        cur.close()

    return render_template('dashboard.html', 
                          full_name=full_name, 
                          account_number=masked_account,
                          full_account_number=full_account_number,
                          balance=f"{balance:,.2f}",
                          last_login=last_login,
                          total_income=f"{total_income:,.2f}",
                          total_expenses=f"{total_expenses:,.2f}",
                          transaction_count=transaction_count,
                          net_flow=f"{net_flow:,.2f}",
                          recent_transactions=recent_txns,
                          active_page='dashboard')

@dashboard_bp.route('/accounts')
@login_required
def accounts():
    user_id = session['user_id']
    mysql = current_app.mysql
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT account_number, balance
        FROM accounts
        WHERE user_id=%s
        LIMIT 1
    """, (user_id,))

    account = cur.fetchone()
    cur.close()

    if account:
        decrypted_acc = decrypt_aes256(account[0]) if account[0] else ""
        masked_account = "XXXX" + decrypted_acc[-4:] if len(decrypted_acc) >= 4 else decrypted_acc
        full_account_number = decrypted_acc
        balance = f"{float(account[1]):,.2f}"
    else:
        masked_account = "—"
        full_account_number = ""
        balance = "0.00"

    return render_template(
        "accounts.html",
        account_number=masked_account,
        full_account_number=full_account_number,
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

    cur.execute(
        "SELECT full_name, email, phone FROM users WHERE user_id=%s",
        (user_id,)
    )
    user = cur.fetchone()

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
