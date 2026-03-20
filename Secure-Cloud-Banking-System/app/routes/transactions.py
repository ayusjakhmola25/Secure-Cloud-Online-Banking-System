from flask import Blueprint, render_template, request, redirect, url_for, session, current_app, flash
from functools import wraps
from datetime import datetime
from app.utils.crypto import hash_sha256, encrypt_aes256, decrypt_aes256

transactions_bp = Blueprint('transactions', __name__)

def login_required(f):
    """Require login session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            flash("Please log in first.", "warning")
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def _get_user_balance(user_id):
    """Helper to get current balance for the logged-in user."""
    mysql = current_app.mysql
    cur = mysql.connection.cursor()
    cur.execute("SELECT balance FROM accounts WHERE user_id = %s AND status = 'active' LIMIT 1", (user_id,))
    row = cur.fetchone()
    cur.close()
    return f"{float(row[0]):,.2f}" if row else "0.00"

@transactions_bp.route('/transactions')
@login_required
def index():
    user_id = session['user_id']
    mysql = current_app.mysql
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            SELECT t.transaction_id, t.type, t.amount, t.status, t.created_at, t.description
            FROM transactions t
            JOIN accounts a ON t.account_id = a.account_id
            WHERE a.user_id = %s
            ORDER BY t.created_at DESC
        """, (user_id,))
        txns = []
        for r in cur.fetchall():
            txns.append({
                'id': r[0],
                'type': r[1] or '—',
                'amount': f"{float(r[2]):,.2f}",
                'status': r[3] or '—',
                'date': r[4].strftime('%b %d, %Y %H:%M') if r[4] else '—',
                'description': r[5] if r[5] else (r[1].capitalize() if r[1] else '—')
            })
    finally:
        cur.close()
    return render_template('transactions.html', transactions=txns, active_page='transactions')

@transactions_bp.route('/history')
@login_required
def history():
    user_id = session['user_id']
    mysql = current_app.mysql
    cur = mysql.connection.cursor()

    cur.execute(
        "SELECT account_id FROM accounts WHERE user_id=%s LIMIT 1",
        (user_id,)
    )
    account = cur.fetchone()

    if not account:
        return render_template("history.html", transactions=[], active_page="transactions")

    account_id = account[0]

    cur.execute("""
        SELECT transaction_id, type, amount, description, created_at, status
        FROM transactions
        WHERE account_id = %s
        ORDER BY created_at DESC
    """, (account_id,))

    rows = cur.fetchall()
    transactions = []

    for r in rows:
        transactions.append({
            "id": r[0],
            "type": r[1],
            "amount": f"${float(r[2]):,.2f}",
            "description": r[3] if r[3] else (r[1].capitalize() if r[1] else '—'),
            "date": r[4].strftime("%d %b %Y %I:%M %p") if r[4] else "—",
            "status": r[5]
        })

    cur.close()

    return render_template(
        "history.html",
        transactions=transactions,
        active_page="transactions"
    )

@transactions_bp.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    user_id = session['user_id']
    balance = _get_user_balance(user_id)

    if request.method == 'POST':
        # Read from form — the template sends 'recipient_account'
        to_account_input = request.form.get('recipient_account', '').strip()
        amount = request.form.get('amount')
        description = request.form.get('description', '').strip()

        if not to_account_input:
            flash("Receiver account number or email is required.", "danger")
            return redirect(url_for('transactions.transfer'))

        if amount:
            try:
                amount = float(amount)
                if amount > 0:
                    mysql = current_app.mysql
                    cur = mysql.connection.cursor()

                    # From user's account
                    cur.execute("SELECT account_id, balance FROM accounts WHERE user_id = %s AND status = 'active' LIMIT 1", (user_id,))
                    from_account = cur.fetchone()

                    if not from_account:
                        cur.close()
                        flash("No active account found.", "danger")
                        return redirect(url_for('transactions.transfer'))

                    if float(from_account[1]) < amount:
                        cur.close()
                        flash("Insufficient balance.", "danger")
                        return redirect(url_for('transactions.transfer'))

                    from_account_id = from_account[0]

                    # Try to find receiver — by account number OR by email
                    to_account_id = None

                    # First try email lookup
                    cur.execute("""
                        SELECT a.account_id, u.full_name FROM accounts a 
                        JOIN users u ON a.user_id = u.user_id 
                        WHERE u.email = %s AND a.status = 'active' LIMIT 1
                    """, (to_account_input,))
                    email_match = cur.fetchone()

                    if email_match:
                        to_account_id = email_match[0]
                        receiver_name = email_match[1]
                    else:
                        # Try account number match (decrypt and compare)
                        cur.execute("SELECT account_id, account_number, user_id FROM accounts WHERE status = 'active'")
                        all_accs = cur.fetchall()
                        for acc_id, enc_num, acc_user_id in all_accs:
                            if enc_num and decrypt_aes256(enc_num) == to_account_input:
                                to_account_id = acc_id
                                # Get receiver name
                                cur.execute("SELECT full_name FROM users WHERE user_id = %s", (acc_user_id,))
                                recv_user = cur.fetchone()
                                receiver_name = recv_user[0] if recv_user else 'Unknown'
                                break

                    if not to_account_id:
                        cur.close()
                        flash("Invalid recipient. Account number or email not found.", "danger")
                        return redirect(url_for('transactions.transfer'))

                    if to_account_id == from_account_id:
                        cur.close()
                        flash("You cannot transfer to your own account.", "danger")
                        return redirect(url_for('transactions.transfer'))

                    # Get sender name
                    sender_name = session.get('full_name', 'Unknown')

                    # Build descriptions
                    sender_desc = description if description else f"Sent ${amount:,.2f} to {receiver_name}"
                    receiver_desc = f"Received ${amount:,.2f} from {sender_name}"

                    # Insert sender's transaction (debit)
                    thash = hash_sha256(f"{from_account_id}-transfer-{amount}-{datetime.now().timestamp()}")
                    cur.execute("""
                        INSERT INTO transactions (account_id, type, amount, status, transaction_hash, description, sender_account_id, receiver_account_id) 
                        VALUES (%s, 'transfer', %s, 'completed', %s, %s, %s, %s)
                    """, (from_account_id, amount, thash, sender_desc, from_account_id, to_account_id))

                    # Insert receiver's transaction (credit)
                    thash_recv = hash_sha256(f"{to_account_id}-transfer_recv-{amount}-{datetime.now().timestamp()}")
                    cur.execute("""
                        INSERT INTO transactions (account_id, type, amount, status, transaction_hash, description, sender_account_id, receiver_account_id)
                        VALUES (%s, 'deposit', %s, 'completed', %s, %s, %s, %s)
                    """, (to_account_id, amount, thash_recv, receiver_desc, from_account_id, to_account_id))

                    # Update balances
                    cur.execute("UPDATE accounts SET balance = balance - %s WHERE account_id = %s", (amount, from_account_id))
                    cur.execute("UPDATE accounts SET balance = balance + %s WHERE account_id = %s", (amount, to_account_id))

                    mysql.connection.commit()
                    cur.close()
                    flash(f"Transfer of ${amount:,.2f} to {receiver_name} completed successfully.", "success")
                    return redirect(url_for('transactions.index'))

                flash("Amount must be greater than zero.", "danger")
            except ValueError:
                flash("Invalid amount.", "danger")

    return render_template('transfer.html', balance=balance, active_page='transfer')

@transactions_bp.route('/deposit', methods=['GET','POST'])
@login_required
def deposit():
    user_id = session['user_id']
    balance = _get_user_balance(user_id)

    if request.method == "POST":
        amount = request.form.get("amount")
        return render_template(
            "deposit_confirm.html",
            amount=amount,
            balance=balance
        )

    return render_template("deposit.html", balance=balance)


@transactions_bp.route('/deposit/confirm', methods=['POST'])
@login_required
def deposit_confirm():
    user_id = session['user_id']
    amount = request.form.get("amount")

    mysql = current_app.mysql
    cur = mysql.connection.cursor()

    cur.execute(
        "SELECT account_id FROM accounts WHERE user_id=%s LIMIT 1",
        (user_id,)
    )
    account = cur.fetchone()

    if account:
        account_id = account[0]
        thash = hash_sha256(f"{account_id}-deposit-{amount}-{datetime.now().timestamp()}")

        cur.execute(
            "INSERT INTO transactions (account_id,type,amount,status,transaction_hash,description) VALUES (%s,'deposit',%s,'completed',%s,%s)",
            (account_id, amount, thash, "Deposit")
        )

        cur.execute(
            "UPDATE accounts SET balance = balance + %s WHERE account_id=%s",
            (amount, account_id)
        )

        mysql.connection.commit()

    cur.close()
    flash("Deposit successful", "success")
    return redirect(url_for("dashboard.index"))

@transactions_bp.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    user_id = session['user_id']
    balance = _get_user_balance(user_id)

    if request.method == "POST":
        amount = request.form.get("amount")
        return render_template(
            "withdraw_confirm.html",
            amount=amount,
            balance=balance
        )

    return render_template("withdraw.html", balance=balance)


@transactions_bp.route('/withdraw/confirm', methods=['POST'])
@login_required
def withdraw_confirm():
    user_id = session['user_id']
    amount = request.form.get("amount")

    if not amount:
        flash("Invalid amount.", "danger")
        return redirect(url_for("transactions.withdraw"))

    mysql = current_app.mysql
    cur = mysql.connection.cursor()

    cur.execute(
        "SELECT account_id, balance FROM accounts WHERE user_id=%s AND status='active' LIMIT 1",
        (user_id,)
    )
    account = cur.fetchone()

    if not account:
        cur.close()
        flash("No active account found.", "danger")
        return redirect(url_for("transactions.withdraw"))

    if float(account[1]) < float(amount):
        cur.close()
        flash("Insufficient balance.", "danger")
        return redirect(url_for("transactions.withdraw"))

    account_id = account[0]
    thash = hash_sha256(f"{account_id}-withdraw-{amount}-{datetime.now().timestamp()}")

    cur.execute(
        "INSERT INTO transactions (account_id,type,amount,status,transaction_hash,description) VALUES (%s,'withdraw',%s,'completed',%s,%s)",
        (account_id, amount, thash, "Withdrawal")
    )

    cur.execute(
        "UPDATE accounts SET balance = balance - %s WHERE account_id=%s",
        (amount, account_id)
    )

    mysql.connection.commit()
    cur.close()

    flash("Withdraw successful", "success")
    return redirect(url_for("dashboard.index"))
