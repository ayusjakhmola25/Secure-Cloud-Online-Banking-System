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

@transactions_bp.route('/transactions')
@login_required
def index():

    user_id = session['user_id']
    mysql = current_app.mysql
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            SELECT t.transaction_id, t.type, t.amount, t.status, t.created_at, a.account_number
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
                'account': decrypt_aes256(r[5]) if r[5] else '—'
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

    # get user account
    cur.execute(
        "SELECT account_id FROM accounts WHERE user_id=%s LIMIT 1",
        (user_id,)
    )

    account = cur.fetchone()

    if not account:
        return render_template("history.html", transactions=[])

    account_id = account[0]

    # get transactions
    cur.execute("""
        SELECT transaction_id,type,amount,description,created_at,status
        FROM transactions
        WHERE account_id = %s
        ORDER BY created_at DESC
    """,(account_id,))

    rows = cur.fetchall()

    transactions = []

    for r in rows:
        transactions.append({
            "id": r[0],
            "type": r[1],
            "amount": f"${float(r[2]):,.2f}",
            "description": r[3] if r[3] else r[1],
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
    if request.method == 'POST':
        to_account = request.form.get('to_account')
        amount = request.form.get('amount')
        if to_account and amount:
            try:
                amount = float(amount)
                if amount > 0:
                    mysql = current_app.mysql
                    cur = mysql.connection.cursor()
                    # From user's account
                    cur.execute("SELECT account_id, balance FROM accounts WHERE user_id = %s AND status = 'active' LIMIT 1", (user_id,))
                    from_account = cur.fetchone()
                    if from_account and float(from_account[1]) >= amount:
                        from_account_id = from_account[0]
                        
                        # Verify to_account exists
                        cur.execute("SELECT account_id, account_number FROM accounts WHERE status = 'active'")
                        all_accs = cur.fetchall()
                        to_account_id = None
                        ence_to = None
                        
                        for acc_id, enc_num in all_accs:
                            if enc_num and decrypt_aes256(enc_num) == to_account:
                                to_account_id = acc_id
                                ence_to = enc_num
                                break
                                
                        if not to_account_id:
                            cur.close()
                            flash("Invalid recipient account number. Please verify and try again.", "danger")
                            return redirect(url_for('transactions.transfer'))

                        thash = hash_sha256(f"{from_account_id}-transfer-{amount}-{datetime.now().timestamp()}")
                        cur.execute("""
                            INSERT INTO transactions (account_id, type, amount, status, to_account, transaction_hash) 
                            VALUES (%s, 'transfer', %s, 'completed', %s, %s)
                        """, (from_account_id, amount, ence_to, thash))
                        
                        # Add a corresponding deposit for the recipient
                        thash_recv = hash_sha256(f"{to_account_id}-transfer_recv-{amount}-{datetime.now().timestamp()}")
                        from_enc = encrypt_aes256("Transfer from " + str(user_id))
                        cur.execute("""
                            INSERT INTO transactions (account_id, type, amount, status, to_account, transaction_hash)
                            VALUES (%s, 'deposit', %s, 'completed', %s, %s)
                        """, (to_account_id, amount, from_enc, thash_recv))
                        
                        # Update balances
                        cur.execute("UPDATE accounts SET balance = balance - %s WHERE account_id = %s", (amount, from_account_id))
                        cur.execute("UPDATE accounts SET balance = balance + %s WHERE account_id = %s", (amount, to_account_id))
                        
                        mysql.connection.commit()
                        cur.close()
                        flash(f"Transfer of ${amount:,.2f} to {to_account} completed successfully.", "success")
                        return redirect(url_for('transactions.index'))

                    cur.close()
                flash("Invalid amount or insufficient balance.", "danger")
            except ValueError:
                flash("Invalid amount.", "danger")
    return render_template('transfer.html', active_page='transfer')

@transactions_bp.route('/deposit', methods=['GET','POST'])
@login_required
def deposit():

    if request.method == "POST":

        amount = request.form.get("amount")

        return render_template(
            "deposit_confirm.html",
            amount=amount
        )

    return render_template("deposit.html")


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
            "INSERT INTO transactions (account_id,type,amount,status,transaction_hash) VALUES (%s,'deposit',%s,'completed',%s)",
            (account_id, amount, thash)
        )

        cur.execute(
            "UPDATE accounts SET balance = balance + %s WHERE account_id=%s",
            (amount, account_id)
        )

        mysql.connection.commit()

    cur.close()

    flash("Deposit successful","success")

    return redirect(url_for("dashboard.index"))

@transactions_bp.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():

    if request.method == "POST":

        amount = request.form.get("amount")

        return render_template(
            "withdraw_confirm.html",
            amount=amount
        )

    return render_template("withdraw.html")


@transactions_bp.route('/withdraw/confirm', methods=['POST'])
@login_required
def withdraw_confirm():

    user_id = session['user_id']
    amount = request.form.get("amount")

    mysql = current_app.mysql
    cur = mysql.connection.cursor()

    cur.execute(
        "SELECT account_id,balance FROM accounts WHERE user_id=%s LIMIT 1",
        (user_id,)
    )

    account = cur.fetchone()

    if account and float(account[1]) >= float(amount):

        account_id = account[0]
        thash = hash_sha256(f"{account_id}-withdraw-{amount}-{datetime.now().timestamp()}")

        cur.execute(
            "INSERT INTO transactions (account_id,type,amount,status,transaction_hash) VALUES (%s,'withdraw',%s,'completed',%s)",
            (account_id, amount, thash)
        )

        cur.execute(
            "UPDATE accounts SET balance = balance - %s WHERE account_id=%s",
            (amount, account_id)
        )

        mysql.connection.commit()

    cur.close()

    flash("Withdraw successful","success")

    return redirect(url_for("dashboard.index"))
