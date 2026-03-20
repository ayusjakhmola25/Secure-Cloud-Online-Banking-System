from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from functools import wraps
import bcrypt
from app.utils.crypto import hash_sha256, decrypt_aes256

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id') or session.get('role') != 'admin':
            flash("You do not have permission to access the admin panel.", "danger")
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not email or not password:
            flash("Email and password are required.", "danger")
            return redirect(url_for("admin.login"))
            
        mysql = current_app.mysql
        cur = mysql.connection.cursor()
        cur.execute("SELECT user_id, full_name, password_hash, role FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        
        if not user or user[3] != 'admin':
            flash("Invalid admin credentials or insufficient permissions.", "danger")
            return redirect(url_for('admin.login'))
            
        stored_hash = user[2]
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode("utf-8")
            
        hashed_attempt = hash_sha256(password)
        if bcrypt.checkpw(hashed_attempt.encode("utf-8"), stored_hash):
            session['user_id'] = user[0]
            session['full_name'] = user[1]
            session['email'] = email
            session['role'] = 'admin'
            return redirect(url_for('admin.dashboard'))
            
        flash("Invalid admin credentials.", "danger")
        return redirect(url_for("admin.login"))
        
    return render_template('admin/admin_login.html')

@admin_bp.route('/logout')
def logout():
    session.clear()
    flash("Admin logged out successfully.", "info")
    return redirect(url_for('auth.login'))

@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    mysql = current_app.mysql
    cur = mysql.connection.cursor()
    
    cur.execute("SELECT COUNT(*) FROM users WHERE role != 'admin'")
    total_users = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM accounts WHERE status = 'active'")
    active_accounts = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM accounts WHERE status = 'suspended'")
    suspended_accounts = cur.fetchone()[0]
    
    cur.execute("SELECT SUM(balance) FROM accounts")
    res = cur.fetchone()[0]
    total_balance = float(res) if res else 0.0
    
    cur.execute("SELECT COUNT(*) FROM transactions")
    total_transactions = cur.fetchone()[0]
    
    cur.execute("SELECT SUM(amount) FROM transactions WHERE type = 'deposit' AND status = 'completed'")
    res = cur.fetchone()[0]
    total_deposits = float(res) if res else 0.0
    
    cur.execute("""
        SELECT t.transaction_id, t.type, t.amount, t.status, t.created_at, u.email 
        FROM transactions t
        JOIN accounts a ON t.account_id = a.account_id
        JOIN users u ON a.user_id = u.user_id
        WHERE t.amount >= 10000
        ORDER BY t.created_at DESC
        LIMIT 10
    """)
    high_value = []
    for r in cur.fetchall():
        high_value.append({
            'id': r[0],
            'type': r[1],
            'amount': f"{float(r[2]):,.2f}",
            'status': r[3],
            'date': r[4].strftime('%b %d, %Y %H:%M') if r[4] else '—',
            'email': r[5]
        })
        
    cur.close()
    
    return render_template('admin/admin_dashboard.html',
                           total_users=total_users,
                           active_accounts=active_accounts,
                           suspended_accounts=suspended_accounts,
                           total_balance=total_balance,
                           total_transactions=total_transactions,
                           total_deposits=total_deposits,
                           high_value=high_value,
                           active_page='dashboard')

@admin_bp.route('/users')
@admin_required
def users():
    mysql = current_app.mysql
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, full_name, email, role, created_at FROM users ORDER BY created_at DESC")
    all_users = []
    for r in cur.fetchall():
        all_users.append({
            'id': r[0],
            'name': r[1],
            'email': r[2],
            'role': r[3],
            'joined': r[4].strftime('%m/%d/%Y') if r[4] else '—'
        })
    cur.close()
    return render_template('admin/user_management.html', users=all_users, active_page='users')

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    mysql = current_app.mysql
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM transactions WHERE account_id IN (SELECT account_id FROM accounts WHERE user_id = %s)", (user_id,))
    cur.execute("DELETE FROM accounts WHERE user_id = %s", (user_id,))
    cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    flash("User deleted successfully.", "success")
    return redirect(url_for('admin.users'))

@admin_bp.route('/accounts')
@admin_required
def accounts():
    mysql = current_app.mysql
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT a.account_id, a.account_number, a.balance, a.status, u.full_name, u.email
        FROM accounts a
        JOIN users u ON a.user_id = u.user_id
        ORDER BY a.created_at DESC
    """)
    all_accounts = []
    for r in cur.fetchall():
        if r[1]:
            decrypted = decrypt_aes256(r[1])
            masked = "XXXX" + decrypted[-3:] if len(decrypted) >= 3 else decrypted
        else:
            masked = '-'
        all_accounts.append({
            'id': r[0],
            'account_number': masked,
            'balance': f"{float(r[2]):,.2f}",
            'status': r[3],
            'holder': r[4],
            'email': r[5]
        })
    cur.close()
    return render_template('admin/account_management.html', accounts=all_accounts, active_page='accounts')

@admin_bp.route('/accounts/<int:account_id>/suspend', methods=['POST'])
@admin_required
def suspend_account(account_id):
    mysql = current_app.mysql
    cur = mysql.connection.cursor()
    cur.execute("UPDATE accounts SET status = 'suspended' WHERE account_id = %s", (account_id,))
    mysql.connection.commit()
    cur.close()
    flash("Account suspended successfully.", "success")
    return redirect(url_for('admin.accounts'))

@admin_bp.route('/accounts/<int:account_id>/activate', methods=['POST'])
@admin_required
def activate_account(account_id):
    mysql = current_app.mysql
    cur = mysql.connection.cursor()
    cur.execute("UPDATE accounts SET status = 'active' WHERE account_id = %s", (account_id,))
    mysql.connection.commit()
    cur.close()
    flash("Account activated successfully.", "success")
    return redirect(url_for('admin.accounts'))

@admin_bp.route('/accounts/<int:account_id>/close', methods=['POST'])
@admin_required
def close_account(account_id):
    mysql = current_app.mysql
    cur = mysql.connection.cursor()
    cur.execute("UPDATE accounts SET status = 'closed' WHERE account_id = %s", (account_id,))
    mysql.connection.commit()
    cur.close()
    flash("Account closed successfully.", "success")
    return redirect(url_for('admin.accounts'))

@admin_bp.route('/transactions')
@admin_required
def transactions():
    mysql = current_app.mysql
    cur = mysql.connection.cursor()
    
    search = request.args.get('search', '')
    type_filter = request.args.get('type', 'All Types')
    status_filter = request.args.get('status', 'All Status')
    
    query = """
        SELECT t.transaction_id, t.type, t.amount, t.status, t.created_at, 
               u.email, u.full_name, t.description,
               t.sender_account_id, t.receiver_account_id
        FROM transactions t
        JOIN accounts a ON t.account_id = a.account_id
        JOIN users u ON a.user_id = u.user_id
        WHERE 1=1
    """
    params = []
    
    if search:
        query += " AND (t.transaction_id LIKE %s OR u.email LIKE %s OR u.full_name LIKE %s)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    if type_filter != 'All Types':
        query += " AND t.type = %s"
        params.append(type_filter.lower())
    if status_filter != 'All Status':
        query += " AND t.status = %s"
        params.append(status_filter.lower())
        
    query += " ORDER BY t.created_at DESC"
    
    cur.execute(query, tuple(params))
    rows = cur.fetchall()

    # Build a map of account_id -> user info for sender/receiver lookup
    account_user_map = {}
    cur.execute("""
        SELECT a.account_id, u.full_name, u.email 
        FROM accounts a JOIN users u ON a.user_id = u.user_id
    """)
    for arow in cur.fetchall():
        account_user_map[arow[0]] = {'name': arow[1], 'email': arow[2]}

    all_txns = []
    for r in rows:
        sender_info = None
        receiver_info = None
        if r[8]:  # sender_account_id
            sender_info = account_user_map.get(r[8])
        if r[9]:  # receiver_account_id
            receiver_info = account_user_map.get(r[9])

        all_txns.append({
            'id': r[0],
            'type': r[1],
            'amount': f"{float(r[2]):,.2f}",
            'status': r[3],
            'date': r[4].strftime('%b %d, %Y %H:%M') if r[4] else '—',
            'email': r[5],
            'name': r[6],
            'description': r[7] or '',
            'sender_name': sender_info['name'] if sender_info else '—',
            'sender_email': sender_info['email'] if sender_info else '—',
            'receiver_name': receiver_info['name'] if receiver_info else '—',
            'receiver_email': receiver_info['email'] if receiver_info else '—',
        })
    cur.close()
    
    return render_template('admin/transaction_monitoring.html', 
                           transactions=all_txns, active_page='transactions', 
                           search=search, type_filter=type_filter, status_filter=status_filter)
