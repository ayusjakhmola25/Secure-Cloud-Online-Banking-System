import os
import bcrypt
from app import create_app, mysql
from app.utils.crypto import hash_sha256

app = create_app()

with app.app_context():
    cur = mysql.connection.cursor()

    # --- Schema Migrations ---

    # 1. Add role column to users
    try:
        cur.execute("SHOW COLUMNS FROM users LIKE 'role'")
        if not cur.fetchone():
            cur.execute("ALTER TABLE users ADD COLUMN role ENUM('user', 'admin') DEFAULT 'user'")
            mysql.connection.commit()
            print("Added role column to users table.")
        else:
            print("Role column already exists.")
    except Exception as e:
        print(f"Error checking/adding role column: {e}")

    # 2. Add last_login column to users
    try:
        cur.execute("SHOW COLUMNS FROM users LIKE 'last_login'")
        if not cur.fetchone():
            cur.execute("ALTER TABLE users ADD COLUMN last_login DATETIME DEFAULT NULL")
            mysql.connection.commit()
            print("Added last_login column to users table.")
        else:
            print("last_login column already exists.")
    except Exception as e:
        print(f"Error checking/adding last_login column: {e}")

    # 3. Add status column to accounts
    try:
        cur.execute("SHOW COLUMNS FROM accounts LIKE 'status'")
        if not cur.fetchone():
            cur.execute("ALTER TABLE accounts ADD COLUMN status VARCHAR(20) DEFAULT 'active'")
            mysql.connection.commit()
            print("Added status column to accounts table.")
        else:
            print("Status column already exists.")
    except Exception as e:
        print(f"Error checking/adding status column: {e}")

    # 4. Add description column to transactions
    try:
        cur.execute("SHOW COLUMNS FROM transactions LIKE 'description'")
        if not cur.fetchone():
            cur.execute("ALTER TABLE transactions ADD COLUMN description VARCHAR(255) DEFAULT NULL")
            mysql.connection.commit()
            print("Added description column to transactions table.")
        else:
            print("description column already exists.")
    except Exception as e:
        print(f"Error checking/adding description column: {e}")

    # 5. Add sender_account_id column to transactions
    try:
        cur.execute("SHOW COLUMNS FROM transactions LIKE 'sender_account_id'")
        if not cur.fetchone():
            cur.execute("ALTER TABLE transactions ADD COLUMN sender_account_id INT DEFAULT NULL")
            mysql.connection.commit()
            print("Added sender_account_id column to transactions table.")
        else:
            print("sender_account_id column already exists.")
    except Exception as e:
        print(f"Error checking/adding sender_account_id column: {e}")

    # 6. Add receiver_account_id column to transactions
    try:
        cur.execute("SHOW COLUMNS FROM transactions LIKE 'receiver_account_id'")
        if not cur.fetchone():
            cur.execute("ALTER TABLE transactions ADD COLUMN receiver_account_id INT DEFAULT NULL")
            mysql.connection.commit()
            print("Added receiver_account_id column to transactions table.")
        else:
            print("receiver_account_id column already exists.")
    except Exception as e:
        print(f"Error checking/adding receiver_account_id column: {e}")

    # --- Admin User Setup ---

    cur.execute("SELECT user_id FROM users WHERE email = %s", ('vipinjakhmola024@gmail.com',))
    admin_user = cur.fetchone()

    password = 'vipin123'
    hashed_pwd = hash_sha256(password)
    hashed = bcrypt.hashpw(hashed_pwd.encode("utf-8"), bcrypt.gensalt())

    if not admin_user:
        try:
            cur.execute(
                "INSERT INTO users (full_name, email, phone, password_hash, role) VALUES (%s, %s, %s, %s, %s)",
                ('Graphic Bank Admin', 'vipinjakhmola024@gmail.com', '', hashed, 'admin')
            )
            mysql.connection.commit()
            print("Admin user created.")
        except Exception as e:
            print(f"Failed to create admin user: {e}")
    else:
        try:
            cur.execute(
                "UPDATE users SET role = 'admin', password_hash = %s WHERE email = %s",
                (hashed, 'vipinjakhmola024@gmail.com')
            )
            mysql.connection.commit()
            print("Admin user role/password updated.")
        except Exception as e:
            print(f"Failed to update admin user: {e}")

    cur.close()
    print("\n--- All migrations complete ---")
