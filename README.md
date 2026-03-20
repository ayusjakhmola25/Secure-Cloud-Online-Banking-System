# Secure Cloud Banking System 🏦 ☁️

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1.3-green.svg)](https://flask.palletsprojects.com/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0%2B-orange.svg)](https://www.mysql.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Made with Flask-WTF](https://img.shields.io/badge/Flask--WTF-1.2.1-blueviolet.svg)](https://flask-wtf.readthedocs.io/)

## 📖 Overview

**Secure Cloud Banking System** is a full-stack web application built with Python Flask, providing a secure, user-friendly platform for personal banking operations. Users can register, log in, manage accounts, perform transactions (deposit, withdraw, transfer), view balances, transaction history, and profiles. 

Designed with security in mind (bcrypt password hashing, CSRF protection, session management), it simulates a real-world banking dashboard with MySQL backend.

**Live Demo**: Run locally on `http://127.0.0.1:5000`

## 🚀 Features

- **🔐 Secure Authentication**: User registration/login/logout with bcrypt-hashed passwords, CSRF protection.
- **👤 Auto Account Creation**: 20-digit account numbers generated on signup/first login.
- **💰 Transaction Management**:
  - Deposits & Withdrawals (with confirmation flow).
  - Transfers to other accounts (initiated as pending).
- **📊 Dashboard**: Real-time balance, recent 5 transactions.
- **📈 History & Profile**: Full transaction logs, user/account details.
- **📱 Responsive UI**: Modern templates with CSS/JS, base layouts.
- **🛡️ Security**: Session-based auth, input validation, SQL injection prevention.

## 📱 Screenshots

Add screenshots here:
- ![Login](screenshots/login.png)
- ![Dashboard](screenshots/dashboard.png)
- ![Transactions](screenshots/transactions.png)

*(Capture via browser after running the app)*

## 🛠️ Prerequisites

- Python 3.10+
- MySQL 8.0+ Server
- pip, virtualenv (recommended)
- Git (for cloning)

## 🔧 Quick Start

### 1. Clone & Setup
```bash
cd a:/MAIN/PBL/Secure Banking System
git clone <repo> .  # Or download
```

### 2. Virtual Environment
```bash
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

### 3. Database Setup
```bash
# Start MySQL (localhost/root/ayush123 - update in setup_database.py)
python setup_database.py
```
*Creates `securebank` DB with tables: `users`, `accounts`, `transactions`, `admins`. Includes sample admin: admin@example.com / admin123 (Balance: $1000).*

### 4. Configuration
Create `.env` (optional, falls back to code defaults):
```
SECRET_KEY=your-stable-secret-key-here  # Critical: Stable across restarts!
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=ayush123
MYSQL_DB=securebank
```

### 5. Run the App
```bash
python run.py
```
- Opens: http://127.0.0.1:5000 → Redirects to `/auth/login`
- Register or use sample: `admin@example.com` / `admin123`

## ⚙️ Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `SECRET_KEY` | Random (urandom) | **Must be stable** for sessions/CSRF. Set env var. |
| `MYSQL_*` | localhost/root/ayush123/securebank | DB connection. Update `app/__init__.py`. |

**Note**: Random SECRET_KEY breaks login/sessions on restart. Fix: Use `.env` with fixed key.

## 📊 Database Schema

```sql
-- users
user_id (PK), full_name, email (UNIQUE), phone, password_hash, created_at, status

-- accounts (1:1 with users)
account_id (PK), user_id (FK), account_number (UNIQUE 20-digit), balance, currency='USD', account_type='Savings'

-- transactions
transaction_id (PK), account_id (FK), type ('deposit'/'withdraw'/'transfer'), amount, description, recipient_account, balance_after, created_at, status ('completed'/'pending')

-- admins (for future admin panel)
admin_id (PK), full_name, email, password_hash
```

## 🌐 Key Endpoints

| Route | Method | Description | Auth |
|-------|--------|-------------|------|
| `/auth/login` | GET/POST | Login | No |
| `/auth/register` | GET/POST | Register | No |
| `/dashboard` | GET | Dashboard | Yes |
| `/transactions` | GET | Txns list | Yes |
| `/transfer` | POST | Initiate transfer | Yes |
| `/profile` | GET | Profile | Yes |

**Blueprints**: `/auth`, `/dashboard`, `/transactions`.

## 🔒 Security Notes

- ✅ Bcrypt hashing.
- ✅ CSRF via Flask-WTF.
- ✅ Prepared SQL statements.
- ⚠️ Update DB creds in prod (hardcoded in code/setup).
- ⚠️ Transfer: Add recipient validation/balance check.
- Next: Rate limiting, 2FA, HTTPS.


## 🤝 Contributing

1. Fork & clone.
2. Create venv, install deps.
3. Setup DB.
4. Branch: `git checkout -b feature/xyz`
5. PR to `main`.

Issues/PRs welcome!

## 📄 License

MIT License - see [LICENSE](LICENSE) (create if needed).

## 🙏 Acknowledgments

Built with Flask ecosystem. Icons from FontAwesome.

---

*⭐ Star if useful! Questions? Open an issue.*

