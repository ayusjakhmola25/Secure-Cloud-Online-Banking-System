<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:1B5EA6,100:0F6E56&height=200&section=header&text=Secure%20Cloud%20Banking%20System&fontSize=38&fontColor=ffffff&fontAlignY=38&desc=Production-grade%20online%20banking%20platform%20%E2%80%94%20Flask%20%2B%20AWS&descAlignY=58&descSize=16" width="100%"/>

<br/>

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1.3-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-00758F?style=for-the-badge&logo=mysql&logoColor=white)](https://mysql.com)
[![AWS EC2](https://img.shields.io/badge/AWS_EC2-t3.micro-FF9900?style=for-the-badge&logo=amazon-ec2&logoColor=white)](https://aws.amazon.com/ec2)
[![Amazon RDS](https://img.shields.io/badge/Amazon_RDS-MySQL-527FFF?style=for-the-badge&logo=amazon-rds&logoColor=white)](https://aws.amazon.com/rds)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)

<br/>

> 🏦 **A full-stack, cloud-deployed digital banking platform** with AES-256 encryption, OTP authentication, real-time dashboards, and a powerful admin portal — deployed live on AWS EC2 + RDS.

<br/>

[![Live Demo](https://img.shields.io/badge/🚀_Live_Demo-AWS_EC2-FF9900?style=for-the-badge)](http://13.235.42.166:5000)
[![GitHub Repo](https://img.shields.io/badge/GitHub-Repository-181717?style=for-the-badge&logo=github)](https://github.com/ayusjakhmola25/Secure-Cloud-Online-Banking-System)

</div>

---

## 📋 Table of Contents

<details open>
<summary><b>Click to expand / collapse</b></summary>

- [✨ Features](#-features)
- [🛠 Tech Stack](#-tech-stack)
- [🔐 Security Architecture](#-security-architecture)
- [☁️ AWS Cloud Architecture](#️-aws-cloud-architecture)
- [📁 Project Structure](#-project-structure)
- [🚀 Getting Started](#-getting-started)
- [🗺 API Routes](#-api-routes)
- [🗄 Database Schema](#-database-schema)
- [👥 Team](#-team)

</details>

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 👤 User Features
- 🔐 Secure registration with auto-generated **20-digit encrypted account number**
- 📧 **Dual-layer login** — password + 6-digit OTP via email
- ⏱️ OTP expires in 5 minutes, locks after 3 failed attempts
- 📊 **Live dashboard** — real-time balance, income vs expenses
- 💸 **Deposit, Withdraw, Transfer** with SHA-256 transaction hash
- 🔄 **P2P Transfer** via email or account number
- 📜 Full **transaction history** with audit trail
- 👤 **Profile management** with encrypted PII

</td>
<td width="50%">

### 🛡️ Admin Features
- 🔒 Separate admin portal with **Role-Based Access Control**
- 📈 **Network overview** — total assets, users, transaction volume
- 👥 **User management** — view, suspend, activate, delete
- 🏦 **Account control** — suspend/close individual accounts
- 🔍 **Transaction monitoring** with high-value alerts (≥$10,000)
- 📊 Real-time platform-wide financial statistics
- 🚨 Instant visibility into suspicious activity

</td>
</tr>
</table>

---

## 🛠 Tech Stack

<div align="center">

| Layer | Technology | Purpose |
|:---:|:---:|:---|
| ![Python](https://img.shields.io/badge/-Python-3776AB?logo=python&logoColor=white) | **Python 3.12 + Flask 3.1.3** | Backend framework with Blueprint architecture |
| ![MySQL](https://img.shields.io/badge/-MySQL-00758F?logo=mysql&logoColor=white) | **MySQL 8.0 via Amazon RDS** | Managed relational database |
| ![AWS](https://img.shields.io/badge/-AWS-FF9900?logo=amazon-aws&logoColor=white) | **EC2 t3.micro + RDS db.t4g.micro** | Cloud compute + managed database |
| ![Security](https://img.shields.io/badge/-Security-red?logo=shield&logoColor=white) | **AES-256 GCM + Bcrypt + SHA-256** | Encryption, password hashing, transaction integrity |
| ![Gunicorn](https://img.shields.io/badge/-Gunicorn-499848?logo=gunicorn&logoColor=white) | **Gunicorn (4 workers)** | Production WSGI server |
| ![HTML](https://img.shields.io/badge/-Frontend-E34F26?logo=html5&logoColor=white) | **HTML5 + CSS3 + JS + Jinja2** | Responsive UI templates |
| ![Gmail](https://img.shields.io/badge/-Gmail_SMTP-EA4335?logo=gmail&logoColor=white) | **Flask-Mail + Gmail TLS** | OTP email delivery |
| ![systemd](https://img.shields.io/badge/-systemd-000000?logo=linux&logoColor=white) | **systemd service** | Auto-start on EC2 reboot |

</div>

---

## 🔐 Security Architecture

<details>
<summary><b>🔑 Password Security — Double Hashing</b></summary>

<br/>

```
User Password
     │
     ▼
SHA-256 Hash  →  fixed-length digest (protects against length extension attacks)
     │
     ▼
Bcrypt Hash   →  salted + slow hash (protects against brute force)
     │
     ▼
  Database    →  stored as $2b$12$... (unrecoverable)
```

```python
# auth.py — registration
hashed_pwd = hash_sha256(password)                         # Step 1: SHA-256
hashed    = bcrypt.hashpw(hashed_pwd.encode(), bcrypt.gensalt())  # Step 2: Bcrypt

# auth.py — login verification
hashed_attempt = hash_sha256(password)
bcrypt.checkpw(hashed_attempt.encode(), stored_hash)  # Compare safely
```

</details>

<details>
<summary><b>🔒 AES-256 GCM Encryption</b></summary>

<br/>

All sensitive PII (phone numbers, 20-digit account numbers) is encrypted **before** being stored in the database using AES-256 in GCM (Galois/Counter Mode) — the same standard used by financial institutions worldwide.

```python
# crypto.py
def encrypt_aes256(plaintext: str) -> str:
    key    = _get_key()            # 32-byte key from .env
    aesgcm = AESGCM(key)
    nonce  = os.urandom(12)        # random 12-byte nonce every time
    cipher = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.urlsafe_b64encode(nonce + cipher).decode()

# Result: "9876543210" → "gAAAABx3mK9...base64..."
```

> Even if the database is compromised, phone numbers and account numbers are unreadable without the `ENCRYPTION_KEY`.

</details>

<details>
<summary><b>🧾 SHA-256 Transaction Hashing</b></summary>

<br/>

Every financial transaction gets a **unique cryptographic hash** generated at the time of execution:

```python
# transactions.py — deposit
thash = hash_sha256(f"{account_id}-deposit-{amount}-{datetime.now().timestamp()}")

# transactions.py — transfer (both sender and receiver get separate hashes)
thash      = hash_sha256(f"{from_account_id}-transfer-{amount}-{timestamp}")
thash_recv = hash_sha256(f"{to_account_id}-transfer_recv-{amount}-{timestamp}")
```

This creates a tamper-evident audit trail — any modification to transaction data would invalidate the hash.

</details>

<details>
<summary><b>📧 OTP Email Verification</b></summary>

<br/>

```python
# auth.py
otp = str(random.randint(100000, 999999))   # 6-digit OTP
session['otp_expiry'] = datetime.now() + timedelta(minutes=5)  # 5 min expiry
session['otp_attempts'] = 0                 # attempt counter

# On verification:
if attempts >= 3:
    session.clear()      # lock account after 3 fails
    return redirect(url_for("auth.login"))
```

</details>

<details>
<summary><b>🛡️ CSRF Protection</b></summary>

<br/>

Every form across the entire application is protected with **Flask-WTF CSRF tokens**. Any POST request without a valid token is automatically rejected — prevents cross-site request forgery attacks.

```python
# app/__init__.py
csrf = CSRFProtect()
csrf.init_app(app)    # Applied globally to all routes
```

</details>

---

## ☁️ AWS Cloud Architecture

```
                    ┌──────────────────────────┐
                    │   IAM User: Ayush         │
                    │   Administrator Role      │
                    └────────────┬─────────────┘
                                 │ manages
          ┌──────────────────────▼──────────────────────────┐
          │              AWS Cloud — ap-south-1              │
          │                    (Mumbai)                      │
          │                                                  │
          │   ┌──────────────────────────────────────────┐   │
          │   │         VPC — vpc-0b4df868bb430dcfd      │   │
          │   │                                          │   │
          │   │  ┌───────────────────────────────────┐  │   │
          │   │  │      EC2 — bank-server             │  │   │
          │   │  │      t3.micro │ Ubuntu 24          │  │   │
          │   │  │      Flask + Gunicorn (4 workers)  │  │   │
          │   │  │      Port 5000 │ systemd service   │  │   │
          │   │  └──────────────┬────────────────────┘  │   │
          │   │                 │ MySQL (Private VPC)    │   │
          │   │  ┌──────────────▼────────────────────┐  │   │
          │   │  │      Amazon RDS — bank-database    │  │   │
          │   │  │      MySQL 8.0 │ db.t4g.micro      │  │   │
          │   │  │      DB: securebank                │  │   │
          │   │  │      Snapshot: bank-databasebackup │  │   │
          │   │  └───────────────────────────────────┘  │   │
          │   │                                          │   │
          │   │  Security Groups:                        │   │
          │   │  bank-security-group → Port 22,80,5000  │   │
          │   │  ec2-rds-1 / rds-ec2-1 → Internal VPC  │   │
          │   └──────────────────────────────────────────┘   │
          │                        │                         │
          │                  Gmail SMTP                       │
          │                  (Port 587 TLS)                   │
          └───────────────────────────────────────────────────┘
                                   │
                               HTTP Request
                                   │
                         ┌─────────▼──────────┐
                         │   User's Browser    │
                         │  EC2-Public-IP:5000 │
                         └────────────────────┘
```

**Infrastructure highlights:**
- 🔒 RDS is **not publicly accessible** — only EC2 can connect via private VPC
- 🔄 `systemd` service ensures app **auto-starts on reboot**
- 💾 Manual **RDS snapshot** (`bank-databasebackup`) for disaster recovery
- 🌍 Deployed in **ap-south-1 (Mumbai)** for low latency in India
- 🔑 All secrets in `.env` — never hardcoded in source code

---

## 📁 Project Structure

```
Secure-Cloud-Online-Banking-System/
│
├── 📂 Secure-Cloud-Banking-System/        ← Main application
│   │
│   ├── 📂 app/
│   │   ├── 📄 __init__.py                 ← App factory (Flask setup, blueprints, DB, mail, CSRF)
│   │   │
│   │   ├── 📂 routes/
│   │   │   ├── 📄 auth.py                 ← Login, register, OTP verify, logout
│   │   │   ├── 📄 dashboard.py            ← Dashboard, accounts, profile management
│   │   │   ├── 📄 transactions.py         ← Deposit, withdraw, transfer, history
│   │   │   └── 📄 admin.py                ← Admin portal — users, accounts, monitoring
│   │   │
│   │   ├── 📂 templates/
│   │   │   ├── 📂 layouts/                ← Base templates (app_base, auth_base)
│   │   │   ├── 📂 admin/                  ← Admin templates (dashboard, users, accounts)
│   │   │   ├── login.html / register.html / otp.html
│   │   │   ├── dashboard.html / accounts.html / profile.html
│   │   │   ├── deposit.html / withdraw.html / transfer.html
│   │   │   └── transactions.html / history.html
│   │   │
│   │   ├── 📂 static/
│   │   │   ├── css/app.css
│   │   │   └── js/app.js
│   │   │
│   │   └── 📂 utils/
│   │       └── 📄 crypto.py               ← AES-256 encrypt/decrypt + SHA-256 hash
│   │
│   ├── 📄 .env                            ← 🔴 Secrets — NEVER commit to Git
│   ├── 📄 db_update.py                    ← Schema migration script
│   └── 📄 run.py                          ← Entry point (Gunicorn target)
│
├── 📄 setup_database.py                   ← Initial DB + table creation
├── 📄 verify_crypto.py                    ← Encryption test script
├── 📄 requirements.txt                    ← Python dependencies
└── 📄 README.md
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- MySQL 8.0 running locally
- Gmail account with [App Password](https://myaccount.google.com/apppasswords) enabled

### Step 1 — Clone the repository

```bash
git clone https://github.com/ayusjakhmola25/Secure-Cloud-Online-Banking-System.git
cd Secure-Cloud-Online-Banking-System
```

### Step 2 — Create virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
```

### Step 3 — Configure environment

Create `.env` inside `Secure-Cloud-Banking-System/`:

```env
# Flask
SECRET_KEY=your-strong-random-secret-key-here

# Encryption (AES-256)
ENCRYPTION_KEY=your-32-byte-base64-key-here

# Database
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=your-mysql-password
MYSQL_DB=securebank

# Email (OTP)
MAIL_USERNAME=your-gmail@gmail.com
MAIL_PASSWORD=your-gmail-app-password
```

> **Generate ENCRYPTION_KEY:**
> ```bash
> python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
> ```

### Step 4 — Initialize database

```bash
python setup_database.py
```

### Step 5 — Run locally

```bash
cd Secure-Cloud-Banking-System
python run.py
```

Open `http://127.0.0.1:5000` 🎉

### Step 6 — Production (AWS EC2)

```bash
pip install gunicorn

# Run with 4 workers
gunicorn -w 4 -b 0.0.0.0:5000 run:app

# OR as background service (recommended)
sudo systemctl start bankapp
sudo systemctl enable bankapp  # auto-start on reboot
```

---

## 🗺 API Routes

<details>
<summary><b>Authentication Routes</b></summary>

| Method | Route | Description |
|:---:|:---|:---|
| `GET/POST` | `/auth/login` | User login — validates credentials, triggers OTP |
| `GET/POST` | `/auth/register` | New user signup — creates user + encrypted account |
| `GET/POST` | `/auth/verify-otp` | OTP verification — 5 min expiry, 3 attempt lockout |
| `GET` | `/auth/logout` | Clear session and redirect to login |

</details>

<details>
<summary><b>Dashboard Routes</b></summary>

| Method | Route | Description |
|:---:|:---|:---|
| `GET` | `/dashboard` | Main dashboard — balance, stats, recent transactions |
| `GET` | `/accounts` | Account details — masked account number, balance |
| `GET/POST` | `/profile` | View & update profile — name, phone (AES encrypted) |

</details>

<details>
<summary><b>Transaction Routes</b></summary>

| Method | Route | Description |
|:---:|:---|:---|
| `GET/POST` | `/deposit` | Initiate deposit |
| `POST` | `/deposit/confirm` | Confirm & execute deposit, generate SHA-256 hash |
| `GET/POST` | `/withdraw` | Initiate withdrawal |
| `POST` | `/withdraw/confirm` | Confirm & execute withdrawal with balance check |
| `GET/POST` | `/transfer` | P2P transfer via email or account number |
| `GET` | `/transactions` | View recent transaction list |
| `GET` | `/history` | Full transaction history |

</details>

<details>
<summary><b>Admin Routes</b></summary>

| Method | Route | Description |
|:---:|:---|:---|
| `GET/POST` | `/admin/login` | Admin login (role=admin required) |
| `GET` | `/admin/dashboard` | Platform overview — users, assets, high-value txns |
| `GET` | `/admin/users` | All registered users |
| `POST` | `/admin/users/<id>/delete` | Delete user and all associated data |
| `GET/POST` | `/admin/accounts` | All accounts — suspend/activate/close |
| `GET` | `/admin/transactions` | All transactions with search & filter |
| `GET` | `/admin/logout` | Admin logout |

</details>

---

## 🗄 Database Schema

<details>
<summary><b>View Schema</b></summary>

```sql
-- Users Table
CREATE TABLE users (
    user_id       INT AUTO_INCREMENT PRIMARY KEY,
    full_name     VARCHAR(100),
    email         VARCHAR(100) UNIQUE,
    phone         VARCHAR(255),          -- AES-256 encrypted
    password_hash VARCHAR(255),          -- SHA-256 + Bcrypt
    role          ENUM('user','admin') DEFAULT 'user',
    last_login    DATETIME,
    status        VARCHAR(20) DEFAULT 'active',
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Accounts Table
CREATE TABLE accounts (
    account_id     INT AUTO_INCREMENT PRIMARY KEY,
    user_id        INT NOT NULL,
    account_number VARCHAR(255),          -- AES-256 encrypted (20-digit)
    balance        DECIMAL(15,2) DEFAULT 0.00,
    status         VARCHAR(20) DEFAULT 'active',
    account_type   VARCHAR(20) DEFAULT 'Savings',
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Transactions Table
CREATE TABLE transactions (
    transaction_id     INT AUTO_INCREMENT PRIMARY KEY,
    account_id         INT NOT NULL,
    type               VARCHAR(20),       -- deposit / withdraw / transfer
    amount             DECIMAL(15,2),
    description        VARCHAR(255),
    transaction_hash   VARCHAR(255),      -- SHA-256 tamper-proof hash
    sender_account_id  INT,
    receiver_account_id INT,
    balance_after      DECIMAL(15,2),
    status             VARCHAR(20) DEFAULT 'completed',
    created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(account_id)
);
```

> 🔐 Fields marked with "AES-256 encrypted" are stored as Base64 ciphertext in the database.

</details>

---

## 👥 Team

<div align="center">

**Cloud Team — Graphic Era Hill University (GEHU) | 2026**

<table>
<tr>
<td align="center" width="33%">
<br/>
<b>Ayush Kumar Jakhmola</b>
<br/>
<sub>🚀 Team Lead</sub>
<br/><br/>
<sub>Backend architecture, Security module, AWS EC2 + RDS deployment, Gunicorn + systemd setup, App factory pattern</sub>
<br/><br/>
<sub>📧 jakhmolaayush51@gmail.com</sub>
<br/>
<sub>🆔 241741017</sub>
</td>
<td align="center" width="33%">
<br/>
<b>Niharika Pandey</b>
<br/>
<sub>⚙️ Backend Developer</sub>
<br/><br/>
<sub>OTP email system, Dashboard module, Admin portal, Environment configuration</sub>
<br/><br/>
<sub>📧 niharikapandey114@gmail.com</sub>
<br/>
<sub>🆔 241742014</sub>
</td>
<td align="center" width="33%">
<br/>
<b>Kanishka Thakur</b>
<br/>
<sub>🎨 Frontend + Transactions</sub>
<br/><br/>
<sub>Transaction module, Withdrawal module, Frontend UI templates, Testing & validation</sub>
<br/><br/>
<sub>📧 kanishkathakur0404@gmail.com</sub>
<br/>
<sub>🆔 240421247</sub>
</td>
</tr>
</table>

</div>

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0F6E56,100:1B5EA6&height=100&section=footer" width="100%"/>

**⭐ Star this repo if you found it useful!**

[![GitHub stars](https://img.shields.io/github/stars/ayusjakhmola25/Secure-Cloud-Online-Banking-System?style=social)](https://github.com/ayusjakhmola25/Secure-Cloud-Online-Banking-System)

*Built with ❤️ by Cloud Team | GEHU | 2026*

</div>
