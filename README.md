# Secure Cloud Online Banking System

<p align="center">
  <img src="images/dashboard.jpeg" alt="Secure Cloud Banking Dashboard" width="900" />
</p>

## Overview

The Secure Cloud Online Banking System is a Flask-based web application that demonstrates common digital banking workflows in a database-backed environment.

Customers can register, sign in using password and email OTP verification, review account information, and perform operations such as deposits, withdrawals, and account-to-account transfers. An administrative area provides views for user management, account status management, and transaction monitoring.

Built with Python, Flask, MySQL, Jinja2 templates, HTML, CSS, and JavaScript, the project brings together application routing, relational data storage, authentication flows, and selected security controls in one learning-oriented application.

**Project status:** This is an educational demonstration, not production-ready banking software. It must not be used with real financial accounts or sensitive customer data without professional security review, transaction-safety improvements, and deployment hardening.

---

## Problem Statement

Online banking applications handle sensitive personal information and financial records. A banking system must control access, protect stored data, maintain reliable transaction records, and give authorized administrators appropriate oversight.

Without carefully designed controls:

- Unauthorized users may access account information.
- Weak transaction validation can lead to incorrect balances.
- Poor session and authentication handling can expose accounts.
- Inconsistent database operations can create unreliable transaction records.
- Administrators may lack a clear view of users, accounts, and transaction activity.

This project explores these challenges through a web application that combines customer authentication, email OTP verification, account workflows, MySQL persistence, security utilities, and administrative views.

---

## Real-World Applications

### Digital Banking Concepts

- Customer registration and account access
- Account balance and transaction-history views
- Deposit, withdrawal, and transfer workflow demonstrations

### Financial Application Development

- Modeling users, accounts, and transactions in a relational database
- Organizing business logic through Flask route blueprints
- Separating customer workflows from administrative workflows

### Application Security Learning

- Password hashing and login verification
- Email OTP-based verification flows
- CSRF protection and session-based access checks
- Encryption concepts for selected sensitive fields

### Academic and Development Labs

- Flask and MySQL integration practice
- Secure coding and authorization review
- Testing database-backed workflows
- Understanding security limitations in prototype applications

These are learning and demonstration use cases; the current project is not a certified financial platform.

---

## Key Features

### Customer Authentication

- User registration and account creation
- Login with email and password
- Email-based one-time password (OTP) verification with a five-minute validity period
- Session-based login and logout
- Profile and account information pages

### Banking Operations

- Customer dashboard with account summary
- Deposit and withdrawal workflows
- Transfers to another account using recipient details
- Transaction list and history
- Transaction descriptions, timestamps, and status records
- SHA-256 transaction digest generation in transaction workflows

### Administrative Dashboard

- Separate administrator login flow with role checks
- Overview of users, accounts, balances, deposits, and transactions
- User listing and user deletion
- Account status management, including suspend, activate, and close actions
- Transaction monitoring with search and type/status filters
- Visibility of high-value transactions for review

### Security Components

- Bcrypt password hashing, with SHA-256 preprocessing in the current authentication implementation
- AES-GCM encryption/decryption utilities for selected sensitive values
- Flask-WTF CSRF protection
- Parameterized SQL queries in application database operations
- Session-based access checks for customer and administrator pages

**Security clarification:** These components do not establish that the application is secure or production-ready. A SHA-256 digest stored with a transaction is not, by itself, a tamper-proof audit system.

---

## Impact and Benefits

The project provides a practical environment for learning how common banking features fit together. The table below describes the intended learning and application value; it does not claim measured performance improvements.

| Area | Project Value |
|---|---|
| Authentication | Demonstrates password login and email OTP verification |
| Account workflows | Models deposits, withdrawals, and transfers |
| Data management | Stores users, accounts, and transaction records in MySQL |
| Application structure | Uses Flask application setup and route blueprints |
| Security concepts | Demonstrates password hashing, encryption utilities, and CSRF protection |
| Administration | Provides views for user, account, and transaction oversight |
| Security awareness | Documents limitations and areas requiring hardening |

---

## System Architecture

<p align="center">
  <img src="images/system-architecture.svg" alt="Secure Cloud Online Banking System Architecture" width="1100" />
</p>

### Architecture Components

- **Presentation layer:** Browser interface rendered with HTML, CSS, JavaScript, and Jinja2 templates.
- **Application entry point:** `run.py` starts the Flask application; `create_app()` configures it and registers route blueprints.
- **Authentication module:** `app/routes/auth.py` handles registration, login, OTP verification, and logout.
- **Customer dashboard module:** `app/routes/dashboard.py` provides dashboard, account, and profile pages.
- **Transaction module:** `app/routes/transactions.py` handles deposit, withdrawal, transfer, and history workflows.
- **Administration module:** `app/routes/admin.py` provides administrator views for users, accounts, and transactions.
- **Data layer:** MySQL stores user, account, and transaction records.
- **Security utilities:** `app/utils/crypto.py` provides AES-GCM encryption/decryption and a SHA-256 helper. Bcrypt and Flask-WTF are used elsewhere in the application.
- **Email service:** Flask-Mail sends login OTPs through the configured SMTP provider.

### How the System Works

1. A customer or administrator opens the web application in a browser.
2. Flask routes the request to the appropriate authentication, dashboard, transaction, or admin blueprint.
3. During customer login, the application checks the credentials and uses an email OTP verification step.
4. Authorized requests read or update the relevant MySQL records.
5. The crypto utility is used where selected fields require encryption or decryption.
6. The application returns a rendered page showing account information, transaction results, or administrative information.

**Deployment note:** This diagram represents the repository's Flask/MySQL application flow. It does not mean AWS EC2, Amazon RDS, a cloud load balancer, or other cloud infrastructure is already provisioned or configured.

---

## Project Structure

```text
Secure-Cloud-Online-Banking-System/
|
|-- Secure-Cloud-Banking-System/
|   |-- app/
|   |   |-- __init__.py              # Flask application factory and configuration
|   |   |-- routes/
|   |   |   |-- auth.py              # Registration, login, OTP, logout
|   |   |   |-- dashboard.py         # Dashboard, accounts, profile
|   |   |   |-- transactions.py      # Deposits, withdrawals, transfers, history
|   |   |   |-- admin.py             # Administrator workflows
|   |   |
|   |   |-- utils/
|   |   |   |-- crypto.py            # AES-GCM and SHA-256 helpers
|   |   |
|   |   |-- templates/               # Jinja2 HTML templates
|   |   |-- static/                  # CSS, JavaScript, and static assets
|   |
|   |-- db_update.py                 # Database schema update script
|   |-- run.py                       # Application entry point
|
|-- images/
|   |-- system-architecture.svg      # System architecture diagram
|   |-- dashboard.jpeg               # Add dashboard screenshot
|   |-- login.jpeg                   # Add login screenshot
|   |-- transactions.jpeg             # Add transaction screenshot
|   |-- admin-dashboard.jpeg          # Add admin screenshot
|
|-- setup_database.py                # Initial database/table setup
|-- dump_schema.py                   # Database schema utility
|-- verify_crypto.py                 # Local verification script
|-- requirements.txt                 # Python dependencies
|-- README.md
```

---

## Banking Workflows

### Customer Registration and Login

1. A user submits registration details.
2. The application creates the customer record and associated account according to the current workflow.
3. During login, the application verifies the submitted password.
4. The customer completes email OTP verification before the authenticated session is established.

### Deposits and Withdrawals

1. The customer opens the relevant transaction page.
2. The application processes the submitted transaction details.
3. The database is updated through the transaction workflow.
4. The customer can review transaction information in the transaction list or history.

### Account-to-Account Transfers

1. The customer enters recipient details and the transfer amount.
2. The application resolves the recipient and processes the transfer workflow.
3. Transaction records are used to represent the operation and its status.

**Important:** These flows are described for understanding the code. Before any real-world use, transaction processing needs robust server-side validation, atomic database transactions, concurrency controls, and comprehensive tests.

---

## Technologies Used

### Backend

- Python
- Flask
- Flask route blueprints

### Database

- MySQL
- Flask-MySQLdb / mysqlclient

### Frontend

- Jinja2
- HTML
- CSS
- JavaScript

### Security and Configuration

- Bcrypt password hashing
- SHA-256 helper and preprocessing
- AES-GCM via the Python cryptography package
- Flask-WTF CSRFProtect
- python-dotenv
- Flask-Mail and SMTP for email OTP delivery

Dependency versions are listed in `requirements.txt`. The current application configuration uses local MySQL settings; any cloud deployment must be provisioned and configured separately.

---

## Deployment Guide

### 1. Clone the Repository

```bash
git clone https://github.com/ayusjakhmola25/Secure-Cloud-Online-Banking-System.git
cd Secure-Cloud-Online-Banking-System
```

### 2. Create a Virtual Environment

**Windows PowerShell**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Linux or macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure the Application

Before running the project, inspect `Secure-Cloud-Banking-System/app/__init__.py` and the database setup scripts.

The current repository includes hard-coded database and SMTP settings, and a committed encryption key has been identified in the existing code. Treat exposed values as compromised. Rotate them, remove secrets from source control history where appropriate, and refactor the application to load configuration consistently from environment variables.

Example local `.env` values (placeholders only):

```env
SECRET_KEY=replace-with-a-long-random-secret
ENCRYPTION_KEY=replace-with-a-valid-base64-encoded-32-byte-key
MYSQL_HOST=localhost
MYSQL_USER=your_mysql_username
MYSQL_PASSWORD=your_mysql_password
MYSQL_DB=securebank
MAIL_USERNAME=your_email@example.com
MAIL_PASSWORD=your_email_app_password
```

These are example variable names. The application code must be updated to read the database and mail settings from the environment instead of hard-coded values. Never commit real credentials or keys.

Generate a Flask secret key:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Generate a URL-safe Base64-encoded 32-byte AES key:

```bash
python -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

### 5. Prepare the Database

Ensure that MySQL is running. Review `setup_database.py` and `Secure-Cloud-Banking-System/db_update.py` before executing them; replace local credentials and sample administrator data with safe local values.

```bash
python setup_database.py
```

Confirm that the database schema contains the columns referenced by the active route modules.

### 6. Start the Application

```bash
cd Secure-Cloud-Banking-System
python run.py
```

The current entry point binds to `127.0.0.1:5000`. Open:

```text
http://127.0.0.1:5000
```

The root route redirects to the login page. Email OTP delivery requires valid SMTP configuration.

---

## Main Application Routes

| Route | Purpose |
|---|---|
| `/` | Redirects to the login page |
| `/auth/register` | User registration |
| `/auth/login` | User login |
| `/auth/verify-otp` | Email OTP verification |
| `/auth/logout` | End the current session |
| `/dashboard` | Customer dashboard |
| `/accounts` | Account details |
| `/profile` | View or update profile |
| `/deposit` | Deposit workflow |
| `/deposit/confirm` | Confirm a deposit |
| `/withdraw` | Withdrawal workflow |
| `/withdraw/confirm` | Confirm a withdrawal |
| `/transfer` | Transfer to another account |
| `/transactions` | Transaction list |
| `/history` | Transaction history |
| `/admin/login` | Administrator login |
| `/admin/dashboard` | Administrative overview |
| `/admin/users` | User management |
| `/admin/accounts` | Account management |
| `/admin/transactions` | Transaction monitoring |

Administrative mutation endpoints include actions for deleting users and changing account status. Access control for these actions should be verified through dedicated authorization tests.

---

## Security Notes and Limitations

This repository is an educational project and needs further security work before deployment.

- **Rotate exposed credentials immediately.** The code has included hard-coded database/SMTP credentials and a committed encryption key. Revoke or rotate exposed values and remove them from source control history where appropriate.
- **Do not commit secrets.** Add `.env`, virtual environments, cache directories, and local database exports to `.gitignore`. Keep only placeholder values in `.env.example`.
- **Use a stable secret key.** Do not generate a new Flask `SECRET_KEY` on every startup.
- **Harden money movement.** Validate positive numeric amounts, sufficient balances, limits, and recipient ownership. Use atomic database transactions and suitable locking to prevent race conditions.
- **Review OTP handling.** Use a cryptographically secure random generator, avoid storing raw OTPs in client-side session state, apply rate limiting, and avoid exposing internal exceptions.
- **Harden sessions and cookies.** Configure secure cookie attributes and HTTPS in deployed environments.
- **Verify authorization.** Ensure customers cannot view or modify other customers' accounts or transactions.
- **Review encryption and key management.** Keep keys out of source control and plan for rotation, backups, and safe decryption failure handling.
- **Do not treat transaction hashes as tamper-proof.** A SHA-256 digest stored beside a transaction is not a complete integrity or audit mechanism.
- **Test database consistency.** Check that setup scripts and schema updates match the columns used by current route implementations.

Do not use this application with real financial accounts or sensitive customer data until it has undergone professional security testing and deployment hardening.

---

## Dashboard Capabilities

The current application includes customer-facing pages for:

- Account summary and balance information
- Account details and profile information
- Deposit, withdrawal, and transfer workflows
- Transaction list and history

The administrator area includes user and account management views and transaction monitoring. Actual screenshots can be displayed at the top of this README after the corresponding image files are added to the repository.

---

## Future Enhancements

- Move every credential and connection setting to environment-based configuration.
- Add automated unit and integration tests for authentication and transaction workflows.
- Strengthen transaction atomicity, concurrency handling, and audit logging.
- Add rate limiting and security-event logging.
- Improve schema migration management.
- Add containerized development and deployment support.
- Configure HTTPS and production-grade server deployment.
- Add continuous integration and dependency/security scanning.
- Improve operational monitoring and error handling.

---

## Learning Outcomes

This project provides practical experience in:

- Flask application structure and route blueprints
- MySQL schema design and relational data access
- Session-based authentication and role checks
- Email OTP verification workflows
- Password hashing and authenticated-encryption concepts
- CSRF protection and form handling
- Banking workflow modeling and transaction history
- Administrative monitoring interfaces
- Secure configuration and deployment considerations

---

## Conclusion

The Secure Cloud Online Banking System demonstrates how customer authentication, account management, transaction workflows, database persistence, and administrative monitoring can be organized in a Flask application. It serves as a learning project for web development and application-security concepts while documenting the additional controls required before a financial application could be considered for real-world use.

---

## License

Review the repository's license file and ownership requirements before redistributing or deploying this project.
