# Flask Application Factory
from flask import Flask, redirect, url_for
import os
from dotenv import load_dotenv
from flask_mysqldb import MySQL
from flask_wtf.csrf import CSRFProtect

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

from flask_mail import Mail
mysql = MySQL()
mail = Mail()

def create_app():
    app = Flask(__name__)
    
    # Configuration
    # IMPORTANT: SECRET_KEY must be stable across restarts, otherwise sessions (and CSRF) break.
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
    app.config['ENCRYPTION_KEY'] = os.environ.get('ENCRYPTION_KEY')
    app.config['MYSQL_HOST'] = 'localhost'
    app.config['MYSQL_USER'] = 'root'
    app.config['MYSQL_PASSWORD'] = 'ayush123'
    app.config['MYSQL_DB'] = 'securebank'
    app.config['MYSQL_CONNECT_TIMEOUT'] = 60
    
    mysql.init_app(app)
    app.mysql = mysql

    # Mail configuration
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'jakhmolaayush51@gmail.com'
    app.config['MAIL_PASSWORD'] = 'lapmwnkrdtbmzoer'
    app.config['MAIL_DEFAULT_SENDER'] = 'jakhmolaayush51@gmail.com'
    mail.init_app(app)

    csrf = CSRFProtect()
    csrf.init_app(app)

    # Register all blueprints
    from app.routes import auth, dashboard, transactions, admin
    app.register_blueprint(auth.bp)
    app.register_blueprint(dashboard.dashboard_bp)
    app.register_blueprint(transactions.transactions_bp)
    app.register_blueprint(admin.admin_bp)
    
    @app.route('/')
    def index():
        from flask import redirect, url_for
        return redirect(url_for('auth.login'))
    
    return app
