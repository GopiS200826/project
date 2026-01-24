from flask import Flask, request, jsonify, redirect, session, render_template_string
import json
import hashlib
from functools import wraps
import traceback
import pymysql
import pymysql.cursors
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import time
from decimal import Decimal
from dotenv import load_dotenv

# Load environment variables first
load_dotenv()

# Create Flask app once
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Database Configuration for Railway
MYSQL_HOST = os.environ.get('MYSQLHOST', 'localhost')
MYSQL_USER = os.environ.get('MYSQLUSER', 'root')
MYSQL_PASSWORD = os.environ.get('MYSQLPASSWORD', '')
MYSQL_DB = os.environ.get('MYSQLDATABASE', 'formmaster')
MYSQL_PORT = int(os.environ.get('MYSQLPORT', 3306))

# Email Configuration (optional)
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
EMAIL_USER = os.environ.get('EMAIL_USER', '')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')
EMAIL_FROM = os.environ.get('EMAIL_FROM', '')
ENABLE_EMAIL_NOTIFICATIONS = os.environ.get('ENABLE_EMAIL_NOTIFICATIONS', 'False').lower() == 'true'

# Default Admin Credentials
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')
ADMIN_NAME = os.environ.get('ADMIN_NAME', 'System Administrator')

# Department options
DEPARTMENTS = ['IT', 'CS', 'ECE', 'EEE', 'MECH', 'CIVIL', 'MBA', 'PHYSICS', 'CHEMISTRY', 'MATHS']

def get_db():
    """Get database connection for Railway"""
    try:
        connection = pymysql.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DB,
            port=MYSQL_PORT,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
            connect_timeout=10
        )
        print(f"✓ Connected to database: {MYSQL_DB} on {MYSQL_HOST}:{MYSQL_PORT}")
        return connection
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        traceback.print_exc()
        return None

# Password functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(hashed, password):
    return hashed == hashlib.sha256(password.encode()).hexdigest()

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# Initialize database
def init_db():
    """Initialize database with all tables"""
    try:
        print("Starting database initialization...")
        
        connection = get_db()
        if not connection:
            print("✗ Failed to connect to database")
            return False
        
        with connection.cursor() as cursor:
            # Users table
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(100) NOT NULL,
                role ENUM('student', 'teacher', 'admin') DEFAULT 'student',
                department VARCHAR(50) DEFAULT 'IT',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            # Forms table
            cursor.execute('''CREATE TABLE IF NOT EXISTS forms (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(200) NOT NULL,
                description TEXT,
                created_by INT NOT NULL,
                department VARCHAR(50) NOT NULL,
                form_type ENUM('open', 'confidential') DEFAULT 'open',
                questions JSON,
                is_published BOOLEAN DEFAULT FALSE,
                is_student_submission BOOLEAN DEFAULT FALSE,
                review_status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            # Create admin user if not exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (ADMIN_EMAIL,))
            admin = cursor.fetchone()
            
            if not admin:
                hashed = hash_password(ADMIN_PASSWORD)
                cursor.execute(
                    "INSERT INTO users (email, password, name, role, department) VALUES (%s, %s, %s, 'admin', 'IT')",
                    (ADMIN_EMAIL, hashed, ADMIN_NAME)
                )
                print(f"✓ Admin user created: {ADMIN_EMAIL}")
            
            connection.commit()
            print("\n✅ Database initialization completed successfully!")
            return True
            
    except Exception as e:
        print(f"\n❌ Error initializing database: {e}")
        traceback.print_exc()
        return False
    finally:
        if 'connection' in locals() and connection:
            try:
                connection.close()
            except:
                pass

# Simple HTML wrapper
def html_wrapper(title, content):
    html = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title} - Form System</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                padding-top: 20px;
            }}
            .card {{
                border-radius: 15px;
                box-shadow: 0 10px 20px rgba(0,0,0,0.1);
                border: none;
                margin-bottom: 20px;
            }}
            .btn-primary {{
                background: linear-gradient(45deg, #667eea, #764ba2);
                border: none;
                padding: 10px 25px;
                border-radius: 50px;
                font-weight: 600;
            }}
        </style>
    </head>
    <body>
        <div class="container mt-4">
            {content}
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    '''
    return html

# Routes
@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            email = request.form['email']
            password = request.form['password']
            
            connection = get_db()
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
                user = cursor.fetchone()
            connection.close()
            
            if user and check_password(user['password'], password):
                session['user_id'] = user['id']
                session['email'] = user['email']
                session['name'] = user['name']
                session['role'] = user['role']
                session['department'] = user['department']
                return redirect('/dashboard')
            else:
                content = f'''
                <div class="row justify-content-center align-items-center" style="min-height: 80vh;">
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-body p-4">
                                <h3 class="text-center mb-4">Login</h3>
                                <div class="alert alert-danger">Invalid email or password</div>
                                <form method="POST">
                                    <div class="mb-3">
                                        <label class="form-label">Email</label>
                                        <input type="email" class="form-control" name="email" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Password</label>
                                        <input type="password" class="form-control" name="password" required>
                                    </div>
                                    <button type="submit" class="btn btn-primary w-100">Login</button>
                                </form>
                                <hr class="my-4">
                                <div class="text-center text-muted small mt-3">
                                    <strong>Default Admin:</strong><br>
                                    Email: {ADMIN_EMAIL}<br>
                                    Password: {ADMIN_PASSWORD}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                '''
                return html_wrapper('Login', content)
        except Exception as e:
            print(f"Login error: {e}")
            return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>')
    
    content = f'''
    <div class="row justify-content-center align-items-center" style="min-height: 80vh;">
        <div class="col-md-4">
            <div class="card">
                <div class="card-body p-4">
                    <h3 class="text-center mb-4">Login</h3>
                    <form method="POST">
                        <div class="mb-3">
                            <label class="form-label">Email</label>
                            <input type="email" class="form-control" name="email" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Password</label>
                            <input type="password" class="form-control" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Login</button>
                    </form>
                    <hr class="my-4">
                    <div class="text-center text-muted small mt-3">
                        <strong>Default Admin:</strong><br>
                        Email: {ADMIN_EMAIL}<br>
                        Password: {ADMIN_PASSWORD}
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return html_wrapper('Login', content)

@app.route('/dashboard')
@login_required
def dashboard():
    content = f'''
    <div class="card">
        <div class="card-header bg-primary text-white">
            <h3 class="mb-0">Welcome, {session["name"]}!</h3>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-12">
                    <div class="alert alert-success">
                        <h4>FormMaster Pro</h4>
                        <p>Welcome to the Form Management System</p>
                        <p><strong>Your Role:</strong> {session['role'].title()}</p>
                        <p><strong>Department:</strong> {session['department']}</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return html_wrapper('Dashboard', content)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/health')
def health_check():
    """Health check endpoint for Railway"""
    try:
        connection = get_db()
        if connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
            connection.close()
            return jsonify({
                "status": "healthy",
                "database": "connected",
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({
                "status": "degraded",
                "database": "not_connected",
                "timestamp": datetime.now().isoformat()
            }), 503
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

@app.route('/test')
def test():
    return "✅ Application is running!"

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return html_wrapper('404', '<div class="alert alert-warning">Page not found</div>'), 404

@app.errorhandler(500)
def server_error(e):
    return html_wrapper('500', '<div class="alert alert-danger">Server error</div>'), 500

if __name__ == '__main__':
    print("=" * 60)
    print("FORM SYSTEM STARTING...")
    print("=" * 60)
    
    # Initialize database
    print("\nInitializing database...")
    init_db()
    
    # Get port from Railway environment variable
    port = int(os.environ.get('PORT', 8080))
    
    print(f"\nStarting server on port {port}...")
    print("=" * 60)
    
    # Run the app
    app.run(host='0.0.0.0', port=port, debug=False)
