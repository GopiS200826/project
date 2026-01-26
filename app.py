from flask import Flask, request, jsonify, redirect, session, render_template_string
import json
import hashlib
from functools import wraps
import traceback
import pymysql
import pymysql.cursors
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import time
from decimal import Decimal
import secrets
import random
import string
import threading
from queue import Queue
import atexit
import socket
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import io

# Create Flask app ONCE
app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'  # Make sure this is set

# OTP Configuration
OTP_EXPIRY_MINUTES = 10
OTP_LENGTH = 6

# Database Configuration
#MYSQL_HOST = 'mysql-vdry.railway.internal'
#MYSQL_USER = 'root'
#MYSQL_PASSWORD = 'kyzpHUHOJbBcdufVHeqRgYwjSVbgxiDs'
#MYSQL_DB = 'railway'



# Get database configuration from environment variables
def get_mysql_config():
    """Get MySQL configuration from Railway environment variables"""
    # Try Railway's standard MySQL variables first
    railway_host = os.environ.get('MYSQLHOST')
    
    if railway_host:
        # Using Railway's managed MySQL service
        print("🚀 Using Railway's managed MySQL service")
        return {
            'host': railway_host,
            'user': os.environ.get('MYSQLUSER'),
            'password': os.environ.get('MYSQLPASSWORD'),
            'database': os.environ.get('MYSQLDATABASE'),
            'port': int(os.environ.get('MYSQLPORT', 3306))
        }
    else:
        # Fallback to custom MySQL variables
        print("⚠️ Using custom MySQL configuration")
        return {
            'host': os.environ.get('MYSQL_HOST', 'localhost'),
            'user': os.environ.get('MYSQL_USER', 'root'),
            'password': os.environ.get('MYSQL_PASSWORD', ''),
            'database': os.environ.get('MYSQL_DB', 'railway'),
            'port': int(os.environ.get('MYSQL_PORT', 3306))
        }

# Test database connection
def test_database_connection():
    """Test database connection with current configuration"""
    try:
        config = get_mysql_config()
        print(f"📊 Database Configuration:")
        print(f"   Host: {config['host']}")
        print(f"   User: {config['user']}")
        print(f"   Database: {config['database']}")
        print(f"   Port: {config['port']}")
        
        connection = mysql.connector.connect(
            host=config['host'],
            user=config['user'],
            password=config['password'],
            database=config['database'],
            port=config['port'],
            connect_timeout=5
        )
        
        if connection.is_connected():
            print("✅ Database connection successful!")
            connection.close()
            return True
        else:
            print("❌ Database connection failed")
            return False
            
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        return False

# Update get_db() function to use the new configuration
def get_db():
    """Get database connection with error handling"""
    try:
        config = get_mysql_config()
        
        connection = mysql.connector.connect(
            host=config['host'],
            user=config['user'],
            password=config['password'],
            database=config['database'],
            port=config['port'],
            charset='utf8mb4',
            autocommit=False
        )
        
        return connection
        
    except mysql.connector.Error as e:
        print(f"❌ Database connection error: {e}")
        traceback.print_exc()
        
        # Try to create database if it doesn't exist
        try:
            print("🔄 Attempting to create database...")
            config = get_mysql_config()
            
            # Connect without database specified
            connection = mysql.connector.connect(
                host=config['host'],
                user=config['user'],
                password=config['password'],
                port=config['port'],
                charset='utf8mb4'
            )
            
            cursor = connection.cursor()
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {config['database']}")
            cursor.execute(f"USE {config['database']}")
            connection.commit()
            cursor.close()
            connection.close()
            
            # Try connecting again with database
            print("🔄 Reconnecting with database...")
            connection = mysql.connector.connect(
                host=config['host'],
                user=config['user'],
                password=config['password'],
                database=config['database'],
                port=config['port'],
                charset='utf8mb4',
                autocommit=False
            )
            
            print(f"✅ Successfully created and connected to database: {config['database']}")
            return connection
            
        except Exception as e2:
            print(f"❌ Failed to create database: {e2}")
            traceback.print_exc()
            raise

# Validation (optional)
required_vars = ['MYSQL_HOST', 'MYSQL_USER', 'MYSQL_PASSWORD', 'MYSQL_DB']
for var in required_vars:
    if not locals().get(var):
        print(f"Warning: {var} is not set in environment variables")


# Email Configuration
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USER = 'gopi200026@gmail.com'  # Change this to your email
EMAIL_PASSWORD = 'laku neok xexr croj'  # Change this to your app password
EMAIL_FROM = 'gopi200026@gmail.com'  # Change this to your emai

# Enable/Disable email notifications
ENABLE_EMAIL_NOTIFICATIONS = True  # Set to False to disable emails

# Default Admin Credentials
ADMIN_EMAIL = 'admin@example.com'
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
ADMIN_NAME = 'System Administrator'

# Super Admin Credentials
SUPER_ADMIN_EMAIL = 'superadmin@example.com'
SUPER_ADMIN_PASSWORD = os.getenv('SUPER_ADMIN_PASSWORD')
SUPER_ADMIN_NAME = 'Super Administrator'

# Department options
DEPARTMENTS = ['IT', 'Data Science', 'AI/ML', 'ECE', 'EEE', 'MECH', 'CIVIL', 'MBA', 'PHYSICS', 'CHEMISTRY', 'MATHS', 'Others']

# Email queue for background processing
email_queue = Queue()
# Replace the existing get_db() function with this:

# ========== DECORATORS DEFINITION ==========
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if session.get('role') not in ['teacher', 'admin', 'super_admin']:
            return '''
            <script>
                alert("Teacher access required");
                window.location.href = "/dashboard";
            </script>
            '''
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if session.get('role') not in ['admin', 'super_admin']:
            return '''
            <script>
                alert("Admin access required");
                window.location.href = "/dashboard";
            </script>
            '''
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'student':
            return '''
            <script>
                alert("Student access required");
                window.location.href = "/dashboard";
            </script>
            '''
        return f(*args, **kwargs)
    return decorated_function

def super_admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'super_admin':
            return '''
            <script>
                alert("Super Admin access required");
                window.location.href = "/dashboard";
            </script>
            '''
        return f(*args, **kwargs)
    return decorated_function


import pymysql
import threading
from queue import Queue

# Simple connection management
def get_db():
    """Get database connection with error handling"""
    try:
        connection = pymysql.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DB,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=False
        )
        return connection
    except pymysql.Error as e:
        print(f"Database connection error: {e}")
        # Try to create database if it doesn't exist
        try:
            connection = pymysql.connect(
                host=MYSQL_HOST,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
            with connection.cursor() as cursor:
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS {MYSQL_DB}")
                cursor.execute(f"USE {MYSQL_DB}")
            connection.close()
            
            # Try connecting again
            return pymysql.connect(
                host=MYSQL_HOST,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DB,
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=False
            )
        except Exception as e2:
            print(f"Failed to create database: {e2}")
            raise

# Email queue for background processing
email_queue = Queue()

def email_worker():
    """Background worker for sending emails"""
    while True:
        try:
            task = email_queue.get()
            if task is None:  # Exit signal
                break
            to_email, subject, html_content = task
            send_email(to_email, subject, html_content)
            email_queue.task_done()
        except Exception as e:
            print(f"Error in email worker: {e}")

# Start email worker thread
email_thread = threading.Thread(target=email_worker, daemon=True)
email_thread.start()

def send_email_async(to_email, subject, html_content):
    """Send email asynchronously"""
    if not ENABLE_EMAIL_NOTIFICATIONS:
        return True
    
    try:
        email_queue.put((to_email, subject, html_content))
        return True
    except Exception as e:
        print(f"Error queueing email: {e}")
        return False
    

def generate_download_token():
    """Generate a secure download token"""
    return secrets.token_urlsafe(32)

def create_response_download_entry(response_id, student_id, form_id):
    """Create an entry in response_downloads table - FIXED VERSION"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Check if entry already exists
            cursor.execute('''
                SELECT id, download_token FROM response_downloads 
                WHERE response_id = %s AND student_id = %s
            ''', (response_id, student_id))
            existing = cursor.fetchone()
            
            if existing:
                connection.close()
                return existing['download_token'], None
            
            # Create new entry
            download_token = generate_download_token()
            cursor.execute('''
                INSERT INTO response_downloads 
                (response_id, student_id, form_id, download_token)
                VALUES (%s, %s, %s, %s)
            ''', (response_id, student_id, form_id, download_token))
            
            # Get form details for notification - FIXED QUERY
            cursor.execute('''
                SELECT f.title, f.form_type, f.created_by,
                       u.email as creator_email, u.name as creator_name
                FROM forms f
                JOIN users u ON f.created_by = u.id
                WHERE f.id = %s
            ''', (form_id,))
            form_details = cursor.fetchone()
            
            connection.commit()
            connection.close()
            
            # Rename 'created_by' to 'creator_id' for consistency
            if form_details:
                form_details['creator_id'] = form_details['created_by']
            
            return download_token, form_details
            
    except Exception as e:
        print(f"Error creating download entry: {e}")
        traceback.print_exc()
        return None, None

def grant_download_access(download_id, granted_by):
    """Grant download access to a student"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                UPDATE response_downloads 
                SET access_granted = TRUE, 
                    granted_by = %s, 
                    granted_at = CURRENT_TIMESTAMP
                WHERE id = %s
            ''', (granted_by, download_id))
            connection.commit()
            
            # Get details for notification
            cursor.execute('''
                SELECT rd.*, r.student_id, f.title, u.email as student_email, 
                       u.name as student_name, u2.name as grantor_name
                FROM response_downloads rd
                JOIN responses r ON rd.response_id = r.id
                JOIN forms f ON rd.form_id = f.id
                JOIN users u ON rd.student_id = u.id
                JOIN users u2 ON rd.granted_by = u2.id
                WHERE rd.id = %s
            ''', (download_id,))
            details = cursor.fetchone()
        connection.close()
        return details
    except Exception as e:
        print(f"Error granting download access: {e}")
        return None

def update_download_count(download_id):
    """Update download count and timestamp"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                UPDATE response_downloads 
                SET download_count = download_count + 1,
                    last_downloaded_at = CURRENT_TIMESTAMP
                WHERE id = %s
            ''', (download_id,))
            connection.commit()
        connection.close()
        return True
    except Exception as e:
        print(f"Error updating download count: {e}")
        return False

def get_download_permission(response_id, student_id):
    """Check if student has permission to download response"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT rd.*, f.form_type, f.created_by as form_owner
                FROM response_downloads rd
                JOIN forms f ON rd.form_id = f.id
                WHERE rd.response_id = %s AND rd.student_id = %s
            ''', (response_id, student_id))
            permission = cursor.fetchone()
        connection.close()
        return permission
    except Exception as e:
        print(f"Error getting download permission: {e}")
        return None

def get_pending_download_requests(form_owner_id=None, form_id=None):
    """Get pending download requests"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            if form_id:
                cursor.execute('''
                    SELECT rd.*, r.student_id, u.name as student_name, 
                           u.email as student_email, f.title as form_title,
                           r.score, r.percentage, r.submitted_at
                    FROM response_downloads rd
                    JOIN responses r ON rd.response_id = r.id
                    JOIN forms f ON rd.form_id = f.id
                    JOIN users u ON rd.student_id = u.id
                    WHERE rd.form_id = %s AND rd.access_granted = FALSE
                    ORDER BY rd.created_at DESC
                ''', (form_id,))
            elif form_owner_id:
                cursor.execute('''
                    SELECT rd.*, r.student_id, u.name as student_name, 
                           u.email as student_email, f.title as form_title,
                           r.score, r.percentage, r.submitted_at
                    FROM response_downloads rd
                    JOIN responses r ON rd.response_id = r.id
                    JOIN forms f ON rd.form_id = f.id
                    JOIN users u ON rd.student_id = u.id
                    WHERE f.created_by = %s AND rd.access_granted = FALSE
                    ORDER BY rd.created_at DESC
                ''', (form_owner_id,))
            else:
                cursor.execute('''
                    SELECT rd.*, r.student_id, u.name as student_name, 
                           u.email as student_email, f.title as form_title,
                           r.score, r.percentage, r.submitted_at
                    FROM response_downloads rd
                    JOIN responses r ON rd.response_id = r.id
                    JOIN forms f ON rd.form_id = f.id
                    JOIN users u ON rd.student_id = u.id
                    WHERE rd.access_granted = FALSE
                    ORDER BY rd.created_at DESC
                ''')
            requests = cursor.fetchall()
        connection.close()
        return requests
    except Exception as e:
        print(f"Error getting pending downloads: {e}")
        return []
    
# Add at the top with other imports
import threading
from queue import Queue
import atexit

# Create a background task queue
email_queue = Queue()

def email_worker():
    """Background worker for sending emails"""
    while True:
        try:
            task = email_queue.get()
            if task is None:  # Exit signal
                break
            to_email, subject, html_content = task
            send_email(to_email, subject, html_content)
            email_queue.task_done()
        except Exception as e:
            print(f"Error in email worker: {e}")

# Start email worker thread
email_thread = threading.Thread(target=email_worker, daemon=True)
email_thread.start()

# Update the send_email function to use queue
def send_email_async(to_email, subject, html_content):
    """Send email asynchronously"""
    if not ENABLE_EMAIL_NOTIFICATIONS:
        return True
    
    # Add email to background queue
    try:
        email_queue.put((to_email, subject, html_content))
        return True
    except Exception as e:
        print(f"Error queueing email: {e}")
        return False
        
def send_email(to_email, subject, html_content):
    """Optimized email sending with timeout"""
    if not ENABLE_EMAIL_NOTIFICATIONS:
        return True
    
    try:
        # Set timeout to prevent hanging
        import socket
        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(5)  # 5 second timeout
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = to_email
        
        html_part = MIMEText(html_content, 'html')
        msg.attach(html_part)
        
        # Quick send
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=5) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)
        
        # Restore original timeout
        socket.setdefaulttimeout(original_timeout)
        return True
        
    except Exception as e:
        print(f"Quick email error to {to_email}: {e}")
        return False

def init_db():
    try:
        config = get_mysql_config()
        print(f"🔧 Initializing database: {config['database']}")
        
        # First check if database exists
        connection = mysql.connector.connect(
            host=config['host'],
            user=config['user'],
            password=config['password'],
            port=config['port'],
            charset='utf8mb4'
        )
        
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {MYSQL_DB}")
            cursor.execute(f"USE {MYSQL_DB}")
            
            # Users table - Updated to include super_admin role
            # In the init_db() function, update the users table creation:
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(100) NOT NULL,
                role ENUM('student', 'teacher', 'admin', 'super_admin') DEFAULT 'student',
                department VARCHAR(50) DEFAULT 'IT',
                phone VARCHAR(20),  # ADD THIS LINE
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_email (email),
                INDEX idx_department (department)
            )''')
            
            # In the init_db() function, update the forms table creation:
            cursor.execute('''CREATE TABLE IF NOT EXISTS forms (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(200) NOT NULL,
                description TEXT,
                created_by INT NOT NULL,
                department VARCHAR(50) NOT NULL,
                form_type ENUM('public', 'open', 'confidential') DEFAULT 'open',  # CHANGED: Added 'public'
                questions JSON,
                is_published BOOLEAN DEFAULT FALSE,
                is_student_submission BOOLEAN DEFAULT FALSE,
                review_status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                reviewed_by INT,
                reviewed_at TIMESTAMP NULL,
                share_token VARCHAR(100) UNIQUE,
                public_link_enabled BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL,
                INDEX idx_created_by (created_by),
                INDEX idx_department_form (department),
                INDEX idx_form_type (form_type),
                INDEX idx_student_submission (is_student_submission),
                INDEX idx_review_status (review_status),
                INDEX idx_share_token (share_token)
            )''')
            
            # Notifications table
            cursor.execute('''CREATE TABLE IF NOT EXISTS notifications (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            user_id INT NOT NULL,
                            title VARCHAR(200) NOT NULL,
                            message TEXT NOT NULL,
                            type ENUM('info', 'success', 'warning', 'danger') DEFAULT 'info',
                            is_read BOOLEAN DEFAULT FALSE,
                            link VARCHAR(500),
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                            INDEX idx_user_id (user_id),
                            INDEX idx_is_read (is_read),
                            INDEX idx_created_at (created_at)
                        )''')
            
            # In the init_db() function, replace the otps table creation with:
            cursor.execute('''CREATE TABLE IF NOT EXISTS otps (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            email VARCHAR(100) NOT NULL,
                            otp_code VARCHAR(10) NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            expires_at TIMESTAMP NULL,
                            is_used BOOLEAN DEFAULT FALSE,
                            purpose ENUM('login', 'registration', 'password_reset') DEFAULT 'login',
                            INDEX idx_email (email),
                            INDEX idx_otp_code (otp_code),
                            INDEX idx_expires_at (expires_at),
                            INDEX idx_is_used (is_used),
                            INDEX idx_purpose (purpose)
                            )''')
            
            # Form requests table
            cursor.execute('''CREATE TABLE IF NOT EXISTS form_requests (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            form_id INT NOT NULL,
                            student_id INT NOT NULL,
                            requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                            approved_by INT,
                            approved_at TIMESTAMP,
                            FOREIGN KEY (form_id) REFERENCES forms(id) ON DELETE CASCADE,
                            FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
                            FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL,
                            INDEX idx_form_id (form_id),
                            INDEX idx_student_id (student_id),
                            INDEX idx_status (status),
                            UNIQUE KEY unique_form_student (form_id, student_id)
                            )''')
            
            # Assignments table
            cursor.execute('''CREATE TABLE IF NOT EXISTS assignments (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            form_id INT NOT NULL,
                            student_id INT NOT NULL,
                            assigned_by INT NOT NULL,
                            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            due_date DATETIME,
                            is_completed BOOLEAN DEFAULT FALSE,
                            FOREIGN KEY (form_id) REFERENCES forms(id) ON DELETE CASCADE,
                            FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
                            FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE CASCADE,
                            INDEX idx_form_assignment (form_id),
                            INDEX idx_student_assignment (student_id),
                            INDEX idx_is_completed (is_completed),
                            UNIQUE KEY unique_assignment (form_id, student_id)
                            )''')
            
            # Response download permissions table
            cursor.execute('''CREATE TABLE IF NOT EXISTS response_downloads (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            response_id INT NOT NULL,
                            student_id INT NOT NULL,
                            form_id INT NOT NULL,
                            access_granted BOOLEAN DEFAULT FALSE,
                            granted_by INT,
                            granted_at TIMESTAMP,
                download_count INT DEFAULT 0,
                last_downloaded_at TIMESTAMP NULL,
                            download_token VARCHAR(100) UNIQUE,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (response_id) REFERENCES responses(id) ON DELETE CASCADE,
                            FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
                            FOREIGN KEY (form_id) REFERENCES forms(id) ON DELETE CASCADE,
                            FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL,
                            INDEX idx_response_download (response_id),
                            INDEX idx_student_download (student_id),
                            INDEX idx_form_download (form_id),
                            INDEX idx_access_granted (access_granted),
                            INDEX idx_download_token (download_token),
                            UNIQUE KEY unique_response_student (response_id, student_id)
                            )''')
            
            # Responses table
            cursor.execute('''CREATE TABLE IF NOT EXISTS responses (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            form_id INT NOT NULL,
                            student_id INT NOT NULL,
                            answers JSON NOT NULL,
                            score DECIMAL(5,2) DEFAULT 0,
                            total_marks DECIMAL(5,2) DEFAULT 0,
                            percentage DECIMAL(5,2) DEFAULT 0,
                            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            time_taken INT,
                            FOREIGN KEY (form_id) REFERENCES forms(id) ON DELETE CASCADE,
                            FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
                            INDEX idx_form_response (form_id),
                            INDEX idx_student_response (student_id),
                            UNIQUE KEY unique_response (form_id, student_id)
                            )''')
            
            # Student form reviews table
            cursor.execute('''CREATE TABLE IF NOT EXISTS student_form_reviews (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            form_id INT NOT NULL,
                            student_id INT NOT NULL,
                            reviewer_id INT NOT NULL,
                            review_notes TEXT,
                            review_status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            reviewed_at TIMESTAMP,
                            FOREIGN KEY (form_id) REFERENCES forms(id) ON DELETE CASCADE,
                            FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
                            FOREIGN KEY (reviewer_id) REFERENCES users(id) ON DELETE CASCADE,
                            INDEX idx_form_review (form_id),
                            INDEX idx_student_review (student_id),
                            INDEX idx_reviewer (reviewer_id)
                            )''')
            
            # Create admin user if not exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (ADMIN_EMAIL,))
            if not cursor.fetchone():
                hashed = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
                cursor.execute(
                    "INSERT INTO users (email, password, name, role, department) VALUES (%s, %s, %s, 'admin', 'IT')",
                    (ADMIN_EMAIL, hashed, ADMIN_NAME)
                )
                print(f"Admin user created: {ADMIN_EMAIL} / {ADMIN_PASSWORD}")
            
            # Create super admin user if not exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (SUPER_ADMIN_EMAIL,))
            if not cursor.fetchone():
                hashed = hashlib.sha256(SUPER_ADMIN_PASSWORD.encode()).hexdigest()
                cursor.execute(
                    "INSERT INTO users (email, password, name, role, department) VALUES (%s, %s, %s, 'super_admin', 'IT')",
                    (SUPER_ADMIN_EMAIL, hashed, SUPER_ADMIN_NAME)
                )
                print(f"Super Admin user created: {SUPER_ADMIN_EMAIL} / {SUPER_ADMIN_PASSWORD}")
            
            connection.commit()
            print("Database initialized successfully!")
            
    except Exception as e:
        print(f"Error initializing database: {e}")
        traceback.print_exc()
    finally:
        if 'connection' in locals() and connection.open:
            connection.close()

# Password functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(hashed, password):
    return hashed == hashlib.sha256(password.encode()).hexdigest()

# OTP Functions
def generate_otp(length=OTP_LENGTH):
    """Generate a random OTP"""
    return ''.join(random.choices(string.digits, k=length))

@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1 as status')
            result = cursor.fetchone()
        connection.close()
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected' if result and result['status'] == 1 else 'disconnected',
            'session': 'active' if 'user_id' in session else 'inactive',
            'otp_enabled': True
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

def store_otp(email, purpose='login'):
    """Store OTP in database and return the OTP code"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Invalidate previous OTPs for this email and purpose
            cursor.execute('''
                UPDATE otps SET is_used = TRUE 
                WHERE email = %s AND purpose = %s AND is_used = FALSE
            ''', (email, purpose))
            
            # Generate new OTP
            otp_code = generate_otp()
            expires_at = datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)
            
            # Store new OTP
            cursor.execute('''
                INSERT INTO otps (email, otp_code, expires_at, purpose)
                VALUES (%s, %s, %s, %s)
            ''', (email, otp_code, expires_at, purpose))
            
            connection.commit()
        
        connection.close()
        print(f"OTP stored for {email}: {otp_code} (expires: {expires_at})")
        return otp_code
    except Exception as e:
        print(f"Error storing OTP: {e}")
        traceback.print_exc()
        return None

def verify_otp(email, otp_code, purpose='login'):
    """Verify OTP with better error handling"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT * FROM otps 
                WHERE email = %s AND otp_code = %s AND purpose = %s 
                AND is_used = FALSE AND expires_at > NOW()
                ORDER BY created_at DESC LIMIT 1
            ''', (email, otp_code, purpose))
            otp_record = cursor.fetchone()
            
            print(f"DEBUG: OTP record found: {otp_record}")
            
            if otp_record:
                # Mark OTP as used
                cursor.execute('''
                    UPDATE otps SET is_used = TRUE 
                    WHERE id = %s
                ''', (otp_record['id'],))
                connection.commit()
                return True
        connection.close()
        return False
    except Exception as e:
        print(f"Error verifying OTP: {e}")
        return False

@app.route('/test-pdf')
@login_required
def test_pdf():
    """Test PDF generation"""
    try:
        # Import inside function
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from io import BytesIO
        
        # Create simple PDF
        buffer = BytesIO()
        doc = canvas.Canvas(buffer, pagesize=letter)
        doc.drawString(100, 750, "PDF Generation Test")
        doc.drawString(100, 730, f"User: {session['name']}")
        doc.drawString(100, 710, f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        doc.save()
        
        pdf_data = buffer.getvalue()
        buffer.close()
        
        response = make_response(pdf_data)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=test.pdf'
        return response
        
    except Exception as e:
        return f"PDF Error: {str(e)}", 500
    
@app.route('/test-otp', methods=['GET', 'POST'])
def test_otp():
    """Test OTP endpoint"""
    if request.method == 'GET':
        return '''
        <html>
        <body>
            <h1>Test OTP Submission</h1>
            <form id="testForm">
                <input type="email" name="email" placeholder="Email" value="test@example.com"><br>
                <input type="text" name="otp" placeholder="OTP" value="123456"><br>
                <input type="text" name="purpose" placeholder="Purpose" value="login"><br>
                <button type="button" onclick="testSubmit()">Test JSON Submit</button>
                <button type="button" onclick="testFormSubmit()">Test Form Submit</button>
            </form>
            <div id="result"></div>
            
            <script>
                function testSubmit() {
                    const form = document.getElementById('testForm');
                    const data = {
                        email: form.email.value,
                        otp: form.otp.value,
                        purpose: form.purpose.value
                    };
                    
                    fetch('/verify-otp', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(data)
                    })
                    .then(res => res.json())
                    .then(data => {
                        document.getElementById('result').innerHTML = 
                            '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                    });
                }
                
                function testFormSubmit() {
                    const form = document.getElementById('testForm');
                    const formData = new FormData(form);
                    
                    fetch('/verify-otp', {
                        method: 'POST',
                        body: formData
                    })
                    .then(res => res.json())
                    .then(data => {
                        document.getElementById('result').innerHTML = 
                            '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                    });
                }
            </script>
        </body>
        </html>
        '''

def send_otp_email(email, otp_code, purpose='login'):
    """Send OTP via email"""
    if not ENABLE_EMAIL_NOTIFICATIONS:
        return True
    
    purpose_text = {
        'login': 'Login',
        'registration': 'Registration',
        'password_reset': 'Password Reset'
    }.get(purpose, 'Verification')
    
    subject = f'{purpose_text} OTP - FormMaster Pro'
    
    html_content = f'''
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px 10px 0 0;">
            <h2 style="color: white; margin: 0; text-align: center;">
                <i class="fas fa-shield-alt" style="margin-right: 10px;"></i>FormMaster Pro
            </h2>
        </div>
        
        <div style="padding: 30px; background: #ffffff; border-radius: 0 0 10px 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <h3 style="color: #333; margin-top: 0;">{purpose_text} Verification</h3>
            
            <p>Hello,</p>
            
            <p>Use the following OTP to complete your {purpose_text.lower()}:</p>
            
            <div style="text-align: center; margin: 30px 0;">
                <div style="background: #f8f9fa; border: 2px dashed #dee2e6; border-radius: 10px; padding: 20px; display: inline-block;">
                    <div style="font-size: 32px; font-weight: bold; letter-spacing: 10px; color: #667eea;">
                        {otp_code}
                    </div>
                </div>
            </div>
            
            <p style="color: #666; font-size: 14px;">
                <strong>Important:</strong>
                <ul style="color: #666;">
                    <li>This OTP is valid for {OTP_EXPIRY_MINUTES} minutes</li>
                    <li>Do not share this OTP with anyone</li>
                    <li>If you didn't request this, please ignore this email</li>
                </ul>
            </p>
            
            <div style="border-top: 1px solid #eee; margin-top: 30px; padding-top: 20px;">
                <p style="color: #999; font-size: 12px; margin: 0;">
                    This is an automated message from FormMaster Pro. Please do not reply to this email.
                </p>
            </div>
        </div>
    </div>
    '''
    
    return send_email(email, subject, html_content)

# ... after all imports ...

# Create Flask app ONCE
app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'  # Make sure this is set


# ========== CONFIGURATION ==========
# OTP Configuration
OTP_EXPIRY_MINUTES = 10
OTP_LENGTH = 6



# ... rest of the code continues ...

# Notification functions
def create_notification(user_id, title, message, type='info', link=None):
    """Create a new notification for a user"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                INSERT INTO notifications (user_id, title, message, type, link)
                VALUES (%s, %s, %s, %s, %s)
            ''', (user_id, title, message, type, link))
            connection.commit()
        connection.close()
        return True
    except Exception as e:
        print(f"Error creating notification: {e}")
        return False

def get_unread_notification_count(user_id):
    """Get count of unread notifications for a user"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT COUNT(*) as count FROM notifications 
                WHERE user_id = %s AND is_read = FALSE
            ''', (user_id,))
            result = cursor.fetchone()
        connection.close()
        return result['count'] if result else 0
    except Exception as e:
        print(f"Error getting notification count: {e}")
        return 0

def get_user_notifications(user_id, limit=20):
    """Get notifications for a user"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT * FROM notifications 
                WHERE user_id = %s 
                ORDER BY created_at DESC 
                LIMIT %s
            ''', (user_id, limit))
            notifications = cursor.fetchall()
        connection.close()
        return notifications
    except Exception as e:
        print(f"Error getting notifications: {e}")
        return []

def mark_notification_as_read(notification_id, user_id):
    """Mark a specific notification as read"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                UPDATE notifications 
                SET is_read = TRUE 
                WHERE id = %s AND user_id = %s
            ''', (notification_id, user_id))
            connection.commit()
        connection.close()
        return True
    except Exception as e:
        print(f"Error marking notification as read: {e}")
        return False

def mark_all_notifications_as_read(user_id):
    """Mark all notifications as read for a user"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                UPDATE notifications 
                SET is_read = TRUE 
                WHERE user_id = %s AND is_read = FALSE
            ''', (user_id,))
            connection.commit()
        connection.close()
        return True
    except Exception as e:
        print(f"Error marking all notifications as read: {e}")
        return False

def get_time_ago(timestamp):
    """Convert timestamp to relative time string"""
    now = datetime.now()
    diff = now - timestamp
    
    if diff.days > 365:
        years = diff.days // 365
        return f"{years} year{'s' if years > 1 else ''} ago"
    elif diff.days > 30:
        months = diff.days // 30
        return f"{months} month{'s' if months > 1 else ''} ago"
    elif diff.days > 0:
        return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    else:
        return "Just now"

# HTML Template function
def html_wrapper(title, content, navbar='', scripts=''):
    # Admin test button
    admin_test_btn = ''
    if session.get('role') == 'admin':
        admin_test_btn = '<div class="admin-test-btn"><a href="/admin/test" class="btn btn-warning"><i class="fas fa-vial me-2"></i>Admin Test</a></div>'
    
    html = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title} - Form System</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            body {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                padding-top: 70px;
            }}
            .navbar {{
                background: rgba(255, 255, 255, 0.98);
                backdrop-filter: blur(10px);
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                position: fixed;
                top: 0;
                width: 100%;
                z-index: 1000;
            }}
            .dropdown-menu {{
                z-index: 1100 !important;
            }}
            .card {{
                border-radius: 15px;
                box-shadow: 0 10px 20px rgba(0,0,0,0.1);
                border: none;
                margin-bottom: 20px;
                transition: transform 0.3s;
            }}
            .card:hover {{
                transform: translateY(-5px);
            }}
            .btn-primary {{
                background: linear-gradient(45deg, #667eea, #764ba2);
                border: none;
                padding: 10px 25px;
                border-radius: 50px;
                font-weight: 600;
            }}
            .btn-primary:hover {{
                background: linear-gradient(45deg, #5a67d8, #6b46c1);
                transform: scale(1.05);
            }}
            .question-card {{
                border-left: 4px solid #667eea;
                background: #f8f9ff;
            }}
            .student-form-card {{
                border-left: 4px solid #10b981;
            }}
            .badge-success {{ background: #10b981; }}
            .badge-warning {{ background: #f59e0b; }}
            .badge-danger {{ background: #ef4444; }}
            .badge-info {{ background: #3b82f6; }}
            .badge-purple {{ 
                background: linear-gradient(45deg, #8b5cf6, #ec4899);
                color: white;
            }}
            .badge-student {{
                background: linear-gradient(45deg, #10b981, #059669);
                color: white;
            }}
            .badge-super-admin {{
                background: linear-gradient(45deg, #dc2626, #b91c1c);
                color: white;
            }}
            .glass-effect {{
                background: rgba(255, 255, 255, 0.9);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.2);
            }}
            .stat-card {{
                color: white;
                border-radius: 15px;
                padding: 20px;
                margin-bottom: 20px;
                transition: transform 0.3s, box-shadow 0.3s;
            }}
            .stat-card:hover {{
                transform: translateY(-5px);
                box-shadow: 0 10px 20px rgba(0,0,0,0.2);
            }}
            .form-control, .form-select {{
                border-radius: 10px;
                padding: 12px 15px;
                border: 2px solid #e2e8f0;
                transition: all 0.3s;
            }}
            .form-control:focus, .form-select:focus {{
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }}
            .table th {{
                border-top: none;
                font-weight: 600;
                color: #4a5568;
            }}
            .alert {{
                border-radius: 10px;
                border: none;
            }}
            .form-action-buttons {{
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
            }}
            .request-badge {{
                font-size: 0.7rem;
                padding: 2px 6px;
                margin-left: 5px;
            }}
            .form-actions {{
                display: flex;
                gap: 8px;
                flex-wrap: wrap;
            }}
            .review-section {{
                background: #f0f9ff;
                border-radius: 10px;
                padding: 20px;
                margin-top: 20px;
            }}
            .student-stats-card {{
                background: linear-gradient(45deg, #10b981, #059669);
                color: white;
            }}
            .admin-test-btn {{
                position: fixed;
                bottom: 20px;
                right: 20px;
                z-index: 1000;
            }}
            .form-check-input:checked {{
                background-color: #667eea;
                border-color: #667eea;
            }}
            .dept-filter {{
                background: rgba(255, 255, 255, 0.9);
                border-radius: 10px;
                padding: 15px;
                margin-bottom: 20px;
            }}
            .dept-stats {{
                background: rgba(255, 255, 255, 0.9);
                border-radius: 10px;
                padding: 15px;
            }}
            .dept-badge {{
                cursor: pointer;
                transition: all 0.3s;
            }}
            .dept-badge:hover {{
                transform: scale(1.05);
                box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            }}
            .notification-item {{
                transition: all 0.3s;
                cursor: pointer;
            }}
            .notification-item:hover {{
                background-color: #f8f9fa;
                transform: translateX(5px);
            }}
            .notification-unread {{
                border-left: 4px solid #667eea;
                background-color: #f0f4ff;
            }}
            .notification-list {{
                max-height: 400px;
                overflow-y: auto;
            }}
            .share-link-box {{
                background: #f8f9fa;
                border: 2px dashed #dee2e6;
                border-radius: 10px;
                padding: 15px;
                margin: 15px 0;
            }}
            .copy-btn {{
                cursor: pointer;
                transition: all 0.3s;
            }}
            .copy-btn:hover {{
                transform: scale(1.05);
            }}
            .share-actions {{
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
                margin-top: 10px;
            }}
            .public-link-badge {{
                background: linear-gradient(45deg, #8b5cf6, #7c3aed);
                color: white;
                padding: 5px 10px;
                border-radius: 20px;
                font-size: 0.8rem;
            }}
        </style>
    </head>
    <body>
        {navbar}
        <div class="container mt-4">
            {content}
        </div>
        {admin_test_btn}
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        {scripts}
    </body>
    </html>
    '''
    return html

def get_navbar():
    if 'user_id' not in session:
        return ''
    
    # Get unread notification count
    unread_count = get_unread_notification_count(session['user_id'])
    notification_badge = ''
    if unread_count > 0:
        notification_badge = f'<span class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger">{unread_count}</span>'
    
    user_badge = ''
    if session['role'] == 'super_admin':
        user_badge = '<span class="badge badge-super-admin">SUPER ADMIN</span>'
    elif session['role'] == 'admin':
        user_badge = '<span class="badge bg-danger">ADMIN</span>'
    elif session['role'] == 'teacher':
        user_badge = '<span class="badge bg-warning">TEACHER</span>'
    else:
        user_badge = '<span class="badge student-stats-card">STUDENT</span>'
    
    dept_badge = '<span class="badge bg-dark ms-2">' + session.get('department', 'N/A') + '</span>'
    
    nav_links = '''
    <li><a class="dropdown-item" href="/dashboard"><i class="fas fa-home me-2"></i>Dashboard</a></li>
    '''
    
    if session['role'] in ['teacher', 'admin', 'super_admin']:
        nav_links += '''
        <li><a class="dropdown-item" href="/create-form"><i class="fas fa-plus me-2"></i>Create Form</a></li>
        <li><a class="dropdown-item" href="/form-requests"><i class="fas fa-clock me-2"></i>Pending Requests</a></li>
        <li><a class="dropdown-item" href="/review-forms"><i class="fas fa-check-circle me-2"></i>Review Forms</a></li>
        <li><a class="dropdown-item" href="/teacher-analytics"><i class="fas fa-chart-bar me-2"></i>Analytics</a></li>
        '''
    
    if session['role'] == 'student':
        nav_links += '''
        <li><a class="dropdown-item" href="/create-student-form"><i class="fas fa-plus-circle me-2"></i>Create Form</a></li>
        <li><a class="dropdown-item" href="/my-submissions"><i class="fas fa-history me-2"></i>My Submissions</a></li>
        <li><a class="dropdown-item" href="/my-responses"><i class="fas fa-chart-bar me-2"></i>My Results</a></li>
        '''
    
    if session['role'] in ['admin', 'super_admin']:
        nav_links += '''
        <li><a class="dropdown-item" href="/admin"><i class="fas fa-cogs me-2"></i>Admin Panel</a></li>
        <li><a class="dropdown-item" href="/admin/test"><i class="fas fa-vial me-2"></i>System Test</a></li>
        '''
    
    return f'''
    <nav class="navbar navbar-expand-lg">
        <div class="container">
            <a class="navbar-brand text-dark fw-bold" href="/dashboard">
                <i class="fas fa-poll me-2"></i>FormMaster Pro
                {dept_badge}
            </a>
            <div class="d-flex align-items-center">
                <!-- Notifications Dropdown -->
                <div class="dropdown me-3">
                    <button class="btn btn-outline-secondary position-relative" type="button" 
                            id="notificationDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                        <i class="fas fa-bell"></i>
                        {notification_badge}
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="notificationDropdown" style="min-width: 350px;">
                        <li class="dropdown-header d-flex justify-content-between align-items-center">
                            <span>Notifications</span>
                            <small>
                                <a href="/notifications" class="text-decoration-none">View All</a>
                            </small>
                        </li>
                        <li><hr class="dropdown-divider"></li>
                        <div id="notification-list" class="notification-list">
                            <!-- Notifications will be loaded via AJAX -->
                            <li class="text-center py-3">
                                <div class="spinner-border spinner-border-sm text-primary" role="status">
                                    <span class="visually-hidden">Loading...</span>
                                </div>
                                <span class="ms-2">Loading notifications...</span>
                            </li>
                        </div>
                        <li><hr class="dropdown-divider"></li>
                        <li class="text-center">
                            <a href="/notifications" class="dropdown-item">
                                <i class="fas fa-list me-2"></i>View All Notifications
                            </a>
                        </li>
                    </ul>
                </div>
                
                <!-- User Profile Dropdown -->
                <div class="dropdown">
                    <button class="btn btn-outline-dark dropdown-toggle d-flex align-items-center" type="button" 
                            id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                        <i class="fas fa-user-circle me-2 fs-4"></i>
                        <div class="text-start">
                            <div class="fw-bold">{session["name"]}</div>
                            <small>{user_badge}</small>
                        </div>
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                        {nav_links}
                        <li><a class="dropdown-item" href="/notifications">
                            <i class="fas fa-bell me-2"></i>Notifications
                            {f'<span class="badge bg-danger ms-2">{unread_count}</span>' if unread_count > 0 else ''}
                        </a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item text-danger" href="/logout">
                            <i class="fas fa-sign-out-alt me-2"></i>Logout
                        </a></li>
                    </ul>
                </div>
            </div>
        </div>
    </nav>
    <script>
        $(document).ready(function() {{
            loadNotifications();
            
            // Load notifications every 30 seconds
            setInterval(loadNotifications, 30000);
        }});
        
        function loadNotifications() {{
            $.ajax({{
                url: '/api/notifications/recent',
                type: 'GET',
                success: function(response) {{
                    if (response.success) {{
                        $('#notification-list').html(response.html);
                        // Update notification badge
                        if (response.unread_count > 0) {{
                            $('.notification-badge').html('<span class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger">' + response.unread_count + '</span>');
                        }} else {{
                            $('.notification-badge').html('');
                        }}
                    }}
                }},
                error: function() {{
                    $('#notification-list').html('<li class="text-center py-3 text-danger">Error loading notifications</li>');
                }}
            }});
        }}
        
        function markAsRead(notificationId) {{
            $.ajax({{
                url: '/api/notifications/' + notificationId + '/read',
                type: 'POST',
                success: function(response) {{
                    if (response.success) {{
                        loadNotifications(); // Reload notifications
                    }}
                }}
            }});
        }}
    </script>
    '''
@app.route('/verify-otp', methods=['POST'])
def verify_otp_endpoint():
    """Endpoint for OTP verification - FIXED VERSION"""
    try:
        data = {}
        
        # Debug: Print request info
        print(f"DEBUG: Request method: {request.method}")
        print(f"DEBUG: Content-Type: {request.content_type}")
        print(f"DEBUG: Is JSON: {request.is_json}")
        print(f"DEBUG: Form data: {request.form}")
        print(f"DEBUG: Raw data: {request.get_data(as_text=True)}")
        
        # Handle both JSON and form data properly
        if request.is_json:
            try:
                data = request.get_json(force=True, silent=True)
                if data is None:
                    print("DEBUG: JSON parsing returned None")
                    data = {}
            except Exception as json_error:
                print(f"JSON parse error: {json_error}")
                data = {}
        else:
            # Handle form data
            try:
                data = request.form.to_dict()
                print(f"DEBUG: Form data extracted: {data}")
            except Exception as form_error:
                print(f"Form data error: {form_error}")
                data = {}
        
        # Debug logging
        print(f"DEBUG: Received OTP verification data: {data}")
        
        # Extract data with proper error handling
        email = data.get('email')
        otp_code = data.get('otp') or data.get('otp_code')
        purpose = data.get('purpose', 'login')
        
        # Debug extracted values
        print(f"DEBUG: Extracted - email: {email}, otp: {otp_code}, purpose: {purpose}")
        
        # Validate required fields
        if not email:
            print("Error: Email is missing in request")
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        
        if not otp_code:
            print("Error: OTP code is missing in request")
            return jsonify({'success': False, 'error': 'OTP code is required'}), 400
        
        print(f"Verifying OTP for email: {email}, purpose: {purpose}")
        
        # Verify OTP
        if verify_otp(email, otp_code, purpose):
            print(f"OTP verified successfully for {email}")
            
            # For login OTP
            if purpose == 'login' and 'pending_login' in session:
                pending_user = session.pop('pending_login', {})
                
                session['user_id'] = pending_user.get('user_id')
                session['email'] = pending_user.get('email')
                session['name'] = pending_user.get('name')
                session['role'] = pending_user.get('role')
                session['department'] = pending_user.get('department')
                
                # Clear login attempts
                session.pop('login_attempts', None)
                
                # Create success response
                response_data = {
                    'success': True, 
                    'message': 'Login successful!',
                    'redirect': '/dashboard'
                }
                print(f"Login successful, returning: {response_data}")
                return jsonify(response_data)
            
            elif purpose == 'registration':
                return jsonify({'success': True, 'message': 'OTP verified successfully'})
            
            elif purpose == 'password_reset':
                return jsonify({'success': True, 'message': 'OTP verified successfully'})
            else:
                return jsonify({'success': True, 'message': 'OTP verified'})
                
        else:
            print(f"Invalid or expired OTP for {email}")
            return jsonify({'success': False, 'error': 'Invalid or expired OTP'}), 400
            
    except Exception as e:
        print(f"OTP verification error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'}), 500
    
# Generate share token
def generate_share_token():
    return secrets.token_urlsafe(32)

def ensure_form_has_share_token(form_id):
    """Ensure a form has a share token, generate if not exists"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('SELECT share_token FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            if not form or not form['share_token']:
                share_token = generate_share_token()
                cursor.execute('UPDATE forms SET share_token = %s WHERE id = %s', (share_token, form_id))
                connection.commit()
                return share_token
            
        connection.close()
        return form['share_token']
    except Exception as e:
        print(f"Error ensuring share token: {e}")
        return None

# Routes
@app.route('/')
def index():
    return redirect('/login')

def get_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    if 'csrf_token' not in session:
        return False
    return secrets.compare_digest(session.get('csrf_token', ''), token or '')
# Add to your login forms:
# First, let's fix the login route to handle both JSON and form data properly
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        csrf_token = get_csrf_token()
        
        # Show login form with CSRF token
        content = f'''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login - FormMaster Pro</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
            <style>
                body {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding-top: 20px;
                }}
                .login-card {{
                    background: rgba(255, 255, 255, 0.95);
                    border-radius: 20px;
                    box-shadow: 0 15px 35px rgba(0,0,0,0.2);
                    padding: 40px;
                    margin-top: 20px;
                }}
                .alert {{
                    border-radius: 10px;
                    border: none;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="row justify-content-center">
                    <div class="col-md-5">
                        <div class="login-card">
                            <div class="text-center mb-4">
                                <i class="fas fa-poll fa-3x text-primary mb-3"></i>
                                <h3>Welcome to FormMaster Pro</h3>
                                <p class="text-muted">Secure Login with OTP Verification</p>
                            </div>
                            
                            <form method="POST" id="loginForm">
                                <input type="hidden" name="csrf_token" value="{csrf_token}">
                                <input type="hidden" name="login_stage" value="credentials">
                                
                                <div class="mb-3">
                                    <label class="form-label">Email Address *</label>
                                    <div class="input-group">
                                        <span class="input-group-text"><i class="fas fa-envelope"></i></span>
                                        <input type="email" class="form-control" name="email" required 
                                               placeholder="your@email.com" value="">
                                    </div>
                                </div>
                                
                                <div class="mb-3">
                                    <label class="form-label">Password *</label>
                                    <div class="input-group">
                                        <span class="input-group-text"><i class="fas fa-lock"></i></span>
                                        <input type="password" class="form-control" name="password" required 
                                               placeholder="••••••••">
                                    </div>
                                </div>
                                
                                <button type="submit" class="btn btn-primary w-100 mt-3">
                                    <i class="fas fa-sign-in-alt me-2"></i>Sign In
                                </button>
                            </form>
                            
                            <hr class="my-4">
                            
                            <div class="text-center">
                                <p class="mb-2">
                                    <a href="/forgot-password" class="text-decoration-none">
                                        <i class="fas fa-key me-1"></i>Forgot Password?
                                    </a>
                                </p>
                                <p class="mb-0">
                                    <span class="text-muted">Don't have an account?</span>
                                    <a href="/register" class="text-decoration-none fw-bold ms-1">
                                        Sign Up Now
                                    </a>
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
                // Simple form validation
                document.getElementById('loginForm').addEventListener('submit', function(e) {{
                    const email = this.querySelector('input[name="email"]').value;
                    const password = this.querySelector('input[name="password"]').value;
                    
                    if (!email || !password) {{
                        e.preventDefault();
                        alert('Please fill in all required fields');
                        return false;
                    }}
                    
                    return true;
                }});
            </script>
        </body>
        </html>
        '''
        return content
    
    # POST request handling
    if request.method == 'POST':
        try:
            print("DEBUG: Login POST request received")
            print(f"DEBUG: Content-Type: {request.content_type}")
            print(f"DEBUG: Is JSON: {request.is_json}")
            print(f"DEBUG: Form data: {dict(request.form)}")
            
            # Get data based on content type
            email = None
            password = None
            csrf_token_from_form = None
            login_stage = 'credentials'
            
            if request.is_json:
                data = request.get_json(silent=True) or {}
                email = data.get('email')
                password = data.get('password')
                csrf_token_from_form = data.get('csrf_token')
                login_stage = data.get('login_stage', 'credentials')
            else:
                # Form data
                email = request.form.get('email', '').strip()
                password = request.form.get('password', '').strip()
                csrf_token_from_form = request.form.get('csrf_token')
                login_stage = request.form.get('login_stage', 'credentials')
            
            print(f"DEBUG: Extracted - email: {email}, stage: {login_stage}")
            print(f"DEBUG: CSRF token received: {csrf_token_from_form}")
            print(f"DEBUG: Session CSRF token: {session.get('csrf_token')}")
            
            # Validate CSRF token
            if not validate_csrf_token(csrf_token_from_form):
                print("ERROR: CSRF token validation failed")
                if request.is_json:
                    return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 400
                else:
                    return '''
                    <script>
                        alert("Security error: Invalid CSRF token. Please refresh the page and try again.");
                        window.location.href = "/login";
                    </script>
                    '''
            
            print("DEBUG: CSRF token validation passed")
            
            # Check if user exists
            connection = get_db()
            user = None
            try:
                with connection.cursor() as cursor:
                    cursor.execute('''
                        SELECT id, email, name, role, department, password 
                        FROM users WHERE email = %s LIMIT 1
                    ''', (email,))
                    user = cursor.fetchone()
            finally:
                connection.close()
            
            print(f"DEBUG: User found: {user is not None}")
            
            # Stage 1: Check credentials
            if login_stage == 'credentials':
                if user and check_password(user['password'], password):
                    print(f"DEBUG: Password check passed for {email}")
                    
                    # Check if user is admin/super_admin (skip OTP)
                    if user['role'] in ['admin', 'super_admin']:
                        print(f"DEBUG: Admin user {email}, skipping OTP")
                        # Direct login for admin/super_admin
                        session['user_id'] = user['id']
                        session['email'] = user['email']
                        session['name'] = user['name']
                        session['role'] = user['role']
                        session['department'] = user['department']
                        
                        # Background login notification
                        def bg_login_notification():
                            try:
                                conn = get_db()
                                with conn.cursor() as cursor:
                                    cursor.execute('''
                                        INSERT INTO notifications (user_id, title, message, type, link) 
                                        VALUES (%s, %s, %s, %s, %s)
                                    ''', (user['id'], 'Admin Login', 
                                          f'Admin login from {request.remote_addr}', 
                                          'success', '/dashboard'))
                                    conn.commit()
                                conn.close()
                            except Exception as e:
                                print(f"Admin login notification error: {e}")
                        
                        threading.Thread(target=bg_login_notification, daemon=True).start()
                        
                        if request.is_json:
                            return jsonify({
                                'success': True,
                                'message': 'Login successful!',
                                'redirect': '/dashboard'
                            })
                        else:
                            return redirect('/dashboard')
                    
                    # If not admin/super_admin, proceed to OTP stage
                    elif user and check_password(user['password'], password):
                        print(f"DEBUG: Storing pending login for {email}")
                        # Store pending login for OTP verification
                        session['pending_login'] = {
                            'user_id': user['id'],
                            'email': user['email'],
                            'name': user['name'],
                            'role': user['role'],
                            'department': user['department']
                        }
                        
                        # Generate and send OTP
                        print(f"DEBUG: Generating OTP for {email}")
                        otp_code = store_otp(email, 'login')
                        print(f"DEBUG: OTP generated: {otp_code}")
                        
                        if otp_code:
                            print(f"DEBUG: Sending OTP email to {email}")
                            email_sent = send_otp_email(email, otp_code, 'login')
                            print(f"DEBUG: OTP email sent: {email_sent}")
                        
                        if request.is_json:
                            return jsonify({
                                'success': True,
                                'message': 'OTP sent to your email',
                                'stage': 'otp',
                                'email': email
                            })
                        else:
                            # Show OTP verification form
                            csrf_token = get_csrf_token()
                            content = f'''
                            <!DOCTYPE html>
                            <html lang="en">
                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>OTP Verification - FormMaster Pro</title>
                                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                                <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
                                <style>
                                    body {{
                                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                        min-height: 100vh;
                                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                                        padding-top: 20px;
                                    }}
                                    .otp-card {{
                                        background: rgba(255, 255, 255, 0.95);
                                        border-radius: 20px;
                                        box-shadow: 0 15px 35px rgba(0,0,0,0.2);
                                        padding: 40px;
                                        margin-top: 20px;
                                        border: 1px solid rgba(255, 255, 255, 0.3);
                                    }}
                                </style>
                            </head>
                            <body>
                                <div class="container">
                                    <div class="row justify-content-center">
                                        <div class="col-md-5">
                                            <div class="otp-card">
                                                <h3 class="text-center mb-4 text-dark">
                                                    <i class="fas fa-shield-alt me-2"></i>OTP Verification
                                                </h3>
                                                <p class="text-center text-muted mb-4">
                                                    Enter the 6-digit OTP sent to:<br>
                                                    <strong>{email}</strong>
                                                </p>
                                                
                                                <form method="POST" id="otpForm">
                                                    <input type="hidden" name="csrf_token" value="{csrf_token}">
                                                    <input type="hidden" name="email" value="{email}">
                                                    <input type="hidden" name="login_stage" value="otp">
                                                    
                                                    <div class="mb-4">
                                                        <label class="form-label text-dark text-center d-block">OTP Code</label>
                                                        <input type="text" class="form-control text-center fs-4" name="otp" required 
                                                            maxlength="6" pattern="\\d{{6}}" 
                                                            placeholder="000000" autocomplete="off"
                                                            oninput="this.value = this.value.replace(/[^0-9]/g, '')">
                                                    </div>
                                                    
                                                    <button type="submit" class="btn btn-primary w-100" id="verifyBtn">
                                                        <i class="fas fa-check-circle me-2"></i>Verify OTP
                                                    </button>
                                                </form>
                                                
                                                <div class="mt-3 text-center">
                                                    <button onclick="resendOTP('{email}')" class="btn btn-link">
                                                        <i class="fas fa-redo me-1"></i>Resend OTP
                                                    </button>
                                                    <a href="/login" class="btn btn-link">Back to Login</a>
                                                </div>
                                                
                                                <div class="mt-3 text-center">
                                                    <small class="text-muted" id="countdown"></small>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                
                                <script>
                                    let timeLeft = {OTP_EXPIRY_MINUTES * 60};
                                    
                                    function updateCountdown() {{
                                        const minutes = Math.floor(timeLeft / 60);
                                        const seconds = timeLeft % 60;
                                        document.getElementById('countdown').textContent = 
                                            `OTP expires in: ${{minutes}}:${{seconds.toString().padStart(2, '0')}}`;
                                    }}
                                    
                                    function startCountdown() {{
                                        updateCountdown();
                                        const interval = setInterval(() => {{
                                            timeLeft--;
                                            updateCountdown();
                                            if (timeLeft <= 0) {{
                                                clearInterval(interval);
                                                document.getElementById('countdown').textContent = 'OTP expired!';
                                                document.getElementById('countdown').className = 'text-danger';
                                                document.getElementById('verifyBtn').disabled = true;
                                            }}
                                        }}, 1000);
                                    }}
                                    
                                    function resendOTP(email) {{
                                        fetch('/resend-otp', {{
                                            method: 'POST',
                                            headers: {{
                                                'Content-Type': 'application/json',
                                            }},
                                            body: JSON.stringify({{
                                                email: email,
                                                purpose: 'login'
                                            }})
                                        }})
                                        .then(res => res.json())
                                        .then(data => {{
                                            if (data.success) {{
                                                alert('New OTP sent to your email!');
                                                timeLeft = {OTP_EXPIRY_MINUTES * 60};
                                                document.getElementById('verifyBtn').disabled = false;
                                                startCountdown();
                                            }} else {{
                                                alert('Error: ' + data.error);
                                            }}
                                        }});
                                    }}
                                    
                                    // Auto-focus OTP input and start countdown
                                    document.addEventListener('DOMContentLoaded', function() {{
                                        document.querySelector('input[name="otp"]').focus();
                                        startCountdown();
                                    }});
                                </script>
                            </body>
                            </html>
                            '''
                            return content
                else:
                    print(f"DEBUG: Invalid credentials for {email}")
                    # Invalid credentials
                    csrf_token = get_csrf_token()
                    error_html = f'''
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        Invalid email or password. Please try again.
                    </div>
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <input type="hidden" name="login_stage" value="credentials">
                        <div class="mb-3">
                            <label class="form-label">Email Address</label>
                            <input type="email" class="form-control" name="email" required 
                                   placeholder="your@email.com" value="{email or ''}">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Password</label>
                            <input type="password" class="form-control" name="password" required 
                                   placeholder="••••••••">
                        </div>
                        <button type="submit" class="btn btn-primary w-100 mt-3">
                            Sign In
                        </button>
                    </form>
                    '''
                    
                    if request.is_json:
                        return jsonify({'success': False, 'error': 'Invalid email or password'}), 400
                    else:
                        return html_wrapper('Login', f'''
                        <div class="row justify-content-center">
                            <div class="col-md-5">
                                <div class="login-card">
                                    <h3 class="text-center mb-4">Login</h3>
                                    {error_html}
                                </div>
                            </div>
                        </div>
                        ''', '', '')
            
            # Stage 2: OTP verification
            elif login_stage == 'otp':
                print(f"DEBUG: OTP verification stage for {email}")
                otp = request.form.get('otp', '').strip() if not request.is_json else request.get_json(silent=True, force=True).get('otp', '')
                print(f"DEBUG: OTP received: {otp}")
                
                # Check if we have pending login
                if 'pending_login' not in session:
                    print("DEBUG: No pending login in session")
                    if request.is_json:
                        return jsonify({'success': False, 'error': 'No pending login session'}), 400
                    else:
                        return redirect('/login')
                
                pending_user = session['pending_login']
                
                print(f"DEBUG: Verifying OTP for {email}")
                # Verify OTP
                if verify_otp(email, otp, 'login'):
                    print("DEBUG: OTP verified successfully")
                    # OTP verified, complete login
                    session.pop('pending_login', None)
                    
                    session['user_id'] = pending_user.get('user_id')
                    session['email'] = pending_user.get('email')
                    session['name'] = pending_user.get('name')
                    session['role'] = pending_user.get('role')
                    session['department'] = pending_user.get('department')
                    
                    # Clear login attempts
                    session.pop('login_attempts', None)
                    
                    print(f"DEBUG: Login successful for {email}")
                    
                    # For AJAX requests
                    if request.is_json:
                        return jsonify({
                            'success': True,
                            'message': 'Login successful!',
                            'redirect': '/dashboard'
                        })
                    else:
                        # For form submissions
                        return redirect('/dashboard')
                else:
                    print(f"DEBUG: Invalid OTP for {email}")
                    if request.is_json:
                        return jsonify({'success': False, 'error': 'Invalid or expired OTP'}), 400
                    else:
                        csrf_token = get_csrf_token()
                        return f'''
                        <script>
                            alert("Invalid or expired OTP. Please try again.");
                            window.location.href = "/login?stage=otp&email={email}";
                        </script>
                        '''
            
        except Exception as e:
            print(f"Login error: {e}")
            traceback.print_exc()
            if request.is_json:
                return jsonify({'success': False, 'error': f'Server error: {str(e)}'}), 500
            else:
                csrf_token = get_csrf_token()
                return f'''
                <div class="alert alert-danger">
                    <h4>Login Error</h4>
                    <p>Error: {str(e)}</p>
                    <a href="/login" class="btn btn-primary">Try Again</a>
                </div>
                '''
            

@app.route('/debug/csrf')
def debug_csrf():
    """Debug CSRF tokens"""
    current_token = session.get('csrf_token', 'No token in session')
    return f'''
    <div class="container mt-5">
        <h2>CSRF Token Debug</h2>
        <div class="card">
            <div class="card-body">
                <p><strong>Session CSRF Token:</strong> {current_token}</p>
                <p><strong>Session ID:</strong> {session.sid}</p>
                <p><strong>New CSRF Token:</strong> {get_csrf_token()}</p>
                <form method="POST" action="/debug/csrf-test">
                    <input type="hidden" name="csrf_token" value="{current_token}">
                    <button type="submit" class="btn btn-primary">Test CSRF Validation</button>
                </form>
            </div>
        </div>
    </div>
    '''

@app.route('/debug/csrf-test', methods=['POST'])
def debug_csrf_test():
    csrf_token = request.form.get('csrf_token')
    is_valid = validate_csrf_token(csrf_token)
    return f'''
    <div class="container mt-5">
        <h2>CSRF Test Result</h2>
        <div class="card">
            <div class="card-body">
                <p><strong>Token received:</strong> {csrf_token}</p>
                <p><strong>Session token:</strong> {session.get('csrf_token')}</p>
                <p><strong>Is valid:</strong> {is_valid}</p>
                <a href="/debug/csrf" class="btn btn-primary">Back</a>
            </div>
        </div>
    </div>
    '''

from werkzeug.exceptions import BadRequestKeyError

@app.errorhandler(BadRequestKeyError)
def handle_bad_request_key_error(e):
    """Handle BadRequestKeyError specifically"""
    print(f"BadRequestKeyError caught: {e}")
    print(f"Request method: {request.method}")
    print(f"Content-Type: {request.content_type}")
    print(f"Form data: {dict(request.form)}")
    print(f"JSON data: {request.get_json(silent=True)}")
    
    return jsonify({
        'success': False,
        'error': 'Invalid request format. Please check your input data.',
        'details': str(e)
    }), 400

@app.before_request
def log_request_info():
    """Log request info for debugging"""
    if request.endpoint in ['login', 'verify_otp_endpoint']:
        print(f"\n=== REQUEST DEBUG ===")
        print(f"Endpoint: {request.endpoint}")
        print(f"Method: {request.method}")
        print(f"Content-Type: {request.content_type}")
        print(f"Is JSON: {request.is_json}")
        print(f"Headers: {dict(request.headers)}")
        
        if request.form:
            print(f"Form data: {dict(request.form)}")
        
        if request.get_data():
            print(f"Raw data (first 500 chars): {request.get_data(as_text=True)[:500]}")
        print("=== END DEBUG ===\n")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            # Get form data safely
            name = request.form.get('name', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '').strip()
            role = request.form.get('role', 'student')
            department = request.form.get('department', 'IT')
            otp = request.form.get('otp', '').strip()
            register_stage = request.form.get('register_stage', 'details')
            
            print(f"DEBUG: Registration stage={register_stage}, email={email}")
            print(f"DEBUG: Session pending_registration: {'pending_registration' in session}")
            
            # Stage 1: Check details and send OTP
            if register_stage == 'details':
                print("DEBUG: Stage 1 - Checking details")
                # Check if email already exists
                connection = get_db()
                email_exists = False
                try:
                    with connection.cursor() as cursor:
                        cursor.execute('SELECT id FROM users WHERE email = %s', (email,))
                        if cursor.fetchone():
                            email_exists = True
                finally:
                    connection.close()
                
                if email_exists:
                    print(f"DEBUG: Email {email} already exists")
                    # Return registration form with error
                    departments_options = ''.join([f'<option value="{dept}" {"selected" if dept == department else ""}>{dept}</option>' for dept in DEPARTMENTS])
                    content = f'''
                    <div class="row justify-content-center">
                        <div class="col-md-6">
                            <div class="card glass-effect">
                                <div class="card-body">
                                    <h3 class="text-center mb-4">Register</h3>
                                    <div class="alert alert-danger">
                                        <i class="fas fa-exclamation-triangle me-2"></i>
                                        Email already exists. Please use a different email or login.
                                    </div>
                                    <form method="POST">
                                        <input type="hidden" name="register_stage" value="details">
                                        <div class="mb-3">
                                            <label>Full Name *</label>
                                            <input type="text" class="form-control" name="name" required value="{name}">
                                        </div>
                                        <div class="mb-3">
                                            <label>Email *</label>
                                            <input type="email" class="form-control" name="email" required value="{email}">
                                        </div>
                                        <div class="mb-3">
                                            <label>Password *</label>
                                            <input type="password" class="form-control" name="password" required>
                                        </div>
                                        <div class="mb-3">
                                            <label>Role</label>
                                            <select class="form-select" name="role">
                                                <option value="student" {'selected' if role == 'student' else ''}>Student</option>
                                                <option value="teacher" {'selected' if role == 'teacher' else ''}>Teacher</option>
                                            </select>
                                        </div>
                                        <div class="mb-3">
                                            <label>Department *</label>
                                            <select class="form-select" name="department" required>
                                                <option value="">Select Department</option>
                                                {departments_options}
                                            </select>
                                        </div>
                                        <button type="submit" class="btn btn-primary w-100">
                                            <i class="fas fa-envelope me-2"></i>Send OTP
                                        </button>
                                    </form>
                                    <hr>
                                    <p class="text-center">
                                        <a href="/login">Already have an account? Login</a>
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                    '''
                    return html_wrapper('Register', content, '', '')
                
                # Store registration details in session
                session['pending_registration'] = {
                    'name': name,
                    'email': email,
                    'password': password,
                    'role': role,
                    'department': department
                }
                
                # Generate and send OTP
                print(f"DEBUG: Storing OTP for {email}")
                otp_code = store_otp(email, 'registration')
                print(f"DEBUG: OTP generated: {otp_code}")
                
                if otp_code:
                    print(f"DEBUG: Attempting to send OTP email to {email}")
                    email_sent = send_otp_email(email, otp_code, 'registration')
                    print(f"DEBUG: OTP email sent: {email_sent}")
                
                # Show OTP verification page
                content = f'''
                <div class="row justify-content-center">
                    <div class="col-md-5">
                        <div class="card">
                            <div class="card-header bg-primary text-white">
                                <h4 class="mb-0">Verify Your Email</h4>
                            </div>
                            <div class="card-body">
                                <div class="alert alert-info">
                                    <i class="fas fa-envelope me-2"></i>
                                    OTP sent to: <strong>{email}</strong>
                                </div>
                                
                                <form method="POST">
                                    <input type="hidden" name="email" value="{email}">
                                    <input type="hidden" name="register_stage" value="otp">
                                    
                                    <div class="mb-3">
                                        <label class="form-label">Enter 6-digit OTP *</label>
                                        <input type="text" class="form-control" name="otp" required 
                                               maxlength="6" pattern="\\d{{6}}" 
                                               placeholder="000000" autocomplete="off"
                                               oninput="this.value = this.value.replace(/[^0-9]/g, '')">
                                        <small class="text-muted">Check your email for the 6-digit code</small>
                                    </div>
                                    
                                    <div class="d-grid gap-2">
                                        <button type="submit" class="btn btn-success">
                                            <i class="fas fa-check-circle me-2"></i>Verify & Complete Registration
                                        </button>
                                        <button type="button" onclick="resendOTP('{email}')" class="btn btn-outline-primary">
                                            <i class="fas fa-redo me-2"></i>Resend OTP
                                        </button>
                                        <a href="/register" class="btn btn-outline-secondary">
                                            <i class="fas fa-arrow-left me-2"></i>Back
                                        </a>
                                    </div>
                                </form>
                                
                                <div class="mt-3 text-center">
                                    <small class="text-muted" id="countdown"></small>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <script>
                    let timeLeft = {OTP_EXPIRY_MINUTES * 60};
                    
                    function updateCountdown() {{
                        const minutes = Math.floor(timeLeft / 60);
                        const seconds = timeLeft % 60;
                        document.getElementById('countdown').textContent = 
                            `OTP expires in: ${{minutes}}:${{seconds.toString().padStart(2, '0')}}`;
                    }}
                    
                    function startCountdown() {{
                        updateCountdown();
                        const interval = setInterval(() => {{
                            timeLeft--;
                            updateCountdown();
                            if (timeLeft <= 0) {{
                                clearInterval(interval);
                                document.getElementById('countdown').textContent = 'OTP expired!';
                                document.getElementById('countdown').className = 'text-danger';
                            }}
                        }}, 1000);
                    }}
                    
                    function resendOTP(email) {{
                        fetch('/resend-otp', {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/json',
                            }},
                            body: JSON.stringify({{
                                email: email,
                                purpose: 'registration'
                            }})
                        }})
                        .then(res => res.json())
                        .then(data => {{
                            if (data.success) {{
                                alert('New OTP sent to your email!');
                                timeLeft = {OTP_EXPIRY_MINUTES * 60};
                                startCountdown();
                            }} else {{
                                alert('Error: ' + data.error);
                            }}
                        }})
                        .catch(error => {{
                            alert('Network error: ' + error);
                        }});
                    }}
                    
                    // Start countdown when page loads
                    document.addEventListener('DOMContentLoaded', function() {{
                        document.querySelector('input[name="otp"]').focus();
                        startCountdown();
                    }});
                </script>
                '''
                return html_wrapper('Verify Email', content, '', '')
            
            # Stage 2: OTP verification
            elif register_stage == 'otp':
                print(f"DEBUG: Stage 2 - OTP verification for {email}")
                print(f"DEBUG: OTP provided: {otp}")
                
                # Check if we have pending registration
                if 'pending_registration' not in session:
                    print("DEBUG: No pending registration in session")
                    return redirect('/register')
                
                pending_reg = session['pending_registration']
                
                # Verify OTP
                print(f"DEBUG: Verifying OTP for {email}")
                if verify_otp(email, otp, 'registration'):
                    print("DEBUG: OTP verified successfully")
                    # OTP verified, complete registration
                    hashed = hash_password(pending_reg['password'])
                    connection = get_db()
                    
                    try:
                        with connection.cursor() as cursor:
                            cursor.execute(
                                'INSERT INTO users (name, email, password, role, department) VALUES (%s, %s, %s, %s, %s)',
                                (pending_reg['name'], pending_reg['email'], hashed, pending_reg['role'], pending_reg['department'])
                            )
                            user_id = cursor.lastrowid
                            
                            cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
                            user = cursor.fetchone()
                            
                            connection.commit()
                        
                        # Clear pending registration
                        session.pop('pending_registration', None)
                        
                        # Auto-login after registration
                        session['user_id'] = user['id']
                        session['email'] = user['email']
                        session['name'] = user['name']
                        session['role'] = user['role']
                        session['department'] = user['department']
                        
                        print(f"DEBUG: User {user['email']} registered successfully")
                        
                        # Background registration tasks
                        def bg_registration_tasks():
                            try:
                                # Create welcome notification
                                conn = get_db()
                                with conn.cursor() as cursor:
                                    cursor.execute('''
                                        INSERT INTO notifications (user_id, title, message, type, link) 
                                        VALUES (%s, %s, %s, %s, %s)
                                    ''', (user['id'], 'Welcome to FormMaster Pro!',
                                          f'Your account has been created successfully as a {user["role"]} in the {user["department"]} department.',
                                          'success', '/dashboard'))
                                    conn.commit()
                                conn.close()
                                
                                # Send registration confirmation email
                                if ENABLE_EMAIL_NOTIFICATIONS:
                                    html_content = f'''
                                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                                        <h2 style="color: #667eea;">Welcome to FormMaster Pro!</h2>
                                        <p>Hello {user["name"]},</p>
                                        <p>Your account has been successfully created with OTP verification.</p>
                                        <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 20px 0;">
                                            <p><strong>Account Details:</strong></p>
                                            <p>Name: {user["name"]}</p>
                                            <p>Email: {user["email"]}</p>
                                            <p>Role: {user["role"].title()}</p>
                                            <p>Department: {user["department"]}</p>
                                            <p>Registration Date: {datetime.now().strftime("%%Y-%%m-%%d %%H:%%M:%%S")}</p>
                                            <p><strong>Security:</strong> OTP verification enabled for future logins</p>
                                        </div>
                                        <p>You can now login to your account and start using FormMaster Pro.</p>
                                        <a href="http://{request.host}/dashboard" style="display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">Go to Dashboard</a>
                                        <hr>
                                        <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
                                    </div>
                                    '''
                                    send_email(user['email'], 'Welcome to FormMaster Pro!', html_content)
                                    
                            except Exception as e:
                                print(f"Registration background task error: {e}")
                        
                        threading.Thread(target=bg_registration_tasks, daemon=True).start()
                        
                        # Show success message and redirect
                        return f'''
                        <script>
                            alert('Registration successful! Welcome to FormMaster Pro.');
                            window.location.href = '/dashboard';
                        </script>
                        '''
                        
                    except Exception as e:
                        print(f"Database error during registration: {e}")
                        connection.rollback()
                        return html_wrapper('Error', f'''
                        <div class="alert alert-danger">
                            <h4>Registration Error</h4>
                            <p>Error: {str(e)}</p>
                            <a href="/register" class="btn btn-primary">Try Again</a>
                        </div>
                        ''', '', '')
                    finally:
                        connection.close()
                else:
                    print("DEBUG: Invalid or expired OTP")
                    return f'''
                    <script>
                        alert("Invalid or expired OTP. Please try again.");
                        window.location.href = "/register?stage=otp&email={email}";
                    </script>
                    '''
            
            else:
                return redirect('/register')
                
        except Exception as e:
            print(f"Register error: {e}")
            traceback.print_exc()
            return html_wrapper('Error', f'''
            <div class="alert alert-danger">
                <h4>Registration Error</h4>
                <p>Error: {str(e)}</p>
                <a href="/register" class="btn btn-primary">Try Again</a>
            </div>
            ''', '', '')
    
    # GET request - show appropriate form
    register_stage = request.args.get('stage', 'details')
    email = request.args.get('email', '')
    
    if register_stage == 'otp' and email:
        # Show OTP verification form for registration
        content = f'''
        <div class="row justify-content-center">
            <div class="col-md-5">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h4 class="mb-0">Verify Your Email</h4>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info">
                            <i class="fas fa-envelope me-2"></i>
                            OTP sent to: <strong>{email}</strong>
                        </div>
                        
                        <form method="POST">
                            <input type="hidden" name="email" value="{email}">
                            <input type="hidden" name="register_stage" value="otp">
                            
                            <div class="mb-3">
                                <label class="form-label">Enter 6-digit OTP *</label>
                                <input type="text" class="form-control" name="otp" required 
                                       maxlength="6" pattern="\\d{{6}}" 
                                       placeholder="000000" autocomplete="off"
                                       oninput="this.value = this.value.replace(/[^0-9]/g, '')">
                                <small class="text-muted">Check your email for the 6-digit code</small>
                            </div>
                            
                            <div class="d-grid gap-2">
                                <button type="submit" class="btn btn-success">
                                    <i class="fas fa-check-circle me-2"></i>Verify & Complete Registration
                                </button>
                                <button type="button" onclick="resendOTP('{email}')" class="btn btn-outline-primary">
                                    <i class="fas fa-redo me-2"></i>Resend OTP
                                </button>
                                <a href="/register" class="btn btn-outline-secondary">
                                    <i class="fas fa-arrow-left me-2"></i>Back to Registration
                                </a>
                            </div>
                        </form>
                        
                        <div class="mt-3 text-center">
                            <small class="text-muted" id="countdown"></small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            let timeLeft = {OTP_EXPIRY_MINUTES * 60};
            
            function updateCountdown() {{
                const minutes = Math.floor(timeLeft / 60);
                const seconds = timeLeft % 60;
                document.getElementById('countdown').textContent = 
                    `OTP expires in: ${{minutes}}:${{seconds.toString().padStart(2, '0')}}`;
            }}
            
            function startCountdown() {{
                updateCountdown();
                const interval = setInterval(() => {{
                    timeLeft--;
                    updateCountdown();
                    if (timeLeft <= 0) {{
                        clearInterval(interval);
                        document.getElementById('countdown').textContent = 'OTP expired!';
                        document.getElementById('countdown').className = 'text-danger';
                    }}
                }}, 1000);
            }}
            
            function resendOTP(email) {{
                fetch('/resend-otp', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{
                        email: email,
                        purpose: 'registration'
                    }})
                }})
                .then(res => res.json())
                .then(data => {{
                    if (data.success) {{
                        alert('New OTP sent to your email!');
                        timeLeft = {OTP_EXPIRY_MINUTES * 60};
                        startCountdown();
                    }} else {{
                        alert('Error: ' + data.error);
                    }}
                }})
                .catch(error => {{
                    alert('Network error: ' + error);
                }});
            }}
            
            // Start countdown when page loads
            document.addEventListener('DOMContentLoaded', function() {{
                document.querySelector('input[name="otp"]').focus();
                startCountdown();
            }});
        </script>
        '''
        return html_wrapper('Verify Email', content, '', '')
    
    # Default registration form (details stage)
    departments_options = ''.join([f'<option value="{dept}">{dept}</option>' for dept in DEPARTMENTS])
    
    content = f'''
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">
                    <h4 class="mb-0">Create New Account</h4>
                    <p class="mb-0 text-muted">OTP verification required for security</p>
                </div>
                <div class="card-body">
                    <div class="alert alert-info">
                        <i class="fas fa-shield-alt me-2"></i>
                        <strong>Security Note:</strong> You'll receive an OTP via email to verify your account.
                    </div>
                    
                    <form method="POST">
                        <input type="hidden" name="register_stage" value="details">
                        
                        <div class="mb-3">
                            <label class="form-label">Full Name *</label>
                            <input type="text" class="form-control" name="name" required 
                                   placeholder="Enter your full name">
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Email Address *</label>
                            <input type="email" class="form-control" name="email" required 
                                   placeholder="your@email.com">
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Password *</label>
                            <input type="password" class="form-control" name="password" required 
                                   placeholder="Create a strong password">
                            <small class="text-muted">At least 8 characters with letters and numbers</small>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Role *</label>
                                <select class="form-select" name="role">
                                    <option value="student">Student</option>
                                    <option value="teacher">Teacher</option>
                                </select>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Department *</label>
                                <select class="form-select" name="department" required>
                                    <option value="">Select Department</option>
                                    {departments_options}
                                </select>
                            </div>
                        </div>
                        
                        <div class="form-check mb-4">
                            <input class="form-check-input" type="checkbox" id="terms" required>
                            <label class="form-check-label" for="terms">
                                I agree to the <a href="#" class="text-decoration-none">Terms of Service</a> 
                                and <a href="#" class="text-decoration-none">Privacy Policy</a>
                            </label>
                        </div>
                        
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="fas fa-envelope me-2"></i>Send OTP & Continue
                        </button>
                    </form>
                    
                    <hr class="my-4">
                    
                    <p class="text-center mb-0">
                        <span class="text-muted">Already have an account?</span>
                        <a href="/login" class="text-decoration-none fw-bold ms-1">Login Here</a>
                    </p>
                </div>
            </div>
        </div>
    </div>
    '''
    return html_wrapper('Register', content, '', '')

# Add OTP resend endpoint
@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    """Resend OTP"""
    try:
        data = request.json
        email = data.get('email')
        purpose = data.get('purpose', 'login')
        
        if not email:
            return jsonify({'success': False, 'error': 'Email required'})
        
        # Generate and send new OTP
        otp_code = store_otp(email, purpose)
        if otp_code:
            send_otp_email(email, otp_code, purpose)
            return jsonify({'success': True, 'message': 'OTP sent successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to generate OTP'})
    except Exception as e:
        print(f"Resend OTP error: {e}")
        return jsonify({'success': False, 'error': str(e)})
# Add password reset with OTP
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Password reset with OTP"""
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            otp = request.form.get('otp', '')
            new_password = request.form.get('new_password', '')
            reset_stage = request.form.get('reset_stage', 'request')
            
            # Stage 1: Request OTP
            if reset_stage == 'request':
                # Check if user exists
                connection = get_db()
                user_exists = False
                try:
                    with connection.cursor() as cursor:
                        cursor.execute('SELECT id FROM users WHERE email = %s', (email,))
                        if cursor.fetchone():
                            user_exists = True
                finally:
                    connection.close()
                
                if not user_exists:
                    return '''
                    <script>
                        alert("Email not found in our system.");
                        window.location.href = "/forgot-password";
                    </script>
                    '''
                
                # Store email in session
                session['password_reset_email'] = email
                
                # Generate and send OTP
                otp_code = store_otp(email, 'password_reset')
                if otp_code:
                    send_otp_email(email, otp_code, 'password_reset')
                    
                return f'''
                <script>
                    alert("Password reset OTP sent to your email.");
                    window.location.href = "/forgot-password?stage=verify&email={email}";
                </script>
                '''
            
            # Stage 2: Verify OTP
            elif reset_stage == 'verify':
                email = session.get('password_reset_email', email)
                
                if not email:
                    return redirect('/forgot-password')
                
                if verify_otp(email, otp, 'password_reset'):
                    session['otp_verified'] = True
                    return f'''
                    <script>
                        alert("OTP verified. Please set your new password.");
                        window.location.href = "/forgot-password?stage=reset&email={email}";
                    </script>
                    '''
                else:
                    return f'''
                    <script>
                        alert("Invalid or expired OTP.");
                        window.location.href = "/forgot-password?stage=verify&email={email}";
                    </script>
                    '''
            
            # Stage 3: Reset password
            elif reset_stage == 'reset':
                email = session.get('password_reset_email')
                
                if not email or not session.get('otp_verified'):
                    return redirect('/forgot-password')
                
                if not new_password or len(new_password) < 8:
                    return '''
                    <script>
                        alert("Password must be at least 8 characters.");
                        window.location.href = "/forgot-password?stage=reset";
                    </script>
                    '''
                
                # Update password
                hashed = hash_password(new_password)
                connection = get_db()
                try:
                    with connection.cursor() as cursor:
                        cursor.execute('UPDATE users SET password = %s WHERE email = %s', (hashed, email))
                        connection.commit()
                    
                    # Clear session
                    session.pop('password_reset_email', None)
                    session.pop('otp_verified', None)
                    
                    # Send confirmation email
                    if ENABLE_EMAIL_NOTIFICATIONS:
                        html_content = f'''
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #10b981;">Password Reset Successful</h2>
                            <p>Your password has been successfully reset.</p>
                            <div style="background: #f0f9ff; padding: 15px; border-radius: 10px; margin: 20px 0;">
                                <p><strong>Reset Details:</strong></p>
                                <p>Email: {email}</p>
                                <p>Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                            </div>
                            <p>If you didn't request this password reset, please contact support immediately.</p>
                        </div>
                        '''
                        send_email(email, 'Password Reset Successful - FormMaster Pro', html_content)
                    
                    return '''
                    <script>
                        alert("Password reset successful! You can now login with your new password.");
                        window.location.href = "/login";
                    </script>
                    '''
                    
                except Exception as e:
                    print(f"Password reset error: {e}")
                    return '''
                    <script>
                        alert("Error resetting password. Please try again.");
                        window.location.href = "/forgot-password";
                    </script>
                    '''
                finally:
                    connection.close()
            
        except Exception as e:
            print(f"Forgot password error: {e}")
            return '''
            <script>
                alert("Error processing request. Please try again.");
                window.location.href = "/forgot-password";
            </script>
            '''
    
    # GET request
    reset_stage = request.args.get('stage', 'request')
    email = request.args.get('email', '')
    
    if reset_stage == 'verify':
        content = f'''
        <div class="row justify-content-center">
            <div class="col-md-5">
                <div class="card">
                    <div class="card-header bg-warning">
                        <h4 class="mb-0">Verify OTP</h4>
                    </div>
                    <div class="card-body">
                        <p class="text-muted">Enter the OTP sent to: <strong>{email}</strong></p>
                        
                        <form method="POST">
                            <input type="hidden" name="reset_stage" value="verify">
                            <input type="hidden" name="email" value="{email}">
                            
                            <div class="mb-3">
                                <label class="form-label">OTP Code</label>
                                <input type="text" class="form-control" name="otp" required 
                                       maxlength="6" placeholder="000000">
                            </div>
                            
                            <div class="d-grid gap-2">
                                <button type="submit" class="btn btn-primary">Verify OTP</button>
                                <button type="button" onclick="resendPasswordResetOTP('{email}')" class="btn btn-outline-secondary">
                                    Resend OTP
                                </button>
                                <a href="/forgot-password" class="btn btn-outline-danger">Cancel</a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            function resendPasswordResetOTP(email) {{
                fetch('/resend-otp', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{
                        email: email,
                        purpose: 'password_reset'
                    }})
                }})
                .then(res => res.json())
                .then(data => {{
                    if (data.success) {{
                        alert('New OTP sent!');
                    }} else {{
                        alert('Error: ' + data.error);
                    }}
                }});
            }}
        </script>
        '''
        return html_wrapper('Verify OTP', content, '', '')
    
    elif reset_stage == 'reset':
        content = f'''
        <div class="row justify-content-center">
            <div class="col-md-5">
                <div class="card">
                    <div class="card-header bg-success text-white">
                        <h4 class="mb-0">Set New Password</h4>
                    </div>
                    <div class="card-body">
                        <p class="text-muted">For: <strong>{email}</strong></p>
                        
                        <form method="POST">
                            <input type="hidden" name="reset_stage" value="reset">
                            <input type="hidden" name="email" value="{email}">
                            
                            <div class="mb-3">
                                <label class="form-label">New Password</label>
                                <input type="password" class="form-control" name="new_password" required 
                                       minlength="8" placeholder="Enter new password">
                                <small class="text-muted">Minimum 8 characters</small>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">Confirm Password</label>
                                <input type="password" class="form-control" name="confirm_password" required 
                                       placeholder="Confirm new password">
                            </div>
                            
                            <div class="d-grid gap-2">
                                <button type="submit" class="btn btn-success">Reset Password</button>
                                <a href="/login" class="btn btn-outline-secondary">Back to Login</a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            // Password confirmation validation
            document.querySelector('form').addEventListener('submit', function(e) {{
                const password = document.querySelector('input[name="new_password"]').value;
                const confirm = document.querySelector('input[name="confirm_password"]').value;
                
                if (password !== confirm) {{
                    e.preventDefault();
                    alert('Passwords do not match!');
                }}
            }});
        </script>
        '''
        return html_wrapper('Reset Password', content, '', '')
    
    # Default: Request password reset
    content = '''
    <div class="row justify-content-center">
        <div class="col-md-5">
            <div class="card">
                <div class="card-header">
                    <h4 class="mb-0">Forgot Password</h4>
                </div>
                <div class="card-body">
                    <div class="alert alert-info">
                        <i class="fas fa-key me-2"></i>
                        Enter your email to receive a password reset OTP.
                    </div>
                    
                    <form method="POST">
                        <input type="hidden" name="reset_stage" value="request">
                        
                        <div class="mb-3">
                            <label class="form-label">Email Address</label>
                            <input type="email" class="form-control" name="email" required 
                                   placeholder="your@email.com">
                        </div>
                        
                        <div class="d-grid gap-2">
                            <button type="submit" class="btn btn-primary">Send Reset OTP</button>
                            <a href="/login" class="btn btn-outline-secondary">Back to Login</a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
    '''
    return html_wrapper('Forgot Password', content, '', '')

# Add admin-only direct user creation (without OTP)
@app.route('/admin/create-user', methods=['GET', 'POST'])
@admin_required
def admin_create_user():
    """Admin-only user creation (no OTP required)"""
    if request.method == 'POST':
        try:
            name = request.form['name']
            email = request.form['email']
            password = request.form['password']
            role = request.form['role']
            department = request.form['department']
            
            # Check if email exists
            connection = get_db()
            try:
                with connection.cursor() as cursor:
                    cursor.execute('SELECT id FROM users WHERE email = %s', (email,))
                    if cursor.fetchone():
                        connection.close()
                        return jsonify({'success': False, 'error': 'Email already exists'})
                    
                    hashed = hash_password(password)
                    cursor.execute(
                        'INSERT INTO users (name, email, password, role, department) VALUES (%s, %s, %s, %s, %s)',
                        (name, email, hashed, role, department)
                    )
                    user_id = cursor.lastrowid
                    
                    connection.commit()
                    
                    # Create notification for admin
                    create_notification(
                        user_id=session['user_id'],
                        title='User Created',
                        message=f'Created user {name} ({email}) as {role}',
                        type='success',
                        link='/admin'
                    )
                    
                    # Send welcome email to new user
                    if ENABLE_EMAIL_NOTIFICATIONS:
                        html_content = f'''
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #667eea;">Account Created by Administrator</h2>
                            <p>Hello {name},</p>
                            <p>Your account has been created by an administrator.</p>
                            <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 20px 0;">
                                <p><strong>Account Details:</strong></p>
                                <p>Name: {name}</p>
                                <p>Email: {email}</p>
                                <p>Role: {role.title()}</p>
                                <p>Department: {department}</p>
                                <p>Created By: {session['name']}</p>
                            </div>
                            <p>You can now login to your account.</p>
                            <a href="https://formmaster.up.railway.app/login" style="display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">Login Now</a>
                            <p><strong>Note:</strong> { 'You will need OTP verification for login.' if role in ['student', 'teacher'] else 'Admin accounts can login directly without OTP.'}</p>
                        </div>
                        '''
                        send_email(email, 'Account Created - FormMaster Pro', html_content)
                    
                    return jsonify({'success': True, 'message': 'User created successfully'})
                    
            finally:
                connection.close()
                
        except Exception as e:
            print(f"Admin create user error: {e}")
            return jsonify({'success': False, 'error': str(e)})
    
    # GET request - show form
    departments_options = ''.join([f'<option value="{dept}">{dept}</option>' for dept in DEPARTMENTS])
    
    content = f'''
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header bg-primary text-white">
                    <h4 class="mb-0">
                        <i class="fas fa-user-plus me-2"></i>Create User (Admin)
                    </h4>
                    <p class="mb-0">Direct user creation - No OTP required</p>
                </div>
                <div class="card-body">
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        <strong>Admin Only:</strong> Users created here can login directly.
                        { 'Non-admin users will still need OTP for future logins.'}
                    </div>
                    
                    <form id="createUserForm">
                        <div class="mb-3">
                            <label class="form-label">Full Name *</label>
                            <input type="text" class="form-control" name="name" required>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Email *</label>
                            <input type="email" class="form-control" name="email" required>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Password *</label>
                            <input type="password" class="form-control" name="password" required minlength="8">
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Role *</label>
                                <select class="form-select" name="role" required>
                                    <option value="student">Student</option>
                                    <option value="teacher">Teacher</option>
                                    <option value="admin">Admin</option>
                                    <option value="super_admin">Super Admin</option>
                                </select>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Department *</label>
                                <select class="form-select" name="department" required>
                                    <option value="">Select Department</option>
                                    {departments_options}
                                </select>
                            </div>
                        </div>
                        
                        <div class="d-grid gap-2">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-save me-2"></i>Create User
                            </button>
                            <a href="/admin" class="btn btn-secondary">Back to Admin Panel</a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        $('#createUserForm').submit(function(e) {{
            e.preventDefault();
            
            const formData = $(this).serialize();
            
            $.ajax({{
                url: '/admin/create-user',
                type: 'POST',
                data: formData,
                beforeSend: function() {{
                    $('button[type="submit"]').prop('disabled', true).html('<i class="fas fa-spinner fa-spin me-2"></i>Creating...');
                }},
                success: function(response) {{
                    if (response.success) {{
                        alert('User created successfully!');
                        window.location.href = '/admin';
                    }} else {{
                        alert('Error: ' + response.error);
                        $('button[type="submit"]').prop('disabled', false).html('<i class="fas fa-save me-2"></i>Create User');
                    }}
                }},
                error: function() {{
                    alert('Network error. Please try again.');
                    $('button[type="submit"]').prop('disabled', false).html('<i class="fas fa-save me-2"></i>Create User');
                }}
            }});
        }});
    </script>
    '''
    return html_wrapper('Create User', content, get_navbar(), '')

# Add to admin panel a link to create users
# Update the admin_panel route to include a "Create User" button
# Add this in the admin_panel function's content, in the "Quick Actions" section:
'''
<div class="col-md-3 mb-3">
    <a href="/admin/create-user" class="btn btn-outline-success w-100">
        <i class="fas fa-user-plus me-2"></i>Create User
    </a>
</div>
'''

# Add cleanup job for expired OTPs (optional, can be run periodically)
def cleanup_expired_otps():
    """Clean up expired OTPs"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('DELETE FROM otps WHERE expires_at < NOW()')
            connection.commit()
        connection.close()
        print(f"Cleaned up expired OTPs at {datetime.now()}")
    except Exception as e:
        print(f"Error cleaning up OTPs: {e}")

# Schedule cleanup job (optional)
import schedule
import time

def run_scheduler():
    """Run scheduled jobs in background"""
    schedule.every(1).hours.do(cleanup_expired_otps)
    while True:
        schedule.run_pending()
        time.sleep(60)

# Start scheduler in background thread
scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
scheduler_thread.start()

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get selected department from query parameter or session
        selected_dept = request.args.get('department', '')
        
        connection = get_db()
        user_dept = session['department']
        user_id = session['user_id']
        user_role = session['role']
        
        with connection.cursor() as cursor:
            # Get department filter for admin/teacher
            dept_filter = ''
            params = []
            
            if user_role in ['admin', 'super_admin']:
                if selected_dept:
                    dept_filter = 'AND f.department = %s'
                    params.append(selected_dept)
                else:
                    dept_filter = ''
            elif user_role == 'teacher':
                dept_filter = 'AND f.department = %s'
                params.append(user_dept)
            
            # Get forms based on user role and department
            if user_role in ['admin', 'super_admin']:
                cursor.execute(f'''
                    SELECT f.*, u.name as creator_name, u.department as creator_department,
                           (SELECT COUNT(*) FROM responses WHERE form_id = f.id) as response_count,
                           (SELECT COUNT(*) FROM assignments WHERE form_id = f.id) as assignment_count
                    FROM forms f 
                    JOIN users u ON f.created_by = u.id 
                    WHERE (f.is_student_submission = FALSE OR f.review_status = 'approved')
                    {dept_filter}
                    ORDER BY f.created_at DESC
                ''', params)
                forms = cursor.fetchall()
            elif user_role == 'teacher':
                cursor.execute(f'''
                    SELECT f.*, u.name as creator_name,
                           (SELECT COUNT(*) FROM responses WHERE form_id = f.id) as response_count,
                           (SELECT COUNT(*) FROM assignments WHERE form_id = f.id) as assignment_count
                    FROM forms f 
                    JOIN users u ON f.created_by = u.id 
                    WHERE (f.is_student_submission = FALSE OR f.review_status = 'approved')
                    {dept_filter}
                    ORDER BY f.created_at DESC
                ''', params)
                forms = cursor.fetchall()
            else:
                # Students only see forms from their department
                cursor.execute(f'''
                    SELECT f.*, u.name as creator_name,
                           (SELECT status FROM form_requests WHERE form_id = f.id AND student_id = %s) as request_status,
                           (SELECT 1 FROM assignments WHERE form_id = f.id AND student_id = %s) as is_assigned,
                           (SELECT 1 FROM responses WHERE form_id = f.id AND student_id = %s) as has_submitted,
                           (SELECT COUNT(*) FROM responses WHERE form_id = f.id) as response_count
                    FROM forms f 
                    JOIN users u ON f.created_by = u.id 
                    WHERE f.department = %s 
                    AND (f.form_type = 'public' OR f.form_type = 'open')
                    AND (f.is_student_submission = FALSE OR f.review_status = 'approved')
                    ORDER BY f.created_at DESC
                ''', (user_id, user_id, user_id, user_dept))
                forms = cursor.fetchall()
            
            # Get assigned forms for students
            assigned_forms = []
            if user_role == 'student':
                cursor.execute('''
                    SELECT f.*, u.name as creator_name, a.due_date, a.is_completed
                    FROM assignments a
                    JOIN forms f ON a.form_id = f.id
                    JOIN users u ON f.created_by = u.id
                    WHERE a.student_id = %s
                    ORDER BY a.due_date, a.assigned_at DESC
                ''', (user_id,))
                assigned_forms = cursor.fetchall()
            
            # Get pending requests count for teachers/admin
            pending_requests_count = 0
            if user_role in ['teacher', 'admin', 'super_admin']:
                if user_role in ['admin', 'super_admin']:
                    cursor.execute('''
                        SELECT COUNT(*) as count FROM form_requests WHERE status = 'pending'
                    ''')
                else:
                    cursor.execute('''
                        SELECT COUNT(*) as count 
                        FROM form_requests fr
                        JOIN forms f ON fr.form_id = f.id
                        WHERE f.created_by = %s AND fr.status = 'pending'
                    ''', (user_id,))
                pending_requests_count = cursor.fetchone()['count']
            
            # Get pending reviews count for teachers/admin
            pending_reviews_count = 0
            if user_role in ['teacher', 'admin', 'super_admin']:
                if user_role in ['admin', 'super_admin']:
                    if selected_dept:
                        cursor.execute('''
                            SELECT COUNT(*) as count FROM forms 
                            WHERE is_student_submission = TRUE 
                            AND review_status = 'pending'
                            AND department = %s
                        ''', (selected_dept,))
                    else:
                        cursor.execute('''
                            SELECT COUNT(*) as count FROM forms 
                            WHERE is_student_submission = TRUE 
                            AND review_status = 'pending'
                        ''')
                else:
                    cursor.execute('''
                        SELECT COUNT(*) as count FROM forms 
                        WHERE is_student_submission = TRUE 
                            AND review_status = 'pending'
                            AND department = %s
                    ''', (user_dept,))
                pending_reviews_count = cursor.fetchone()['count']
            
            # Get pending download requests count for teachers/admin
            pending_downloads_count = 0
            if user_role in ['teacher', 'admin', 'super_admin']:
                if user_role in ['admin', 'super_admin']:
                    cursor.execute('''
                        SELECT COUNT(*) as count FROM response_downloads rd
                        JOIN forms f ON rd.form_id = f.id
                        WHERE rd.access_granted = FALSE
                    ''')
                else:
                    cursor.execute('''
                        SELECT COUNT(*) as count FROM response_downloads rd
                        JOIN forms f ON rd.form_id = f.id
                        WHERE rd.access_granted = FALSE AND f.created_by = %s
                    ''', (user_id,))
                pending_downloads_count = cursor.fetchone()['count']
            
            # Get department statistics for admin
            dept_stats = {}
            if user_role in ['admin', 'super_admin']:
                cursor.execute('''
                    SELECT department, 
                           COUNT(*) as form_count,
                           SUM(CASE WHEN is_student_submission = TRUE THEN 1 ELSE 0 END) as student_forms,
                           SUM(CASE WHEN review_status = 'approved' THEN 1 ELSE 0 END) as approved_forms,
                           SUM(CASE WHEN is_published = TRUE THEN 1 ELSE 0 END) as published_forms,
                           COUNT(DISTINCT created_by) as active_teachers
                    FROM forms 
                    GROUP BY department
                ''')
                dept_stats = cursor.fetchall()
            
            # Student statistics
            student_stats = {}
            if user_role == 'student':
                cursor.execute('''
                    SELECT 
                        COUNT(*) as total_forms_taken,
                        AVG(percentage) as avg_score,
                        SUM(CASE WHEN percentage >= 70 THEN 1 ELSE 0 END) as passed_forms,
                        SUM(CASE WHEN percentage < 70 THEN 1 ELSE 0 END) as failed_forms,
                        MAX(percentage) as highest_score,
                        MIN(percentage) as lowest_score
                    FROM responses 
                    WHERE student_id = %s
                ''', (user_id,))
                student_stats = cursor.fetchone()
                
                cursor.execute('''
                    SELECT COUNT(*) as pending_submissions 
                    FROM forms 
                    WHERE created_by = %s 
                    AND is_student_submission = TRUE 
                    AND review_status = 'pending'
                ''', (user_id,))
                pending_subs = cursor.fetchone()
                student_stats['pending_submissions'] = pending_subs['pending_submissions'] if pending_subs else 0
                
                # Get pending download requests count for student
                cursor.execute('''
                    SELECT COUNT(*) as pending_downloads
                    FROM response_downloads rd
                    JOIN responses r ON rd.response_id = r.id
                    WHERE r.student_id = %s AND rd.access_granted = FALSE
                ''', (user_id,))
                pending_dls = cursor.fetchone()
                student_stats['pending_downloads'] = pending_dls['pending_downloads'] if pending_dls else 0
                
                # Get granted downloads count for student
                cursor.execute('''
                    SELECT COUNT(*) as granted_downloads
                    FROM response_downloads rd
                    JOIN responses r ON rd.response_id = r.id
                    WHERE r.student_id = %s AND rd.access_granted = TRUE
                ''', (user_id,))
                granted_dls = cursor.fetchone()
                student_stats['granted_downloads'] = granted_dls['granted_downloads'] if granted_dls else 0
            
            # Teacher statistics
            teacher_stats = {}
            if user_role in ['teacher', 'admin', 'super_admin']:
                if user_role in ['admin', 'super_admin']:
                    cursor.execute('''
                        SELECT 
                            COUNT(DISTINCT f.id) as total_forms,
                            COUNT(DISTINCT r.id) as total_responses,
                            AVG(r.percentage) as avg_score,
                            COUNT(DISTINCT CASE WHEN f.is_student_submission = TRUE THEN f.id END) as student_forms,
                            COUNT(DISTINCT a.id) as total_assignments
                        FROM forms f
                        LEFT JOIN responses r ON f.id = r.form_id
                        LEFT JOIN assignments a ON f.id = a.form_id
                        WHERE f.created_by = %s OR 1=1
                    ''', (user_id,))
                else:
                    cursor.execute('''
                        SELECT 
                            COUNT(DISTINCT f.id) as total_forms,
                            COUNT(DISTINCT r.id) as total_responses,
                            AVG(r.percentage) as avg_score,
                            COUNT(DISTINCT CASE WHEN f.is_student_submission = TRUE THEN f.id END) as student_forms,
                            COUNT(DISTINCT a.id) as total_assignments
                        FROM forms f
                        LEFT JOIN responses r ON f.id = r.form_id
                        LEFT JOIN assignments a ON f.id = a.form_id
                        WHERE f.created_by = %s
                    ''', (user_id,))
                teacher_stats = cursor.fetchone()
            
            # Recent activities
            recent_activities = []
            if user_role in ['admin', 'super_admin']:
                cursor.execute('''
                    (SELECT 
                        'form_created' as type,
                        f.title as description,
                        u.name as user_name,
                        f.created_at as timestamp,
                        CONCAT('/form/', f.id, '/edit') as link
                    FROM forms f
                    JOIN users u ON f.created_by = u.id
                    ORDER BY f.created_at DESC
                    LIMIT 3)
                    
                    UNION ALL
                    
                    (SELECT 
                        'response_submitted' as type,
                        CONCAT('Submitted: ', f.title) as description,
                        u.name as user_name,
                        r.submitted_at as timestamp,
                        CONCAT('/form/', f.id, '/responses') as link
                    FROM responses r
                    JOIN forms f ON r.form_id = f.id
                    JOIN users u ON r.student_id = u.id
                    ORDER BY r.submitted_at DESC
                    LIMIT 3)
                    
                    UNION ALL
                    
                    (SELECT 
                        'download_requested' as type,
                        CONCAT('Download: ', f.title) as description,
                        u.name as user_name,
                        rd.created_at as timestamp,
                        CONCAT('/form/', f.id, '/response-downloads') as link
                    FROM response_downloads rd
                    JOIN responses r ON rd.response_id = r.id
                    JOIN forms f ON r.form_id = f.id
                    JOIN users u ON rd.student_id = u.id
                    WHERE rd.access_granted = FALSE
                    ORDER BY rd.created_at DESC
                    LIMIT 3)
                    
                    ORDER BY timestamp DESC
                    LIMIT 5
                ''')
            elif user_role == 'teacher':
                cursor.execute('''
                    (SELECT 
                        'response_submitted' as type,
                        CONCAT('Submitted: ', f.title) as description,
                        u.name as user_name,
                        r.submitted_at as timestamp,
                        CONCAT('/form/', f.id, '/responses') as link
                    FROM responses r
                    JOIN forms f ON r.form_id = f.id
                    JOIN users u ON r.student_id = u.id
                    WHERE f.created_by = %s
                    ORDER BY r.submitted_at DESC
                    LIMIT 3)
                    
                    UNION ALL
                    
                    (SELECT 
                        'download_requested' as type,
                        CONCAT('Download: ', f.title) as description,
                        u.name as user_name,
                        rd.created_at as timestamp,
                        CONCAT('/form/', f.id, '/response-downloads') as link
                    FROM response_downloads rd
                    JOIN responses r ON rd.response_id = r.id
                    JOIN forms f ON r.form_id = f.id
                    JOIN users u ON rd.student_id = u.id
                    WHERE f.created_by = %s AND rd.access_granted = FALSE
                    ORDER BY rd.created_at DESC
                    LIMIT 3)
                    
                    UNION ALL
                    
                    (SELECT 
                        'form_requested' as type,
                        CONCAT('Access: ', f.title) as description,
                        u.name as user_name,
                        fr.requested_at as timestamp,
                        '/form-requests' as link
                    FROM form_requests fr
                    JOIN forms f ON fr.form_id = f.id
                    JOIN users u ON fr.student_id = u.id
                    WHERE f.created_by = %s AND fr.status = 'pending'
                    ORDER BY fr.requested_at DESC
                    LIMIT 3)
                    
                    ORDER BY timestamp DESC
                    LIMIT 5
                ''', (user_id, user_id, user_id))
            elif user_role == 'student':
                cursor.execute('''
                    (SELECT 
                        'response_submitted' as type,
                        CONCAT('Submitted: ', f.title) as description,
                        'You' as user_name,
                        r.submitted_at as timestamp,
                        '/my-responses' as link
                    FROM responses r
                    JOIN forms f ON r.form_id = f.id
                    WHERE r.student_id = %s
                    ORDER BY r.submitted_at DESC
                    LIMIT 3)
                    
                    UNION ALL
                    
                    (SELECT 
                        'download_granted' as type,
                        CONCAT('Download ready: ', f.title) as description,
                        'System' as user_name,
                        rd.granted_at as timestamp,
                        '/my-responses/downloads' as link
                    FROM response_downloads rd
                    JOIN responses r ON rd.response_id = r.id
                    JOIN forms f ON r.form_id = f.id
                    WHERE r.student_id = %s AND rd.access_granted = TRUE
                    ORDER BY rd.granted_at DESC
                    LIMIT 3)
                    
                    ORDER BY timestamp DESC
                    LIMIT 5
                ''', (user_id, user_id))
            recent_activities = cursor.fetchall()
        
        connection.close()
        
        # Department filter for admin/teacher
        dept_filter_html = ''
        if user_role in ['admin', 'super_admin', 'teacher']:
            departments_options = '<option value="">All Departments</option>' if user_role in ['admin', 'super_admin'] else f'<option value="{user_dept}" selected>{user_dept} (Current)</option>'
            
            if user_role in ['admin', 'super_admin']:
                for dept in DEPARTMENTS:
                    selected = 'selected' if dept == selected_dept else ''
                    departments_options += f'<option value="{dept}" {selected}>{dept}</option>'
            
            dept_filter_html = f'''
            <div class="dept-filter mb-4">
                <h5 class="mb-3">Department Filter</h5>
                <form method="GET" action="/dashboard" class="row align-items-center">
                    <div class="col-md-4">
                        <select class="form-select" name="department" onchange="this.form.submit()">
                            {departments_options}
                        </select>
                    </div>
                    <div class="col-md-8">
                        <small class="text-muted">
                            {f'Showing forms from: {selected_dept if selected_dept else "All Departments"}' if user_role in ['admin', 'super_admin'] else f'Showing forms from your department: {user_dept}'}
                        </small>
                    </div>
                </form>
            </div>
            '''
        
        # Department statistics for admin
        dept_stats_html = ''
        if user_role in ['admin', 'super_admin'] and not selected_dept:
            dept_stats_html = '''
            <div class="dept-stats mb-4">
                <h5 class="mb-3">Department-wise Form Statistics</h5>
                <div class="row">
            '''
            for stat in dept_stats:
                dept_stats_html += f'''
                <div class="col-md-3 mb-3">
                    <div class="card">
                        <div class="card-body text-center">
                            <h6>{stat['department']}</h6>
                            <h4>{stat['form_count']}</h4>
                            <small class="text-muted">
                                Teachers: {stat['active_teachers']}<br>
                                Student Forms: {stat['student_forms']}<br>
                                Published: {stat['published_forms']}
                            </small>
                            <div class="mt-2">
                                <a href="/dashboard?department={stat['department']}" class="btn btn-sm btn-outline-primary">
                                    View Forms
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
                '''
            dept_stats_html += '</div></div>'
        
        # Render forms
        forms_html = ''
        for form in forms:
            status_badge = 'badge-success' if form['is_published'] else 'badge-warning'
            status_text = 'Published' if form['is_published'] else 'Draft'
            type_badge = 'badge-info' if form['form_type'] == 'open' else 'badge-success' if form['form_type'] == 'public' else 'badge-purple'
            type_text = 'Open' if form['form_type'] == 'open' else 'Public' if form['form_type'] == 'public' else 'Confidential'
            
            # Check if it's a student submission
            student_badge = ''
            if form.get('is_student_submission'):
                if form.get('review_status') == 'approved':
                    student_badge = '<span class="badge student-stats-card"><i class="fas fa-user-graduate"></i> Student Created</span>'
                elif form.get('review_status') == 'pending':
                    student_badge = '<span class="badge bg-warning"><i class="fas fa-clock"></i> Under Review</span>'
                else:
                    student_badge = '<span class="badge bg-danger"><i class="fas fa-times"></i> Rejected</span>'
            
            # Get creator info
            creator_info = f'<i class="fas fa-user me-1"></i>{form["creator_name"]}'
            
            # For students, check request status and access
            request_status = form.get('request_status')
            is_assigned = form.get('is_assigned')
            has_submitted = form.get('has_submitted')
            
            # Check if user can edit/view responses
            edit_button = ''
            results_button = ''
            assign_button = ''
            share_button = ''
            delete_button = ''
            publish_button = ''
            student_actions = ''
            
            if form['created_by'] == user_id or user_role in ['teacher', 'admin', 'super_admin']:
                edit_button = f'<a href="/form/{form["id"]}/edit" class="btn btn-sm btn-outline-primary"><i class="fas fa-edit"></i> Edit</a>'
                results_button = f'<a href="/form/{form["id"]}/responses" class="btn btn-sm btn-outline-success"><i class="fas fa-chart-bar"></i> Results</a>'
            
            if user_role in ['teacher', 'admin', 'super_admin']:
                assign_button = f'<a href="/form/{form["id"]}/assign" class="btn btn-sm btn-outline-warning"><i class="fas fa-user-plus"></i> Assign</a>'
                share_button = f'<a href="/form/{form["id"]}/share" class="btn btn-sm btn-outline-info"><i class="fas fa-share-alt"></i> Share</a>'
            
            # Super admin delete button
            if user_role == 'super_admin':
                delete_button = f'''
                <button onclick="deleteForm({form['id']}, '{form['title']}')" class="btn btn-sm btn-outline-danger">
                    <i class="fas fa-trash"></i> Delete
                </button>
                '''
            
            # Publish/Unpublish button for admin/super_admin
            if user_role in ['admin', 'super_admin']:
                publish_text = 'Unpublish' if form['is_published'] else 'Publish'
                publish_icon = 'fa-eye-slash' if form['is_published'] else 'fa-eye'
                publish_class = 'outline-warning' if form['is_published'] else 'outline-success'
                # Disable publish button for unapproved student forms
                if form.get('is_student_submission') and form.get('review_status') != 'approved':
                    publish_button = f'''
                    <button class="btn btn-sm btn-outline-secondary" disabled title="Student forms must be approved before publishing">
                        <i class="fas {publish_icon}"></i> {publish_text}
                    </button>
                    '''
                else:
                    publish_button = f'''
                    <button onclick="togglePublish({form['id']}, {form['is_published']}, '{form['title']}')" 
                            class="btn btn-sm btn-{publish_class}">
                        <i class="fas {publish_icon}"></i> {publish_text}
                    </button>
                    '''
            
            # Student actions for taking forms
            if user_role == 'student':
                if has_submitted:
                    # Check download access for submitted forms
                    connection = get_db()
                    with connection.cursor() as cursor:
                        cursor.execute('''
                            SELECT r.id as response_id, rd.access_granted, f.form_type
                            FROM responses r
                            LEFT JOIN response_downloads rd ON r.id = rd.response_id AND rd.student_id = %s
                            JOIN forms f ON r.form_id = f.id
                            WHERE r.form_id = %s AND r.student_id = %s
                        ''', (user_id, form['id'], user_id))
                        response_info = cursor.fetchone()
                    connection.close()
                    
                    if response_info:
                        if response_info['form_type'] == 'public' or response_info['access_granted']:
                            student_actions = f'''
                            <a href="/my-responses/downloads" class="btn btn-sm btn-success">
                                <i class="fas fa-download"></i> Download
                            </a>
                            '''
                        else:
                            student_actions = f'''
                            <button onclick="requestDownloadByForm({form['id']})" class="btn btn-sm btn-outline-warning">
                                <i class="fas fa-paper-plane"></i> Request Download
                            </button>
                            '''
                    else:
                        student_actions = '<span class="badge bg-success"><i class="fas fa-check"></i> Submitted</span>'
                elif is_assigned:
                    student_actions = f'<a href="/form/{form["id"]}/take" class="btn btn-sm btn-primary"><i class="fas fa-play"></i> Start</a>'
                elif request_status == 'approved':
                    student_actions = f'<a href="/form/{form["id"]}/take" class="btn btn-sm btn-primary"><i class="fas fa-play"></i> Take Test</a>'
                elif request_status == 'pending':
                    student_actions = '<span class="badge bg-warning"><i class="fas fa-clock"></i> Request Pending</span>'
                elif request_status == 'rejected':
                    student_actions = '<span class="badge bg-danger"><i class="fas fa-times"></i> Request Rejected</span>'
                else:
                    # Check if form is public
                    if form['form_type'] == 'public':
                        student_actions = f'<a href="/form/{form["id"]}/take" class="btn btn-sm btn-success"><i class="fas fa-play"></i> Take Public Test</a>'
                    else:
                        student_actions = f'<button onclick="requestForm({form["id"]})" class="btn btn-sm btn-outline-purple"><i class="fas fa-hand-paper"></i> Request Access</button>'
            
            # For admin, show creator's department
            dept_info = f'<i class="fas fa-building me-1"></i>{form["department"]}'
            if user_role in ['admin', 'super_admin'] and 'creator_department' in form:
                dept_info = f'<i class="fas fa-building me-1"></i>{form["department"]} (Creator Dept: {form["creator_department"]})'
            
            # Response and assignment counts
            stats_info = ''
            if form.get('response_count') is not None or form.get('assignment_count') is not None:
                stats_info = f'<small class="text-muted d-block mt-1">'
                if form.get('response_count') is not None:
                    stats_info += f'<i class="fas fa-paper-plane me-1"></i>{form["response_count"]} responses'
                if form.get('assignment_count') is not None:
                    stats_info += f' | <i class="fas fa-tasks me-1"></i>{form["assignment_count"]} assigned'
                stats_info += '</small>'
            
            forms_html += f'''
            <div class="card mb-3 {'student-form-card' if form.get('is_student_submission') else ''}">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <h5 class="mb-1">{form['title']} {student_badge}</h5>
                            <p class="text-muted mb-2">{form['description'][:100] if form['description'] else 'No description'}...</p>
                            <small class="text-muted">
                                {creator_info} |
                                {dept_info} |
                                <span class="badge {type_badge}">{type_text}</span>
                            </small>
                            {stats_info}
                        </div>
                        <span class="badge {status_badge}">{status_text}</span>
                    </div>
                    <div class="form-actions mt-3">
                        {student_actions}
                        {edit_button}
                        {results_button}
                        {assign_button}
                        {share_button}
                        {delete_button}
                        {publish_button}
                    </div>
                </div>
            </div>
            '''
        
        if not forms_html:
            forms_html = f'''
            <div class="alert alert-info">
                <i class="fas fa-info-circle me-2"></i>
                No forms available {f'for department: {selected_dept}' if selected_dept else ''}.
            </div>
            '''
        
        # Render assigned forms for students - FIXED THE COMPARISON ERROR HERE
        assigned_html = ''
        if user_role == 'student':
            for form in assigned_forms:
                status_badge = 'badge-success' if form['is_completed'] else 'badge-danger'
                status_text = 'Completed' if form['is_completed'] else 'Pending'
                
                if form['is_completed']:
                    # Check if download is available
                    connection = get_db()
                    with connection.cursor() as cursor:
                        cursor.execute('''
                            SELECT r.id as response_id, rd.access_granted, f.form_type
                            FROM responses r
                            LEFT JOIN response_downloads rd ON r.id = rd.response_id AND rd.student_id = %s
                            JOIN forms f ON r.form_id = f.id
                            WHERE r.form_id = %s AND r.student_id = %s
                        ''', (user_id, form['id'], user_id))
                        response_info = cursor.fetchone()
                    connection.close()
                    
                    if response_info and (response_info['form_type'] == 'public' or response_info['access_granted']):
                        start_button = f'<a href="/my-responses/downloads" class="btn btn-sm btn-success"><i class="fas fa-download"></i> Download</a>'
                    else:
                        start_button = '<span class="text-success"><i class="fas fa-check"></i> Submitted</span>'
                else:
                    start_button = f'<a href="/form/{form["id"]}/take" class="btn btn-sm btn-primary"><i class="fas fa-play"></i> Start</a>'
                
                due_date_info = ''
                if form['due_date']:
                    due_date = form['due_date']
                    # Ensure due_date is a datetime object
                    if isinstance(due_date, str):
                        # Convert string to datetime
                        try:
                            due_date = datetime.strptime(due_date, '%Y-%m-%d %H:%M:%S')
                        except ValueError:
                            try:
                                due_date = datetime.strptime(due_date, '%Y-%m-%d')
                            except:
                                due_date = None
                    
                    if due_date:
                        now = datetime.now()
                        if due_date < now and not form['is_completed']:
                            due_date_info = f'<small class="text-danger"><i class="fas fa-exclamation-triangle me-1"></i>Overdue: {due_date.strftime("%Y-%m-%d")}</small>'
                        else:
                            due_date_info = f'<small class="text-muted"><i class="fas fa-calendar me-1"></i>Due: {due_date.strftime("%Y-%m-%d")}</small>'
                
                assigned_html += f'''
                <div class="card mb-3">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <h5 class="mb-1">{form['title']}</h5>
                                <small class="text-muted">
                                    <i class="fas fa-building me-1"></i>{form['department']}
                                    {due_date_info}
                                </small>
                            </div>
                            <span class="badge {status_badge}">{status_text}</span>
                        </div>
                        <div class="mt-3">
                            {start_button}
                        </div>
                    </div>
                </div>
                '''
            
            if not assigned_html:
                assigned_html = '<div class="alert alert-info">No assigned forms.</div>'
        
        # Student statistics display
        student_stats_html = ''
        if user_role == 'student' and student_stats:
            student_stats_html = f'''
            <div class="row mb-4">
                <div class="col-md-3">
                    <div class="stat-card student-stats-card">
                        <h5>Forms Taken</h5>
                        <h2>{student_stats.get('total_forms_taken', 0) or 0}</h2>
                        <small>Passed: {student_stats.get('passed_forms', 0)}</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(45deg, #3b82f6, #1d4ed8);">
                        <h5>Average Score</h5>
                        <h2>{student_stats.get('avg_score', 0) or 0:.1f}%</h2>
                        <small>Best: {student_stats.get('highest_score', 0) or 0:.1f}%</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(45deg, #10b981, #059669);">
                        <h5>Downloads</h5>
                        <h2>{student_stats.get('granted_downloads', 0) or 0}</h2>
                        <small>Pending: {student_stats.get('pending_downloads', 0)}</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(45deg, #8b5cf6, #7c3aed);">
                        <h5>Pending</h5>
                        <h2>{student_stats.get('pending_submissions', 0) or 0}</h2>
                        <small>Submissions</small>
                    </div>
                </div>
            </div>
            '''
        
        # Teacher statistics display
        teacher_stats_html = ''
        if user_role in ['teacher', 'admin', 'super_admin'] and teacher_stats:
            teacher_stats_html = f'''
            <div class="row mb-4">
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(45deg, #667eea, #764ba2);">
                        <h5>Total Forms</h5>
                        <h2>{teacher_stats.get('total_forms', 0) or 0}</h2>
                        <small>Student Forms: {teacher_stats.get('student_forms', 0)}</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(45deg, #10b981, #059669);">
                        <h5>Total Responses</h5>
                        <h2>{teacher_stats.get('total_responses', 0) or 0}</h2>
                        <small>Avg Score: {teacher_stats.get('avg_score', 0) or 0:.1f}%</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(45deg, #f59e0b, #d97706);">
                        <h5>Assignments</h5>
                        <h2>{teacher_stats.get('total_assignments', 0) or 0}</h2>
                        <small>Active</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(45deg, #ef4444, #dc2626);">
                        <h5>Pending</h5>
                        <h2>{pending_requests_count + pending_reviews_count + pending_downloads_count}</h2>
                        <small>Requests/Reviews/Downloads</small>
                    </div>
                </div>
            </div>
            '''
        
        # Recent activities HTML
        recent_activities_html = ''
        if recent_activities:
            for activity in recent_activities:
                icon_map = {
                    'form_created': 'fa-file-alt text-primary',
                    'response_submitted': 'fa-paper-plane text-success',
                    'download_requested': 'fa-download text-warning',
                    'download_granted': 'fa-check-circle text-success',
                    'form_requested': 'fa-hand-paper text-info'
                }
                icon = icon_map.get(activity['type'], 'fa-info-circle')
                time_ago = get_time_ago(activity['timestamp'])
                
                recent_activities_html += f'''
                <div class="d-flex mb-3">
                    <div class="flex-shrink-0">
                        <i class="fas {icon} fa-lg mt-1"></i>
                    </div>
                    <div class="flex-grow-1 ms-3">
                        <h6 class="mb-1">{activity['description']}</h6>
                        <p class="mb-0 text-muted">By {activity['user_name']}</p>
                        <small class="text-muted">{time_ago}</small>
                        {f'<a href="{activity["link"]}" class="btn btn-sm btn-outline-primary mt-1">View</a>' if activity.get('link') and activity['link'] != '#' else ''}
                    </div>
                </div>
                '''
        else:
            recent_activities_html = '''
            <div class="text-center py-3">
                <i class="fas fa-history fa-2x text-muted mb-2"></i>
                <p class="text-muted">No recent activities</p>
            </div>
            '''
        
        # Determine column widths
        col_width = '12'
        assigned_section = ''
        if user_role == 'student':
            col_width = '8'
            assigned_section = f'''
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="fas fa-tasks me-2"></i>Assigned Forms ({len(assigned_forms)})</h5>
                    </div>
                    <div class="card-body">
                        {assigned_html}
                    </div>
                </div>
            </div>
            '''
        
        # Pending requests badge for teachers/admin
        requests_badge = ''
        if user_role in ['teacher', 'admin', 'super_admin'] and pending_requests_count > 0:
            requests_badge = f'<span class="badge bg-danger request-badge">{pending_requests_count}</span>'
        
        # Pending reviews badge for teachers/admin
        reviews_badge = ''
        if user_role in ['teacher', 'admin', 'super_admin'] and pending_reviews_count > 0:
            reviews_badge = f'<span class="badge bg-warning request-badge">{pending_reviews_count}</span>'
        
        # Pending downloads badge for teachers/admin
        downloads_badge = ''
        if user_role in ['teacher', 'admin', 'super_admin'] and pending_downloads_count > 0:
            downloads_badge = f'<span class="badge bg-info request-badge">{pending_downloads_count}</span>'
        
        # Quick actions for teachers/admin
        quick_actions = ''
        if user_role in ['teacher', 'admin', 'super_admin']:
            quick_actions = f'''
            <div class="row mb-4">
                <div class="col-md-3">
                    <a href="/create-form" class="btn btn-primary w-100">
                        <i class="fas fa-plus me-2"></i>Create Form
                    </a>
                </div>
                <div class="col-md-3">
                    <a href="/form-requests" class="btn btn-warning w-100">
                        <i class="fas fa-clock me-2"></i>Access Requests {requests_badge}
                    </a>
                </div>
                <div class="col-md-3">
                    <a href="/review-forms" class="btn btn-info w-100">
                        <i class="fas fa-check-circle me-2"></i>Review Forms {reviews_badge}
                    </a>
                </div>
                <div class="col-md-3">
                    <a href="#" onclick="viewDownloadRequests()" class="btn btn-success w-100">
                        <i class="fas fa-download me-2"></i>Download Requests {downloads_badge}
                    </a>
                </div>
            </div>
            '''
        elif user_role == 'student':
            quick_actions = f'''
            <div class="row mb-4">
                <div class="col-md-4">
                    <a href="/create-student-form" class="btn btn-success w-100">
                        <i class="fas fa-plus-circle me-2"></i>Create Form
                    </a>
                </div>
                <div class="col-md-4">
                    <a href="/my-responses" class="btn btn-primary w-100">
                        <i class="fas fa-chart-bar me-2"></i>My Results
                    </a>
                </div>
                <div class="col-md-4">
                    <a href="/my-responses/downloads" class="btn btn-warning w-100">
                        <i class="fas fa-download me-2"></i>My Downloads
                        {f'<span class="badge bg-danger ms-2">{student_stats.get("pending_downloads", 0)}</span>' if student_stats.get('pending_downloads', 0) > 0 else ''}
                    </a>
                </div>
            </div>
            '''
        
        # Build dashboard
        sidebar_html = f'''<div class="col-md-4">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="fas fa-history me-2"></i>Recent Activities</h5>
                </div>
                <div class="card-body">
                    {recent_activities_html}
                </div>
            </div>
            
            <!-- Quick Stats -->
            <div class="card mt-4">
                <div class="card-header">
                    <h5 class="mb-0"><i class="fas fa-chart-pie me-2"></i>Quick Stats</h5>
                </div>
                <div class="card-body">
                    <div class="row text-center">
                        <div class="col-6">
                            <h4>{len(forms)}</h4>
                            <small class="text-muted">Forms</small>
                        </div>
                        <div class="col-6">
                            <h4>{sum([f.get('response_count', 0) for f in forms])}</h4>
                            <small class="text-muted">Total Responses</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>''' if user_role != 'student' else ''
        
        content = f'''
        <div class="mb-4">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h2 class="text-white">Welcome, {session["name"]}!</h2>
                    <p class="text-white-50 mb-0">
                        <span class="badge bg-light text-dark me-2">{session["department"]}</span>
                        <span class="badge {'badge-super-admin' if user_role == 'super_admin' else 'bg-danger' if user_role == 'admin' else 'bg-warning' if user_role == 'teacher' else 'student-stats-card'}">
                            {user_role.upper().replace('_', ' ')}
                        </span>
                    </p>
                </div>
                <div>
                    <a href="/notifications" class="btn btn-outline-light position-relative me-2">
                        <i class="fas fa-bell"></i>
                        {f'<span class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger">{get_unread_notification_count(user_id)}</span>' if get_unread_notification_count(user_id) > 0 else ''}
                    </a>
                </div>
            </div>
        </div>

        {dept_filter_html}
        {dept_stats_html}
        {student_stats_html}
        {teacher_stats_html}
        
        {quick_actions}
        
        <div class="row">
            <div class="col-md-{col_width}">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-list me-2"></i>Available Forms ({len(forms)})
                        </h5>
                    </div>
                    <div class="card-body">
                        {forms_html}
                    </div>
                </div>
            </div>
            {assigned_section}
            
            <!-- Recent Activities Sidebar -->
            {sidebar_html}
        </div>
        '''
        
        scripts = '''
        <script>
            function requestForm(formId) {
                if (confirm('Request access to this form?')) {
                    fetch('/request-form/' + formId, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            alert('Request submitted successfully!');
                            window.location.reload();
                        } else {
                            alert('Error: ' + data.error);
                        }
                    });
                }
            }
            
            function requestDownloadByForm(formId) {
                // First get the response ID for this form
                fetch('/api/get-response/' + formId, {
                    method: 'GET',
                    headers: {'Content-Type': 'application/json'}
                })
                .then(res => res.json())
                .then(data => {
                    if (data.success && data.response_id) {
                        requestDownload(data.response_id);
                    } else {
                        alert('Error: ' + (data.error || 'No response found for this form'));
                    }
                })
                .catch(error => {
                    alert('Network error: ' + error);
                });
            }
            
            function requestDownload(responseId) {
                if (confirm('Request download permission for this response?')) {
                    fetch('/request-download/' + responseId, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            alert(data.message);
                            window.location.reload();
                        } else {
                            alert('Error: ' + data.error);
                        }
                    })
                    .catch(error => {
                        alert('Network error: ' + error);
                    });
                }
            }
            
            function deleteForm(formId, formTitle) {
                if (confirm(`Are you sure you want to delete the form "${formTitle}"? This action cannot be undone.`)) {
                    fetch('/form/' + formId + '/delete', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            alert('Form deleted successfully!');
                            window.location.reload();
                        } else {
                            alert('Error: ' + data.error);
                        }
                    });
                }
            }
            
            function togglePublish(formId, currentStatus, formTitle) {
                const action = currentStatus ? 'unpublish' : 'publish';
                const confirmMsg = currentStatus 
                    ? `Unpublish the form "${formTitle}"?\\n\\nThis will make the form unavailable to students.`
                    : `Publish the form "${formTitle}"?\\n\\nThis will make the form available to students.`;
                
                if (confirm(confirmMsg)) {
                    fetch('/form/' + formId + '/toggle-publish', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            alert(`Form ${data.status_text} successfully!`);
                            window.location.reload();
                        } else {
                            alert('Error: ' + data.error);
                        }
                    });
                }
            }
            
            function viewDownloadRequests() {
            // For teachers/admins, show their forms with download requests
            fetch('/api/my-forms-download-requests', {
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            })
            .then(res => {
                // Check if response is JSON
                const contentType = res.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    return res.text().then(text => {
                        throw new Error('Expected JSON but got: ' + text.substring(0, 100));
                    });
                }
                return res.json();
            })
            .then(data => {
                if (data.success && data.forms.length > 0) {
                    let html = '<h5>Forms with Pending Download Requests</h5>';
                    data.forms.forEach(form => {
                        html += `
                            <div class="card mb-2">
                                <div class="card-body">
                                    <h6>${form.title}</h6>
                                    <p class="text-muted">Pending requests: ${form.pending_downloads}</p>
                                    <a href="/form/${form.id}/response-downloads" class="btn btn-sm btn-primary">Manage</a>
                                </div>
                            </div>
                        `;
                    });
                    
                    // Show in modal
                    const modal = new bootstrap.Modal(document.getElementById('downloadRequestsModal'));
                    document.getElementById('downloadRequestsContent').innerHTML = html;
                    modal.show();
                } else {
                    alert('No forms with pending download requests.');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error loading download requests. Please try again.');
            });
        }
            
            // Auto-refresh notifications every 30 seconds
            setInterval(() => {
                fetch('/api/notifications/recent')
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            // Update notification badge
                            const badge = document.querySelector('.notification-badge');
                            if (data.unread_count > 0) {
                                if (badge) {
                                    badge.innerHTML = `<span class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger">${data.unread_count}</span>`;
                                }
                            } else if (badge) {
                                badge.innerHTML = '';
                            }
                        }
                    });
            }, 30000);
        </script>
        
        <!-- Download Requests Modal -->
        <div class="modal fade" id="downloadRequestsModal" tabindex="-1" aria-labelledby="downloadRequestsModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="downloadRequestsModalLabel">Download Requests</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body" id="downloadRequestsContent">
                        <!-- Content loaded dynamically -->
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        return html_wrapper('Dashboard', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"Dashboard error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')


def get_navbar():
    if 'user_id' not in session:
        return ''
    
    # Get unread notification count
    unread_count = get_unread_notification_count(session['user_id'])
    notification_badge = ''
    if unread_count > 0:
        notification_badge = f'<span class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger">{unread_count}</span>'
    
    user_badge = ''
    badge_class = ''
    badge_color = ''
    if session['role'] == 'super_admin':
        user_badge = '<span class="badge badge-super-admin">SUPER ADMIN</span>'
        badge_class = 'badge-super-admin'
        badge_color = 'linear-gradient(135deg, #6f42c1, #5a32a3)'
    elif session['role'] == 'admin':
        user_badge = '<span class="badge bg-danger">ADMIN</span>'
        badge_class = 'bg-danger'
        badge_color = 'linear-gradient(135deg, #dc3545, #c82333)'
    elif session['role'] == 'teacher':
        user_badge = '<span class="badge bg-warning text-dark">TEACHER</span>'
        badge_class = 'bg-warning text-dark'
        badge_color = 'linear-gradient(135deg, #ffc107, #e0a800)'
    else:
        user_badge = '<span class="badge student-stats-card">STUDENT</span>'
        badge_class = 'student-stats-card'
        badge_color = 'linear-gradient(135deg, #6c757d, #5a6268)'
    
    dept_badge = '<span class="badge bg-dark ms-1 ms-md-2">' + session.get('department', 'N/A') + '</span>'
    
    # Create navigation sections based on role
    main_nav_items = []
    quick_access_items = []
    admin_items = []
    
    # Common items for all logged-in users
    main_nav_items.append('<a class="nav-link" href="/dashboard"><i class="fas fa-home me-2"></i>Dashboard</a>')
    
    # Role-specific main navigation
    if session['role'] in ['teacher', 'admin', 'super_admin']:
        main_nav_items.append('<a class="nav-link" href="/create-form"><i class="fas fa-plus me-2"></i>Create Form</a>')
        main_nav_items.append('<a class="nav-link" href="/review-forms"><i class="fas fa-check-circle me-2"></i>Review Forms</a>')
        quick_access_items.append('<a class="dropdown-item" href="/form-requests"><i class="fas fa-clock me-2"></i>Pending Requests</a>')
        quick_access_items.append('<a class="dropdown-item" href="/teacher-analytics"><i class="fas fa-chart-bar me-2"></i>Analytics</a>')
    
    if session['role'] == 'student':
        main_nav_items.append('<a class="nav-link" href="/create-student-form"><i class="fas fa-plus-circle me-2"></i>Create Form</a>')
        main_nav_items.append('<a class="nav-link" href="/my-submissions"><i class="fas fa-history me-2"></i>My Submissions</a>')
        quick_access_items.append('<a class="dropdown-item" href="/my-responses"><i class="fas fa-chart-bar me-2"></i>My Results</a>')
    
    if session['role'] in ['admin', 'super_admin']:
        admin_items.append('<a class="dropdown-item" href="/admin"><i class="fas fa-cogs me-2"></i>Admin Panel</a>')
        admin_items.append('<a class="dropdown-item" href="/admin/test"><i class="fas fa-vial me-2"></i>System Test</a>')
    
    # Profile icon with initials
    user_name = session["name"]
    initials = ''.join([name[0].upper() for name in user_name.split()[:2]])
    
    # Build conditional sections
    teacher_admin_html = ''
    if session['role'] in ['teacher', 'admin', 'super_admin']:
        teacher_admin_html = '''
        <a href="/create-form" class="list-group-item list-group-item-action border-0 py-3">
            <i class="fas fa-plus me-3 text-success"></i>Create Form
        </a>
        <a href="/review-forms" class="list-group-item list-group-item-action border-0 py-3">
            <i class="fas fa-check-circle me-3 text-info"></i>Review Forms
        </a>
        <a href="/form-requests" class="list-group-item list-group-item-action border-0 py-3">
            <i class="fas fa-clock me-3 text-warning"></i>Pending Requests
        </a>
        <a href="/teacher-analytics" class="list-group-item list-group-item-action border-0 py-3">
            <i class="fas fa-chart-bar me-3 text-purple"></i>Analytics
        </a>
        '''
    
    student_html = ''
    if session['role'] == 'student':
        student_html = '''
        <a href="/create-student-form" class="list-group-item list-group-item-action border-0 py-3">
            <i class="fas fa-plus-circle me-3 text-success"></i>Create Form
        </a>
        <a href="/my-submissions" class="list-group-item list-group-item-action border-0 py-3">
            <i class="fas fa-history me-3 text-secondary"></i>My Submissions
        </a>
        <a href="/my-responses" class="list-group-item list-group-item-action border-0 py-3">
            <i class="fas fa-chart-bar me-3 text-info"></i>My Results
        </a>
        '''
    
    admin_tools_html = ''
    if session['role'] in ['admin', 'super_admin']:
        admin_tools_html = '''
        <div class="border-top mt-2 pt-2">
            <div class="text-muted small px-3 py-2">Admin Tools</div>
            <a href="/admin" class="list-group-item list-group-item-action border-0 py-3">
                <i class="fas fa-cogs me-3 text-danger"></i>Admin Panel
            </a>
            <a href="/admin/test" class="list-group-item list-group-item-action border-0 py-3">
                <i class="fas fa-vial me-3 text-danger"></i>System Test
            </a>
        </div>
        '''
    
    # Build mobile navigation (collapsible)
    mobile_nav = '''
    <!-- Mobile Navigation -->
    <div class="offcanvas offcanvas-end" tabindex="-1" id="mobileNav" aria-labelledby="mobileNavLabel">
        <div class="offcanvas-header border-bottom">
            <div class="d-flex align-items-center">
                <div class="rounded-circle d-flex align-items-center justify-content-center me-3"
                     style="width: 50px; height: 50px; background: ''' + badge_color + '''; color: white; font-weight: bold;">
                    ''' + initials + '''
                </div>
                <div>
                    <h5 class="offcanvas-title fw-bold" id="mobileNavLabel">''' + user_name + '''</h5>
                    <div>''' + user_badge + ' ' + dept_badge + '''</div>
                </div>
            </div>
            <button type="button" class="btn-close" data-bs-dismiss="offcanvas"></button>
        </div>
        <div class="offcanvas-body p-0">
            <div class="list-group list-group-flush">
                <a href="/dashboard" class="list-group-item list-group-item-action border-0 py-3">
                    <i class="fas fa-home me-3 text-primary"></i>Dashboard
                </a>
                
                ''' + teacher_admin_html + '''
                ''' + student_html + '''
                ''' + admin_tools_html + '''
                
                <div class="border-top mt-2 pt-2">
                    <a href="/profile" class="list-group-item list-group-item-action border-0 py-3">
                        <i class="fas fa-user me-3"></i>My Profile
                    </a>
                    <a href="/settings" class="list-group-item list-group-item-action border-0 py-3">
                        <i class="fas fa-cog me-3"></i>Settings
                    </a>
                    <a href="/notifications" class="list-group-item list-group-item-action border-0 py-3">
                        <i class="fas fa-bell me-3"></i>Notifications
                        ''' + (f'<span class="badge bg-danger float-end mt-1">{unread_count}</span>' if unread_count > 0 else '') + '''
                    </a>
                </div>
                
                <div class="border-top mt-2 pt-3 px-3">
                    <a href="/logout" class="btn btn-outline-danger w-100">
                        <i class="fas fa-sign-out-alt me-2"></i>Logout
                    </a>
                </div>
            </div>
        </div>
    </div>
    '''
    
    # Build quick access dropdown HTML
    quick_access_dropdown = ''
    if quick_access_items:
        quick_access_dropdown = '''
        <li class="nav-item dropdown mx-1">
            <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                <i class="fas fa-bolt me-2"></i>Quick Access
            </a>
            <ul class="dropdown-menu dropdown-menu-end">
                ''' + ''.join(quick_access_items) + '''
            </ul>
        </li>
        '''
    
    # Build admin dropdown HTML
    admin_dropdown = ''
    if admin_items:
        admin_dropdown = '''
        <li class="nav-item dropdown mx-1">
            <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                <i class="fas fa-shield-alt me-2"></i>Admin
            </a>
            <ul class="dropdown-menu dropdown-menu-end">
                ''' + ''.join(admin_items) + '''
            </ul>
        </li>
        '''
    
    return '''
    <nav class="navbar navbar-expand-lg navbar-light bg-white border-bottom py-2 fixed-top" style="z-index: 1030;">
        <div class="container-fluid px-3">
            <!-- Brand Logo -->
            <a class="navbar-brand d-flex align-items-center" href="/dashboard">
                <div class="brand-icon me-2">
                    <i class="fas fa-poll text-primary fs-4"></i>
                </div>
                <div class="d-flex flex-column">
                    <span class="fw-bold text-dark fs-5">FormMaster Pro</span>
                    ''' + dept_badge + '''
                </div>
            </a>
            
            <!-- Mobile Menu Button -->
            <button class="btn btn-outline-secondary d-lg-none ms-auto me-2" type="button" 
                    data-bs-toggle="offcanvas" data-bs-target="#mobileNav">
                <i class="fas fa-bars"></i>
            </button>
            
            <!-- Desktop Navigation & Actions (Right Corner) -->
            <div class="d-none d-lg-flex align-items-center ms-auto">
                <!-- Main Navigation Links -->
                <ul class="navbar-nav me-3">
                    ''' + ''.join([f'<li class="nav-item mx-1">{item}</li>' for item in main_nav_items]) + '''
                    
                    <!-- Quick Access Dropdown -->
                    ''' + quick_access_dropdown + '''
                    
                    <!-- Admin Dropdown -->
                    ''' + admin_dropdown + '''
                </ul>
                
                <!-- Right Corner Items -->
                <div class="d-flex align-items-center border-left ps-3 ms-3">
                    <!-- Notifications -->
                    <div class="dropdown me-3">
                        <button class="btn btn-light position-relative p-2 rounded-circle border-0" 
                                type="button" data-bs-toggle="dropdown"
                                aria-label="Notifications">
                            <i class="fas fa-bell"></i>
                            ''' + notification_badge + '''
                        </button>
                        <div class="dropdown-menu dropdown-menu-end p-0" style="width: 350px;">
                            <div class="dropdown-header bg-light py-3">
                                <div class="d-flex justify-content-between align-items-center">
                                    <h6 class="mb-0 fw-bold">Notifications</h6>
                                    <a href="/notifications" class="text-decoration-none small">
                                        View All <i class="fas fa-external-link-alt ms-1"></i>
                                    </a>
                                </div>
                            </div>
                            <div class="notification-container" style="max-height: 400px; overflow-y: auto;">
                                <div id="notification-list">
                                    <div class="text-center py-4">
                                        <div class="spinner-border spinner-border-sm text-primary" role="status">
                                            <span class="visually-hidden">Loading...</span>
                                        </div>
                                        <span class="ms-2 text-muted">Loading notifications...</span>
                                    </div>
                                </div>
                            </div>
                            <div class="dropdown-footer bg-light py-2 border-top">
                                <div class="text-center">
                                    <button class="btn btn-sm btn-link text-decoration-none" onclick="markAllAsRead()">
                                        <i class="fas fa-check-circle me-1"></i> Mark all as read
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- User Profile -->
                    <div class="dropdown">
                        <button class="btn p-0 border-0 bg-transparent d-flex align-items-center" type="button" 
                                data-bs-toggle="dropdown" aria-expanded="false">
                            <div class="profile-avatar">
                                <div class="rounded-circle d-flex align-items-center justify-content-center"
                                     style="width: 40px; height: 40px; background: ''' + badge_color + '''; color: white; font-weight: bold; font-size: 14px;">
                                    ''' + initials + '''
                                </div>
                            </div>
                            <i class="fas fa-chevron-down text-muted ms-2"></i>
                        </button>
                        <ul class="dropdown-menu dropdown-menu-end p-2" style="min-width: 250px;">
                            <li class="dropdown-header">
                                <div class="d-flex align-items-center">
                                    <div class="rounded-circle d-flex align-items-center justify-content-center me-2"
                                         style="width: 36px; height: 36px; background: ''' + badge_color + '''; color: white; font-weight: bold;">
                                        ''' + initials + '''
                                    </div>
                                    <div>
                                        <div class="fw-bold">''' + user_name + '''</div>
                                        <small class="text-muted">''' + session.get('email', '') + '''</small>
                                    </div>
                                </div>
                            </li>
                            <li><hr class="dropdown-divider my-2"></li>
                            
                            <li><a class="dropdown-item py-2" href="/profile">
                                <i class="fas fa-user me-2 text-primary"></i>My Profile
                            </a></li>
                            <li><a class="dropdown-item py-2" href="/settings">
                                <i class="fas fa-cog me-2 text-secondary"></i>Settings
                            </a></li>
                            <li><a class="dropdown-item py-2" href="/notifications">
                                <i class="fas fa-bell me-2 text-warning"></i>Notifications
                                ''' + (f'<span class="badge bg-danger float-end mt-1">{unread_count}</span>' if unread_count > 0 else '') + '''
                            </a></li>
                            
                            <li><hr class="dropdown-divider my-2"></li>
                            
                            <li>
                                <a class="dropdown-item py-2 text-danger" href="/logout">
                                    <i class="fas fa-sign-out-alt me-2"></i>Logout
                                </a>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </nav>
    
    ''' + mobile_nav + '''
    
    <!-- Spacer to prevent content from hiding behind fixed navbar -->
    <div style="height: 70px;"></div>
    
    <style>
        /* Fix navbar to top with no spacing */
        body {
            padding-top: 0 !important;
            margin-top: 0 !important;
        }
        
        .navbar.fixed-top {
            top: 0;
            left: 0;
            right: 0;
            margin: 0;
            padding: 0;
        }
        
        /* Right corner items styling */
        .border-left {
            border-left: 1px solid #dee2e6 !important;
        }
        
        /* Custom scrollbar for notifications */
        .notification-container {
            scrollbar-width: thin;
            scrollbar-color: #dee2e6 transparent;
        }
        
        .notification-container::-webkit-scrollbar {
            width: 6px;
        }
        
        .notification-container::-webkit-scrollbar-track {
            background: transparent;
        }
        
        .notification-container::-webkit-scrollbar-thumb {
            background-color: #dee2e6;
            border-radius: 3px;
        }
        
        /* Nav link hover effects */
        .nav-link {
            font-weight: 500;
            padding: 0.5rem 1rem !important;
            border-radius: 6px;
            transition: all 0.2s;
            color: #495057 !important;
        }
        
        .nav-link:hover {
            background-color: rgba(0, 123, 255, 0.1);
            color: #0d6efd !important;
            transform: translateY(-1px);
        }
        
        .nav-link.active {
            background-color: rgba(0, 123, 255, 0.15);
            color: #0d6efd !important;
            font-weight: 600;
        }
        
        /* Profile dropdown animation */
        .dropdown-menu {
            animation: fadeIn 0.2s ease-in-out;
        }
        
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        /* Mobile offcanvas styles */
        .offcanvas {
            width: 300px !important;
        }
        
        .list-group-item {
            border-left: 3px solid transparent;
            transition: all 0.2s;
        }
        
        .list-group-item:hover {
            border-left-color: #0d6efd;
            background-color: #f8f9fa;
        }
        
        .text-purple {
            color: #6f42c1 !important;
        }
        
        /* Responsive adjustments */
        @media (max-width: 992px) {
            .container-fluid {
                padding-left: 15px !important;
                padding-right: 15px !important;
            }
            
            .navbar-brand {
                font-size: 1.1rem !important;
            }
            
            .border-left {
                border-left: none !important;
                padding-left: 0 !important;
                margin-left: 0 !important;
            }
        }
        
        @media (max-width: 576px) {
            .navbar-brand {
                font-size: 1rem !important;
            }
            
            .offcanvas {
                width: 280px !important;
            }
        }
        
        /* Desktop specific */
        @media (min-width: 992px) {
            .navbar-nav {
                align-items: center;
            }
            
            .profile-avatar {
                transition: transform 0.2s;
            }
            
            .profile-avatar:hover {
                transform: scale(1.05);
            }
            
            .btn-light.rounded-circle:hover {
                background-color: #e9ecef !important;
                box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.1);
            }
        }
    </style>
    
    <script>
        $(document).ready(function() {
            loadNotifications();
            setInterval(loadNotifications, 30000);
            
            // Highlight active link
            const currentPath = window.location.pathname;
            $('.nav-link').each(function() {
                if ($(this).attr('href') === currentPath) {
                    $(this).addClass('active');
                }
            });
            
            // Update notification badge on page load
            updateNotificationBadge(''' + str(unread_count) + ''');
            
            // Add hover effect to profile avatar
            $('.profile-avatar').hover(
                function() {
                    $(this).css('transform', 'scale(1.05)');
                },
                function() {
                    $(this).css('transform', 'scale(1)');
                }
            );
        });
        
        function loadNotifications() {
            $.ajax({
                url: '/api/notifications/recent',
                type: 'GET',
                success: function(response) {
                    if (response.success) {
                        $('#notification-list').html(response.html);
                        updateNotificationBadge(response.unread_count);
                    }
                },
                error: function() {
                    $('#notification-list').html(
                        '<div class="text-center py-4 text-danger">' +
                        '<i class="fas fa-exclamation-triangle me-2"></i>' +
                        'Error loading notifications' +
                        '</div>'
                    );
                }
            });
        }
        
        function updateNotificationBadge(count) {
            // Update notification bell badge
            if (count > 0) {
                $('.fa-bell').parent().find('.badge').remove();
                $('.fa-bell').parent().append(
                    '<span class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger">' + count + '</span>'
                );
            } else {
                $('.fa-bell').parent().find('.badge').remove();
            }
            
            // Update badge in dropdown menu
            const badge = $('.notification-count-badge');
            if (count > 0) {
                badge.text(count).removeClass('d-none');
            } else {
                badge.addClass('d-none');
            }
        }
        
        function markAsRead(notificationId) {
            $.ajax({
                url: '/api/notifications/' + notificationId + '/read',
                type: 'POST',
                success: function(response) {
                    if (response.success) {
                        loadNotifications();
                        showToast('Notification marked as read', 'success');
                    }
                }
            });
        }
        
        function markAllAsRead() {
            $.ajax({
                url: '/api/notifications/mark-all-read',
                type: 'POST',
                success: function(response) {
                    if (response.success) {
                        loadNotifications();
                        showToast('All notifications marked as read', 'success');
                    }
                }
            });
        }
        
        function showToast(message, type) {
            const toast = $(
                '<div class="toast align-items-center text-bg-' + type + ' border-0 position-fixed bottom-0 end-0 m-3" role="alert">' +
                    '<div class="d-flex">' +
                        '<div class="toast-body">' +
                            message +
                        '</div>' +
                        '<button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>' +
                    '</div>' +
                '</div>'
            );
            $('body').append(toast);
            const bsToast = new bootstrap.Toast(toast[0]);
            bsToast.show();
            toast.on('hidden.bs.toast', function() {
                $(this).remove();
            });
        }
    </script>
    '''

@app.route('/profile')
@login_required
def myprofile():
    """User profile page"""
    try:
        user_id = session['user_id']
        
        connection = get_db()
        with connection.cursor() as cursor:
            # Get user data
            cursor.execute("""
                SELECT u.*, 
                       COUNT(DISTINCT f.id) as forms_created,
                       COUNT(DISTINCT r.id) as submissions_made,
                       COUNT(DISTINCT a.id) as assignments_received
                FROM users u
                LEFT JOIN forms f ON f.created_by = u.id
                LEFT JOIN responses r ON r.student_id = u.id
                LEFT JOIN assignments a ON a.student_id = u.id
                WHERE u.id = %s
                GROUP BY u.id
            """, (user_id,))
            user = cursor.fetchone()
            
            # Get recent activity
            cursor.execute("""
                (SELECT 'form_created' as type, f.title, f.created_at as date, NULL as status, f.id as item_id
                 FROM forms f 
                 WHERE f.created_by = %s 
                 ORDER BY f.created_at DESC LIMIT 5)
                UNION ALL
                (SELECT 'response_submitted' as type, f.title, r.submitted_at as date, 
                        CASE WHEN r.percentage >= 70 THEN 'passed' ELSE 'failed' END as status, 
                        r.id as item_id
                 FROM responses r 
                 JOIN forms f ON r.form_id = f.id 
                 WHERE r.student_id = %s 
                 ORDER BY r.submitted_at DESC LIMIT 5)
                ORDER BY date DESC LIMIT 10
            """, (user_id, user_id))
            recent_activity = cursor.fetchall()
            
            # Get user statistics based on role
            if session['role'] in ['teacher', 'admin', 'super_admin']:
                cursor.execute("""
                    SELECT 
                        COUNT(DISTINCT f.id) as total_forms,
                        SUM(CASE WHEN f.is_published = TRUE THEN 1 ELSE 0 END) as published_forms,
                        COUNT(DISTINCT r.id) as total_responses,
                        AVG(r.percentage) as avg_score
                    FROM forms f
                    LEFT JOIN responses r ON f.id = r.form_id
                    WHERE f.created_by = %s
                """, (user_id,))
                stats = cursor.fetchone()
            else:  # Student
                cursor.execute("""
                    SELECT 
                        COUNT(DISTINCT r.form_id) as forms_taken,
                        COUNT(DISTINCT r.id) as submissions_made,
                        AVG(r.percentage) as avg_score,
                        SUM(CASE WHEN r.percentage >= 70 THEN 1 ELSE 0 END) as passed_forms,
                        SUM(CASE WHEN r.percentage < 70 THEN 1 ELSE 0 END) as failed_forms
                    FROM responses r
                    WHERE r.student_id = %s
                """, (user_id,))
                stats = cursor.fetchone()
        
        connection.close()
        
        # Format statistics
        if stats:
            for key in stats:
                if isinstance(stats[key], Decimal):
                    stats[key] = float(stats[key])
        
        # Generate HTML content
        profile_html = f'''
        <div class="row">
            <div class="col-md-4">
                <div class="card mb-4">
                    <div class="card-body text-center">
                        <div class="rounded-circle bg-primary d-inline-flex align-items-center justify-content-center" 
                             style="width: 120px; height: 120px; margin-bottom: 20px;">
                            <span class="text-white fw-bold" style="font-size: 48px;">
                                {user['name'][0].upper() if user['name'] else 'U'}
                            </span>
                        </div>
                        <h4>{user['name']}</h4>
                        <p class="text-muted">{user['email']}</p>
                        
                        <div class="d-flex justify-content-center mb-3">
                            <span class="badge {'badge-super-admin' if session['role'] == 'super_admin' else 'bg-danger' if session['role'] == 'admin' else 'bg-warning' if session['role'] == 'teacher' else 'student-stats-card'} me-2">
                                {session['role'].upper().replace('_', ' ')}
                            </span>
                            <span class="badge bg-dark">{user['department']}</span>
                        </div>
                        
                        <p class="text-muted">
                            <small>Member since: {user['created_at'].strftime('%B %d, %Y')}</small>
                        </p>
                        
                        <div class="mt-3">
                            <button onclick="editProfile()" class="btn btn-outline-primary w-100 mb-2">
                                <i class="fas fa-edit me-2"></i>Edit Profile
                            </button>
                            <button onclick="changePassword()" class="btn btn-outline-secondary w-100">
                                <i class="fas fa-key me-2"></i>Change Password
                            </button>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Statistics</h5>
                    </div>
                    <div class="card-body">
                        <div class="row text-center">
        '''
        
        if session['role'] in ['teacher', 'admin', 'super_admin']:
            profile_html += f'''
                            <div class="col-6 mb-3">
                                <h6>Forms Created</h6>
                                <h4>{stats.get('total_forms', 0) or 0}</h4>
                                <small class="text-muted">Published: {stats.get('published_forms', 0)}</small>
                            </div>
                            <div class="col-6 mb-3">
                                <h6>Total Responses</h6>
                                <h4>{stats.get('total_responses', 0) or 0}</h4>
                                <small class="text-muted">Avg Score: {stats.get('avg_score', 0) or 0:.1f}%</small>
                            </div>
            '''
        else:
            profile_html += f'''
                            <div class="col-6 mb-3">
                                <h6>Forms Taken</h6>
                                <h4>{stats.get('forms_taken', 0) or 0}</h4>
                                <small class="text-muted">Submissions: {stats.get('submissions_made', 0)}</small>
                            </div>
                            <div class="col-6 mb-3">
                                <h6>Average Score</h6>
                                <h4>{stats.get('avg_score', 0) or 0:.1f}%</h4>
                                <small class="text-muted">Passed: {stats.get('passed_forms', 0)}</small>
                            </div>
            '''
        
        profile_html += f'''
                            <div class="col-6">
                                <h6>User ID</h6>
                                <h6 class="text-muted">{user['id']}</h6>
                            </div>
                            <div class="col-6">
                                <h6>Department</h6>
                                <h6 class="text-muted">{user['department']}</h6>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-8">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5 class="mb-0">Recent Activity</h5>
                    </div>
                    <div class="card-body">
        '''
        
        if recent_activity:
            profile_html += '''
                        <div class="timeline">
            '''
            
            for activity in recent_activity:
                icon = {
                    'form_created': 'fa-file-alt text-primary',
                    'response_submitted': 'fa-paper-plane text-success'
                }.get(activity['type'], 'fa-info-circle')
                
                time_ago = get_time_ago(activity['date'])
                
                profile_html += f'''
                            <div class="d-flex mb-3">
                                <div class="flex-shrink-0">
                                    <i class="fas {icon} fa-lg"></i>
                                </div>
                                <div class="flex-grow-1 ms-3">
                                    <h6 class="mb-1">{activity['title']}</h6>
                                    <p class="mb-1 text-muted">
                                        {activity['type'].replace('_', ' ').title()}
                                        {f'- <span class="badge bg-{"success" if activity["status"] == "passed" else "danger"}">{activity["status"].upper()}</span>' if activity['status'] else ''}
                                    </p>
                                    <small class="text-muted">{time_ago}</small>
                                </div>
                            </div>
                '''
            
            profile_html += '''
                        </div>
            '''
        else:
            profile_html += '''
                        <div class="text-center py-4">
                            <i class="fas fa-history fa-3x text-muted mb-3"></i>
                            <p class="text-muted">No recent activity</p>
                        </div>
            '''
        
        profile_html += f'''
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">Account Information</h5>
                            </div>
                            <div class="card-body">
                                <table class="table table-sm">
                                    <tbody>
                                        <tr>
                                            <th>Full Name:</th>
                                            <td>{user['name']}</td>
                                        </tr>
                                        <tr>
                                            <th>Email:</th>
                                            <td>{user['email']}</td>
                                        </tr>
                                        <tr>
                                            <th>Role:</th>
                                            <td><span class="badge {'badge-super-admin' if session['role'] == 'super_admin' else 'bg-danger' if session['role'] == 'admin' else 'bg-warning' if session['role'] == 'teacher' else 'student-stats-card'}">
                                                {session['role'].upper().replace('_', ' ')}
                                            </span></td>
                                        </tr>
                                        <tr>
                                            <th>Department:</th>
                                            <td>{user['department']}</td>
                                        </tr>
                                        <tr>
                                            <th>Account Created:</th>
                                            <td>{user['created_at'].strftime('%B %d, %Y')}</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">Quick Actions</h5>
                            </div>
                            <div class="card-body">
                                <div class="d-grid gap-2">
        '''
        
        if session['role'] in ['teacher', 'admin', 'super_admin']:
            profile_html += '''
                                    <a href="/create-form" class="btn btn-outline-primary">
                                        <i class="fas fa-plus me-2"></i>Create New Form
                                    </a>
                                    <a href="/form-requests" class="btn btn-outline-warning">
                                        <i class="fas fa-clock me-2"></i>View Pending Requests
                                    </a>
                                    <a href="/review-forms" class="btn btn-outline-info">
                                        <i class="fas fa-check-circle me-2"></i>Review Forms
                                    </a>
            '''
        else:
            profile_html += '''
                                    <a href="/create-student-form" class="btn btn-outline-success">
                                        <i class="fas fa-plus-circle me-2"></i>Create Student Form
                                    </a>
                                    <a href="/my-submissions" class="btn btn-outline-primary">
                                        <i class="fas fa-history me-2"></i>My Submissions
                                    </a>
                                    <a href="/my-responses" class="btn btn-outline-info">
                                        <i class="fas fa-chart-bar me-2"></i>My Results
                                    </a>
            '''
        
        profile_html += '''
                                    <a href="/settings" class="btn btn-outline-secondary">
                                        <i class="fas fa-cog me-2"></i>Account Settings
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            function editProfile() {
                // Show edit profile modal
                alert('Edit profile feature coming soon!');
            }
            
            function changePassword() {
                // Redirect to password change
                window.location.href = '/settings#security';
            }
        </script>
        
        <style>
            .timeline {
                position: relative;
                padding-left: 30px;
            }
            
            .timeline::before {
                content: '';
                position: absolute;
                left: 15px;
                top: 0;
                bottom: 0;
                width: 2px;
                background-color: #e9ecef;
            }
            
            .timeline .d-flex .flex-shrink-0 {
                position: relative;
                z-index: 1;
            }
            
            .rounded-circle.bg-primary {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }
        </style>
        '''
        
        return html_wrapper('My Profile', profile_html, get_navbar(), '')
        
    except Exception as e:
        print(f"Profile page error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

# API endpoint to update profile picture
@app.route('/api/profile/upload-picture', methods=['POST'])
def upload_profile_picture():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    user_id = session['user_id']
    
    if 'profile_picture' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'})
    
    file = request.files['profile_picture']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'})
    
    if file and allowed_file(file.filename):
        # Generate unique filename
        filename = secure_filename(f"profile_{user_id}_{datetime.now().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
        
        # Create uploads directory if it doesn't exist
        upload_folder = 'static/uploads/profile_pictures'
        os.makedirs(upload_folder, exist_ok=True)
        
        # Save file
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)
        
        # Update database with relative path
        relative_path = f"uploads/profile_pictures/{filename}"
        
        try:
            cursor = mysql.connection.cursor()
            cursor.execute("UPDATE users SET profile_picture = %s WHERE id = %s", (relative_path, user_id))
            mysql.connection.commit()
            cursor.close()
            
            return jsonify({
                'success': True, 
                'message': 'Profile picture updated',
                'image_url': f"/static/{relative_path}"
            })
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)})
    
    return jsonify({'success': False, 'message': 'Invalid file type'})

# Helper function for file upload
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# API endpoint to get user stats
@app.route('/api/profile/stats')
def get_user_stats():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    user_id = session['user_id']
    
    cursor = mysql.connection.cursor()
    
    if session['role'] in ['teacher', 'admin', 'super_admin']:
        cursor.execute("""
            SELECT 
                MONTH(created_at) as month,
                COUNT(*) as forms_created
            FROM forms 
            WHERE created_by = %s AND YEAR(created_at) = YEAR(CURDATE())
            GROUP BY MONTH(created_at)
            ORDER BY month
        """, (user_id,))
        monthly_stats = cursor.fetchall()
        
        cursor.execute("""
            SELECT 
                f.title,
                COUNT(s.id) as submission_count
            FROM forms f
            LEFT JOIN submissions s ON f.id = s.form_id
            WHERE f.created_by = %s
            GROUP BY f.id
            ORDER BY submission_count DESC
            LIMIT 5
        """, (user_id,))
        top_forms = cursor.fetchall()
    else:
        cursor.execute("""
            SELECT 
                MONTH(submitted_at) as month,
                COUNT(*) as submissions_made
            FROM submissions 
            WHERE user_id = %s AND YEAR(submitted_at) = YEAR(CURDATE())
            GROUP BY MONTH(submitted_at)
            ORDER BY month
        """, (user_id,))
        monthly_stats = cursor.fetchall()
        
        cursor.execute("""
            SELECT 
                f.title,
                s.status
            FROM submissions s
            JOIN forms f ON s.form_id = f.id
            WHERE s.user_id = %s
            ORDER BY s.submitted_at DESC
            LIMIT 5
        """, (user_id,))
        recent_submissions = cursor.fetchall()
    
    cursor.close()
    
    return jsonify({
        'success': True,
        'monthly_stats': monthly_stats,
        'top_forms': top_forms if session['role'] in ['teacher', 'admin', 'super_admin'] else [],
        'recent_submissions': recent_submissions if session['role'] == 'student' else []
    })

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    
    # Get user data from database - FIXED
    connection = get_db()
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
    connection.close()
    
    # Rest of the settings HTML code remains the same...
    
    # Get active sessions (simplified version)
    active_sessions = [
        {
            'device': 'Chrome on Windows',
            'location': 'Chennai, India',
            'ip': '192.168.1.100',
            'last_active': 'Just now',
            'current': True
        },
        {
            'device': 'Safari on iPhone',
            'location': 'Chennai, India',
            'ip': '192.168.1.101',
            'last_active': '2 hours ago',
            'current': False
        }
    ]
    
    # Inline HTML template for settings
    settings_html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Settings - FormMaster Pro</title>
        
        <!-- Bootstrap 5 CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <!-- Font Awesome -->
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {
                --primary-color: #4e73df;
                --success-color: #1cc88a;
                --warning-color: #f6c23e;
                --danger-color: #e74a3b;
                --dark-color: #5a5c69;
            }
            
            .settings-container {
                max-width: 1200px;
                margin: 0 auto;
            }
            
            .settings-sidebar {
                background: white;
                border-radius: 10px;
                box-shadow: 0 0.15rem 1.75rem 0 rgba(58, 59, 69, 0.15);
                position: sticky;
                top: 100px;
            }
            
            .settings-content {
                background: white;
                border-radius: 10px;
                box-shadow: 0 0.15rem 1.75rem 0 rgba(58, 59, 69, 0.15);
            }
            
            .nav-link.active {
                background-color: var(--primary-color);
                color: white !important;
                border-radius: 8px;
            }
            
            .nav-link {
                color: #6e707e;
                font-weight: 500;
                padding: 12px 20px;
                margin: 5px 0;
                transition: all 0.3s;
            }
            
            .nav-link:hover {
                background-color: rgba(78, 115, 223, 0.1);
                color: var(--primary-color);
                border-radius: 8px;
            }
            
            .settings-card {
                border: none;
                border-radius: 10px;
                box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
                transition: transform 0.3s;
            }
            
            .settings-card:hover {
                transform: translateY(-2px);
            }
            
            .form-control:focus {
                border-color: var(--primary-color);
                box-shadow: 0 0 0 0.2rem rgba(78, 115, 223, 0.25);
            }
            
            .btn-primary {
                background-color: var(--primary-color);
                border-color: var(--primary-color);
                padding: 10px 25px;
                font-weight: 600;
            }
            
            .btn-primary:hover {
                background-color: #2e59d9;
                border-color: #2e59d9;
            }
            
            .settings-header {
                border-bottom: 1px solid #e3e6f0;
                padding-bottom: 15px;
                margin-bottom: 30px;
            }
            
            .settings-icon {
                width: 50px;
                height: 50px;
                border-radius: 10px;
                display: flex;
                align-items: center;
                justify-content: center;
                margin-right: 15px;
            }
            
            .icon-profile {
                background: linear-gradient(135deg, #4e73df, #2e59d9);
                color: white;
            }
            
            .icon-security {
                background: linear-gradient(135deg, #1cc88a, #13855c);
                color: white;
            }
            
            .icon-notifications {
                background: linear-gradient(135deg, #f6c23e, #dda20a);
                color: white;
            }
            
            .icon-privacy {
                background: linear-gradient(135deg, #e74a3b, #be2617);
                color: white;
            }
            
            .toggle-switch {
                position: relative;
                display: inline-block;
                width: 60px;
                height: 30px;
            }
            
            .toggle-switch input {
                opacity: 0;
                width: 0;
                height: 0;
            }
            
            .toggle-slider {
                position: absolute;
                cursor: pointer;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background-color: #ccc;
                transition: .4s;
                border-radius: 34px;
            }
            
            .toggle-slider:before {
                position: absolute;
                content: "";
                height: 22px;
                width: 22px;
                left: 4px;
                bottom: 4px;
                background-color: white;
                transition: .4s;
                border-radius: 50%;
            }
            
            input:checked + .toggle-slider {
                background-color: var(--success-color);
            }
            
            input:checked + .toggle-slider:before {
                transform: translateX(30px);
            }
            
            .password-strength {
                height: 5px;
                border-radius: 2px;
                margin-top: 5px;
                transition: all 0.3s;
            }
            
            .strength-weak { background-color: var(--danger-color); width: 25%; }
            .strength-fair { background-color: var(--warning-color); width: 50%; }
            .strength-good { background-color: #17a2b8; width: 75%; }
            .strength-strong { background-color: var(--success-color); width: 100%; }
            
            .session-card {
                border-left: 4px solid var(--primary-color);
                transition: all 0.3s;
            }
            
            .session-card:hover {
                transform: translateX(5px);
            }
            
            .current-session {
                border-left-color: var(--success-color);
            }
        </style>
    </head>
    <body>
        ''' + get_navbar() + '''
        
        <div class="container py-4 settings-container">
            <div class="row">
                <!-- Sidebar -->
                <div class="col-lg-3 mb-4">
                    <div class="settings-sidebar p-4">
                        <h4 class="mb-4"><i class="fas fa-cog me-2"></i>Settings</h4>
                        <div class="nav flex-column nav-pills" id="settingsTab" role="tablist">
                            <a class="nav-link active" id="profile-tab" data-bs-toggle="pill" href="#profile">
                                <i class="fas fa-user me-2"></i>Profile
                            </a>
                            <a class="nav-link" id="security-tab" data-bs-toggle="pill" href="#security">
                                <i class="fas fa-shield-alt me-2"></i>Security
                            </a>
                            <a class="nav-link" id="notifications-tab" data-bs-toggle="pill" href="#notifications">
                                <i class="fas fa-bell me-2"></i>Notifications
                            </a>
                            <a class="nav-link" id="privacy-tab" data-bs-toggle="pill" href="#privacy">
                                <i class="fas fa-lock me-2"></i>Privacy
                            </a>
                        </div>
                    </div>
                </div>
                
                <!-- Content -->
                <div class="col-lg-9">
                    <div class="settings-content p-4">
                        <div class="tab-content" id="settingsTabContent">
                            <!-- Profile Tab -->
                            <div class="tab-pane fade show active" id="profile">
                                <div class="settings-header">
                                    <div class="d-flex align-items-center">
                                        <div class="settings-icon icon-profile">
                                            <i class="fas fa-user fa-lg"></i>
                                        </div>
                                        <div>
                                            <h4 class="mb-1">Profile Settings</h4>
                                            <p class="text-muted mb-0">Update your personal information</p>
                                        </div>
                                    </div>
                                </div>
                                
                                <form id="profileForm">
                                    <div class="row mb-4">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Full Name</label>
                                            <input type="text" class="form-control" name="name" 
                                                   value="''' + (user['name'] if user else '') + '''" required>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Email Address</label>
                                            <input type="email" class="form-control" name="email" 
                                                   value="''' + (user['email'] if user else '') + '''" required>
                                        </div>
                                        # In the settings HTML, change the phone input section to:
                                        
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Phone Number</label>
                                            <input type="tel" class="form-control" name="phone" 
                                                value="">
                                        </div>
                                        
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Department</label>
                                            <input type="text" class="form-control" name="department" 
                                                   value="''' + (user['department'] if user and user['department'] else '') + '''">
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Role</label>
                                            <input type="text" class="form-control" value="''' + session.get('role', '').title() + '''" readonly>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">User ID</label>
                                            <input type="text" class="form-control" value="''' + (str(user['id']) if user else '') + '''" readonly>
                                        </div>
                                    </div>
                                    <button type="submit" class="btn btn-primary">
                                        <i class="fas fa-save me-2"></i>Save Changes
                                    </button>
                                </form>
                            </div>
                            
                            <!-- Security Tab -->
                            <div class="tab-pane fade" id="security">
                                <div class="settings-header">
                                    <div class="d-flex align-items-center">
                                        <div class="settings-icon icon-security">
                                            <i class="fas fa-shield-alt fa-lg"></i>
                                        </div>
                                        <div>
                                            <h4 class="mb-1">Security Settings</h4>
                                            <p class="text-muted mb-0">Manage your password and security</p>
                                        </div>
                                    </div>
                                </div>
                                
                                <!-- Change Password -->
                                <div class="card settings-card mb-4">
                                    <div class="card-body">
                                        <h5 class="card-title">Change Password</h5>
                                        <form id="passwordForm">
                                            <div class="mb-3">
                                                <label class="form-label">Current Password</label>
                                                <input type="password" class="form-control" name="current_password" required>
                                            </div>
                                            <div class="mb-3">
                                                <label class="form-label">New Password</label>
                                                <input type="password" class="form-control" name="new_password" id="newPassword" required>
                                                <div class="password-strength" id="passwordStrength"></div>
                                            </div>
                                            <div class="mb-3">
                                                <label class="form-label">Confirm New Password</label>
                                                <input type="password" class="form-control" name="confirm_password" required>
                                            </div>
                                            <button type="submit" class="btn btn-primary">
                                                <i class="fas fa-key me-2"></i>Change Password
                                            </button>
                                        </form>
                                    </div>
                                </div>
                                
                                <!-- Active Sessions -->
                                <div class="card settings-card">
                                    <div class="card-body">
                                        <h5 class="card-title">Active Sessions</h5>
                                        <p class="text-muted">Manage your active login sessions</p>
                                        
                                        <div class="list-group">
    '''
    
    # Add active sessions
    for i, sess in enumerate(active_sessions):
        current_session_class = 'current-session' if sess['current'] else ''
        current_badge = '<span class="badge bg-success ms-2">Current Session</span>' if sess['current'] else ''
        terminate_button = ''
        if not sess['current']:
            terminate_button = f'''
                                                    <button class="btn btn-sm btn-outline-danger terminate-session" 
                                                            data-session-id="{i}">
                                                        <i class="fas fa-sign-out-alt"></i> Terminate
                                                    </button>'''
        
        settings_html += f'''
                                            <div class="list-group-item border-0 px-0 py-3 session-card {current_session_class}">
                                                <div class="d-flex justify-content-between align-items-center">
                                                    <div>
                                                        <h6 class="mb-1">{sess['device']}</h6>
                                                        <small class="text-muted">
                                                            <i class="fas fa-map-marker-alt me-1"></i>{sess['location']}
                                                            <i class="fas fa-network-wired ms-3 me-1"></i>{sess['ip']}
                                                        </small>
                                                        <div class="mt-1">
                                                            <small class="text-muted">
                                                                <i class="far fa-clock me-1"></i>Last active: {sess['last_active']}
                                                            </small>
                                                            {current_badge}
                                                        </div>
                                                    </div>
                                                    {terminate_button}
                                                </div>
                                            </div>'''
    
    settings_html += '''
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <!-- Notifications Tab -->
                            <div class="tab-pane fade" id="notifications">
                                <div class="settings-header">
                                    <div class="d-flex align-items-center">
                                        <div class="settings-icon icon-notifications">
                                            <i class="fas fa-bell fa-lg"></i>
                                        </div>
                                        <div>
                                            <h4 class="mb-1">Notification Settings</h4>
                                            <p class="text-muted mb-0">Configure how you receive notifications</p>
                                        </div>
                                    </div>
                                </div>
                                
                                <form id="notificationForm">
                                    <div class="card settings-card mb-3">
                                        <div class="card-body">
                                            <div class="d-flex justify-content-between align-items-center mb-3">
                                                <div>
                                                    <h6 class="mb-1">Email Notifications</h6>
                                                    <p class="text-muted mb-0">Receive notifications via email</p>
                                                </div>
                                                <label class="toggle-switch">
                                                    <input type="checkbox" name="email_notifications" checked>
                                                    <span class="toggle-slider"></span>
                                                </label>
                                            </div>
                                            
                                            <div class="d-flex justify-content-between align-items-center mb-3">
                                                <div>
                                                    <h6 class="mb-1">Push Notifications</h6>
                                                    <p class="text-muted mb-0">Receive browser notifications</p>
                                                </div>
                                                <label class="toggle-switch">
                                                    <input type="checkbox" name="push_notifications" checked>
                                                    <span class="toggle-slider"></span>
                                                </label>
                                            </div>
                                            
                                            <div class="d-flex justify-content-between align-items-center mb-3">
                                                <div>
                                                    <h6 class="mb-1">Form Updates</h6>
                                                    <p class="text-muted mb-0">Notify when forms are updated</p>
                                                </div>
                                                <label class="toggle-switch">
                                                    <input type="checkbox" name="form_updates" checked>
                                                    <span class="toggle-slider"></span>
                                                </label>
                                            </div>
                                            
                                            <div class="d-flex justify-content-between align-items-center mb-3">
                                                <div>
                                                    <h6 class="mb-1">Deadline Alerts</h6>
                                                    <p class="text-muted mb-0">Alert before form deadlines</p>
                                                </div>
                                                <label class="toggle-switch">
                                                    <input type="checkbox" name="deadline_alerts" checked>
                                                    <span class="toggle-slider"></span>
                                                </label>
                                            </div>
                                            
                                            <div class="d-flex justify-content-between align-items-center">
                                                <div>
                                                    <h6 class="mb-1">Weekly Digest</h6>
                                                    <p class="text-muted mb-0">Receive weekly summary emails</p>
                                                </div>
                                                <label class="toggle-switch">
                                                    <input type="checkbox" name="weekly_digest">
                                                    <span class="toggle-slider"></span>
                                                </label>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <button type="submit" class="btn btn-primary">
                                        <i class="fas fa-save me-2"></i>Save Preferences
                                    </button>
                                </form>
                            </div>
                            
                            <!-- Privacy Tab -->
                            <div class="tab-pane fade" id="privacy">
                                <div class="settings-header">
                                    <div class="d-flex align-items-center">
                                        <div class="settings-icon icon-privacy">
                                            <i class="fas fa-lock fa-lg"></i>
                                        </div>
                                        <div>
                                            <h4 class="mb-1">Privacy Settings</h4>
                                            <p class="text-muted mb-0">Control your data and privacy</p>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="card settings-card mb-4">
                                    <div class="card-body">
                                        <h5 class="card-title">Data Privacy</h5>
                                        <p class="text-muted">Manage how your data is used and stored</p>
                                        
                                        <div class="d-flex justify-content-between align-items-center mb-3">
                                            <div>
                                                <h6 class="mb-1">Allow Data Collection</h6>
                                                <p class="text-muted mb-0">Allow anonymous usage data collection</p>
                                            </div>
                                            <label class="toggle-switch">
                                                <input type="checkbox" checked>
                                                <span class="toggle-slider"></span>
                                            </label>
                                        </div>
                                        
                                        <div class="d-flex justify-content-between align-items-center mb-3">
                                            <div>
                                                <h6 class="mb-1">Show Profile to Others</h6>
                                                <p class="text-muted mb-0">Allow other users to view your profile</p>
                                            </div>
                                            <label class="toggle-switch">
                                                <input type="checkbox" checked>
                                                <span class="toggle-slider"></span>
                                            </label>
                                        </div>
                                        
                                        <div class="d-flex justify-content-between align-items-center">
                                            <div>
                                                <h6 class="mb-1">Email Visibility</h6>
                                                <p class="text-muted mb-0">Show email address to other users</p>
                                            </div>
                                            <label class="toggle-switch">
                                                <input type="checkbox">
                                                <span class="toggle-slider"></span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="card settings-card border-danger">
                                    <div class="card-body">
                                        <h5 class="card-title text-danger">Danger Zone</h5>
                                        <p class="text-muted">Permanent actions that cannot be undone</p>
                                        
                                        <div class="d-grid gap-2 d-md-flex">
                                            <button class="btn btn-outline-danger" data-bs-toggle="modal" data-bs-target="#deleteAccountModal">
                                                <i class="fas fa-trash me-2"></i>Delete Account
                                            </button>
                                            <button class="btn btn-outline-warning">
                                                <i class="fas fa-download me-2"></i>Export My Data
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Delete Account Modal -->
        <div class="modal fade" id="deleteAccountModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title text-danger">Delete Account</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            <strong>Warning:</strong> This action cannot be undone. All your data will be permanently deleted.
                        </div>
                        <p>To confirm account deletion, please type your password:</p>
                        <input type="password" class="form-control" id="deletePassword" placeholder="Enter your password">
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-danger" id="confirmDelete">Delete Account</button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Bootstrap JS -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <!-- jQuery -->
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        
        <script>
            $(document).ready(function() {
                // Profile form submission
                $('#profileForm').submit(function(e) {
                    e.preventDefault();
                    const formData = $(this).serialize();
                    
                    $.ajax({
                        url: '/api/settings/update-profile',
                        type: 'POST',
                        data: formData,
                        success: function(response) {
                            if (response.success) {
                                showAlert('Profile updated successfully!', 'success');
                            } else {
                                showAlert(response.message, 'error');
                            }
                        }
                    });
                });
                
                // Password form submission
                $('#passwordForm').submit(function(e) {
                    e.preventDefault();
                    
                    if ($('input[name="new_password"]').val() !== $('input[name="confirm_password"]').val()) {
                        showAlert('Passwords do not match!', 'error');
                        return;
                    }
                    
                    const formData = $(this).serialize();
                    
                    $.ajax({
                        url: '/api/settings/change-password',
                        type: 'POST',
                        data: formData,
                        success: function(response) {
                            if (response.success) {
                                showAlert('Password changed successfully!', 'success');
                                $('#passwordForm')[0].reset();
                            } else {
                                showAlert(response.message, 'error');
                            }
                        }
                    });
                });
                
                // Password strength indicator
                $('#newPassword').on('input', function() {
                    const password = $(this).val();
                    const strengthBar = $('#passwordStrength');
                    
                    if (password.length === 0) {
                        strengthBar.removeClass().addClass('password-strength');
                        return;
                    }
                    
                    let strength = 0;
                    if (password.length >= 8) strength++;
                    if (/[A-Z]/.test(password)) strength++;
                    if (/[0-9]/.test(password)) strength++;
                    if (/[^A-Za-z0-9]/.test(password)) strength++;
                    
                    strengthBar.removeClass().addClass('password-strength');
                    if (strength <= 1) {
                        strengthBar.addClass('strength-weak');
                    } else if (strength === 2) {
                        strengthBar.addClass('strength-fair');
                    } else if (strength === 3) {
                        strengthBar.addClass('strength-good');
                    } else {
                        strengthBar.addClass('strength-strong');
                    }
                });
                
                // Notification form submission
                $('#notificationForm').submit(function(e) {
                    e.preventDefault();
                    
                    const formData = {
                        email_notifications: $('input[name="email_notifications"]').is(':checked'),
                        push_notifications: $('input[name="push_notifications"]').is(':checked'),
                        form_updates: $('input[name="form_updates"]').is(':checked'),
                        deadline_alerts: $('input[name="deadline_alerts"]').is(':checked'),
                        weekly_digest: $('input[name="weekly_digest"]').is(':checked')
                    };
                    
                    $.ajax({
                        url: '/api/settings/update-notifications',
                        type: 'POST',
                        data: formData,
                        success: function(response) {
                            if (response.success) {
                                showAlert('Notification preferences updated!', 'success');
                            } else {
                                showAlert(response.message, 'error');
                            }
                        }
                    });
                });
                
                // Terminate session
                $('.terminate-session').click(function() {
                    const sessionId = $(this).data('session-id');
                    const button = $(this);
                    
                    $.ajax({
                        url: '/api/settings/terminate-session',
                        type: 'POST',
                        data: { session_id: sessionId },
                        success: function(response) {
                            if (response.success) {
                                button.closest('.session-card').fadeOut();
                                showAlert('Session terminated', 'success');
                            } else {
                                showAlert(response.message, 'error');
                            }
                        }
                    });
                });
                
                // Confirm account deletion
                $('#confirmDelete').click(function() {
                    const password = $('#deletePassword').val();
                    if (!password) {
                        showAlert('Please enter your password', 'error');
                        return;
                    }
                    
                    if (confirm('Are you absolutely sure? This cannot be undone!')) {
                        showAlert('Account deletion requested. This feature is disabled in demo.', 'warning');
                        $('#deleteAccountModal').modal('hide');
                    }
                });
                
                // Show alert function
                function showAlert(message, type) {
                    const alertClass = type === 'success' ? 'alert-success' : 'alert-danger';
                    const alert = $(
                        '<div class="alert ' + alertClass + ' alert-dismissible fade show position-fixed top-0 end-0 m-3" role="alert" style="z-index: 1050;">' +
                            message +
                            '<button type="button" class="btn-close" data-bs-dismiss="alert"></button>' +
                        '</div>'
                    );
                    
                    $('body').append(alert);
                    setTimeout(() => alert.alert('close'), 3000);
                }
            });
        </script>
    </body>
    </html>
    '''
    
    return settings_html


@app.route('/api/settings/update-profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    user_id = session['user_id']
    name = request.form.get('name')
    email = request.form.get('email')
    phone = request.form.get('phone', '')  # Default to empty string
    department = request.form.get('department')
    
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Check if phone column exists
            cursor.execute("SHOW COLUMNS FROM users LIKE 'phone'")
            phone_exists = cursor.fetchone()
            
            if phone_exists:
                cursor.execute("""
                    UPDATE users 
                    SET name = %s, email = %s, phone = %s, department = %s 
                    WHERE id = %s
                """, (name, email, phone, department, user_id))
            else:
                cursor.execute("""
                    UPDATE users 
                    SET name = %s, email = %s, department = %s 
                    WHERE id = %s
                """, (name, email, department, user_id))
        
        # Update session data
        session['name'] = name
        session['email'] = email
        session['department'] = department
        
        return jsonify({'success': True, 'message': 'Profile updated successfully'})
    except Exception as e:
        print(f"Update profile error: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/settings/change-password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    user_id = session['user_id']
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'Passwords do not match'})
    
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute("SELECT password FROM users WHERE id = %s", (user_id,))
            result = cursor.fetchone()
        
        if not result:
            return jsonify({'success': False, 'message': 'User not found'})
        
        # Verify current password (assuming plain text for demo - use hashing in production)
        if result['password'] != current_password:
            return jsonify({'success': False, 'message': 'Current password is incorrect'})
        
        # Update password
        with connection.cursor() as cursor:
            cursor.execute("UPDATE users SET password = %s WHERE id = %s", (new_password, user_id))
            connection.commit()
        connection.close()
        
        return jsonify({'success': True, 'message': 'Password changed successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/settings/update-notifications', methods=['POST'])
def update_notification_preferences():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    user_id = session['user_id']
    email_notifications = request.form.get('email_notifications') == 'true'
    push_notifications = request.form.get('push_notifications') == 'true'
    form_updates = request.form.get('form_updates') == 'true'
    deadline_alerts = request.form.get('deadline_alerts') == 'true'
    weekly_digest = request.form.get('weekly_digest') == 'true'
    
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Check if table exists, create if not
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notification_preferences (
                    user_id INT PRIMARY KEY,
                    email_notifications BOOLEAN DEFAULT TRUE,
                    push_notifications BOOLEAN DEFAULT TRUE,
                    form_updates BOOLEAN DEFAULT TRUE,
                    deadline_alerts BOOLEAN DEFAULT TRUE,
                    weekly_digest BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            
            cursor.execute("""
                INSERT INTO notification_preferences 
                (user_id, email_notifications, push_notifications, form_updates, deadline_alerts, weekly_digest)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                email_notifications = VALUES(email_notifications),
                push_notifications = VALUES(push_notifications),
                form_updates = VALUES(form_updates),
                deadline_alerts = VALUES(deadline_alerts),
                weekly_digest = VALUES(weekly_digest)
            """, (user_id, email_notifications, push_notifications, form_updates, deadline_alerts, weekly_digest))
            connection.commit()
        connection.close()
        
        return jsonify({'success': True, 'message': 'Notification preferences updated'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/settings/terminate-session', methods=['POST'])
def terminate_session():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    session_id = request.form.get('session_id')
    # In a real app, you would invalidate the session token in database
    return jsonify({'success': True, 'message': 'Session terminated'})

@app.route('/create-form', methods=['GET', 'POST'])
@login_required
def create_form():
    if session['role'] not in ['teacher', 'admin', 'super_admin']:
        return redirect('/create-student-form')
    
    if request.method == 'POST':
        try:
            # Get form data
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            department = request.form.get('department', session['department'])
            form_type = request.form.get('form_type', 'open')
            
            if not title:
                return jsonify({'error': 'Title is required'}), 400
            
            # FAST DATABASE OPERATION ONLY
            connection = get_db()
            form_id = None
            
            try:
                with connection.cursor() as cursor:
                    share_token = secrets.token_urlsafe(32)
                    cursor.execute('''
                        INSERT INTO forms (title, description, created_by, department, form_type, questions, share_token) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ''', (title, description, session['user_id'], department, form_type, '[]', share_token))
                    form_id = cursor.lastrowid
                    connection.commit()
            finally:
                connection.close()
            
            # BACKGROUND TASKS - DON'T WAIT
            def background_tasks():
                try:
                    # Notification
                    conn = get_db()
                    try:
                        with conn.cursor() as cursor:
                            cursor.execute('''
                                INSERT INTO notifications (user_id, title, message, type, link) 
                                VALUES (%s, %s, %s, %s, %s)
                            ''', (session['user_id'], 'Form Created', 
                                  f'Your form "{title}" has been created.', 
                                  'success', f'/form/{form_id}/edit'))
                            conn.commit()
                    finally:
                        conn.close()
                    
                    # Email
                    if ENABLE_EMAIL_NOTIFICATIONS:
                        html_content = f'''
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #667eea;">New Form Created</h2>
                            <p>Hello {session["name"]},</p>
                            <p>You have created: <strong>{title}</strong></p>
                            <p><strong>Type:</strong> {form_type.upper()}</p>
                            {'<p class="text-success"><strong>✓ PUBLIC FORM:</strong> Students from your department can take this form without requesting access.</p>' if form_type == 'public' else ''}
                        </div>
                        '''
                        send_email_async(session['email'], 'Form Created - FormMaster Pro', html_content)
                        
                except Exception as e:
                    print(f"Background task error: {e}")
            
            # Start background thread
            threading.Thread(target=background_tasks, daemon=True).start()
            
            # REDIRECT IMMEDIATELY
            return redirect(f'/form/{form_id}/edit')
            
        except Exception as e:
            print(f"Create form error: {e}")
            return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')
    
    # Show all departments for admin/super_admin, only user's department for teachers
    if session['role'] in ['admin', 'super_admin']:
        departments_options = ''.join([f'<option value="{dept}" {"selected" if dept == session.get("department") else ""}>{dept}</option>' for dept in DEPARTMENTS])
    else:
        departments_options = f'<option value="{session.get("department")}" selected>{session.get("department")}</option>'
    
    content = f'''
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">
                    <h4 class="mb-0">Create New Form (Teacher/Admin)</h4>
                </div>
                <div class="card-body">
                    <form method="POST">
                        <div class="mb-3">
                            <label class="form-label">Form Title *</label>
                            <input type="text" class="form-control" name="title" required 
                                   placeholder="Enter form title">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Description</label>
                            <textarea class="form-control" name="description" rows="3" 
                                      placeholder="Enter form description"></textarea>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Department *</label>
                            <select class="form-select" name="department" required>
                                {departments_options}
                            </select>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Form Type *</label>
                            <select class="form-select" name="form_type" required>
                                <option value="public">Public - Students from selected department can take without requesting</option>
                                <option value="open">Open - Students can request to take</option>
                                <option value="confidential">Confidential - Students must request access</option>
                            </select>
                            <small class="text-muted">
                                <strong>Public Forms:</strong> Students from the selected department can take the test immediately without requesting access.<br>
                                <strong>Open Forms:</strong> Students need to request access and await approval.<br>
                                <strong>Confidential Forms:</strong> Students must request access and await approval.
                            </small>
                        </div>
                        <div class="d-flex gap-2">
                            <a href="/dashboard" class="btn btn-secondary">Cancel</a>
                            <button type="submit" class="btn btn-primary">Create Form</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
    '''
    return html_wrapper('Create Form', content, get_navbar(), '')

@app.route('/create-student-form', methods=['GET', 'POST'])
@student_required
def create_student_form():
    if request.method == 'POST':
        try:
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            department = session['department']
            form_type = request.form.get('form_type', 'open')
            reviewer_id = request.form.get('reviewer_id')
            
            if not title or not reviewer_id:
                return jsonify({'error': 'Title and reviewer are required'}), 400
            
            # FAST DATABASE OPERATION
            connection = get_db()
            form_id = None
            reviewer_email = None
            reviewer_name = None
            
            try:
                with connection.cursor() as cursor:
                    # Get reviewer info
                    cursor.execute('SELECT name, email FROM users WHERE id = %s', (reviewer_id,))
                    reviewer = cursor.fetchone()
                    if reviewer:
                        reviewer_email = reviewer['email']
                        reviewer_name = reviewer['name']
                    
                    # Create form
                    share_token = secrets.token_urlsafe(32)
                    cursor.execute('''
                        INSERT INTO forms (title, description, created_by, department, form_type, questions, 
                                          is_student_submission, review_status, reviewed_by, share_token) 
                        VALUES (%s, %s, %s, %s, %s, %s, TRUE, 'pending', %s, %s)
                    ''', (title, description, session['user_id'], department, form_type, '[]', reviewer_id, share_token))
                    form_id = cursor.lastrowid
                    
                    # Create review entry
                    cursor.execute('''
                        INSERT INTO student_form_reviews (form_id, student_id, reviewer_id, review_status)
                        VALUES (%s, %s, %s, 'pending')
                    ''', (form_id, session['user_id'], reviewer_id))
                    
                    connection.commit()
            finally:
                connection.close()
            
            # BACKGROUND TASKS
            def background_tasks():
                try:
                    # Student notification
                    conn = get_db()
                    try:
                        with conn.cursor() as cursor:
                            cursor.execute('''
                                INSERT INTO notifications (user_id, title, message, type, link) 
                                VALUES (%s, %s, %s, %s, %s)
                            ''', (session['user_id'], 'Student Form Created',
                                  f'Your form "{title}" is pending review.', 
                                  'success', f'/student-form/{form_id}/edit'))
                            
                            # Reviewer notification
                            cursor.execute('''
                                INSERT INTO notifications (user_id, title, message, type, link) 
                                VALUES (%s, %s, %s, %s, %s)
                            ''', (reviewer_id, 'New Student Form for Review',
                                  f'A student form "{title}" needs your review.', 
                                  'warning', '/review-forms'))
                            
                            conn.commit()
                    finally:
                        conn.close()
                    
                    # Emails in background
                    if ENABLE_EMAIL_NOTIFICATIONS:
                        # Email to student (simplified)
                        student_html = f'''
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2>Student Form Created</h2>
                            <p>Your form "{title}" is pending review by {reviewer_name}.</p>
                        </div>
                        '''
                        send_email_async(session['email'], 'Student Form Created', student_html)
                        
                        # Email to reviewer (simplified)
                        if reviewer_email:
                            reviewer_html = f'''
                            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                                <h2>New Student Form for Review</h2>
                                <p>Student {session["name"]} submitted form "{title}".</p>
                            </div>
                            '''
                            send_email_async(reviewer_email, 'New Student Form for Review', reviewer_html)
                            
                except Exception as e:
                    print(f"Student form background error: {e}")
            
            # Start background thread
            threading.Thread(target=background_tasks, daemon=True).start()
            
            # REDIRECT IMMEDIATELY
            return redirect(f'/student-form/{form_id}/edit')
            
        except Exception as e:
            print(f"Create student form error: {e}")
            return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')
    
    # Get available teachers for review
    connection = get_db()
    with connection.cursor() as cursor:
        cursor.execute('''
            SELECT id, name, email, role, department 
            FROM users 
            WHERE role IN ('teacher', 'admin', 'super_admin') 
            AND department = %s
            ORDER BY name
        ''', (session['department'],))
        reviewers = cursor.fetchall()
    connection.close()
    
    reviewers_options = '<option value="">Select a reviewer...</option>'
    for reviewer in reviewers:
        role_text = 'Teacher' if reviewer['role'] == 'teacher' else 'Admin' if reviewer['role'] == 'admin' else 'Super Admin'
        reviewers_options += f'<option value="{reviewer["id"]}">{reviewer["name"]} ({reviewer["email"]}) - {role_text}</option>'
    
    content = f'''
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">
                    <h4 class="mb-0">Create New Form (Student)</h4>
                    <p class="mb-0 text-muted">Your form will be submitted for review before being published</p>
                </div>
                <div class="card-body">
                    <form method="POST">
                        <div class="mb-3">
                            <label class="form-label">Form Title *</label>
                            <input type="text" class="form-control" name="title" required 
                                   placeholder="Enter form title">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Description</label>
                            <textarea class="form-control" name="description" rows="3" 
                                      placeholder="Enter form description"></textarea>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Department</label>
                            <input type="text" class="form-control" value="{session['department']}" readonly>
                            <small class="text-muted">Your department is automatically assigned</small>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Form Type *</label>
                            <select class="form-select" name="form_type" required>
                                <option value="open">Open - Other students can request to take</option>
                                <option value="confidential">Confidential - Students must request access</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Select Reviewer *</label>
                            <select class="form-select" name="reviewer_id" required>
                                {reviewers_options}
                            </select>
                            <small class="text-muted">
                                Choose a teacher or admin from your department to review your form.
                                The reviewer will become co-owner of the form once approved.
                            </small>
                        </div>
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle me-2"></i>
                            <strong>Important:</strong> After creating the form, you'll be able to add questions.
                            Once you submit for review, the selected reviewer will need to approve it before
                            it becomes available to other students.
                        </div>
                        <div class="d-flex gap-2">
                            <a href="/dashboard" class="btn btn-secondary">Cancel</a>
                            <button type="submit" class="btn btn-success">Create & Add Questions</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
    '''
    return html_wrapper('Create Student Form', content, get_navbar(), '')

@app.route('/student-form/<int:form_id>/edit')
@student_required
def edit_student_form(form_id):
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT f.*, u.name as reviewer_name, u.email as reviewer_email
                FROM forms f 
                LEFT JOIN users u ON f.reviewed_by = u.id
                WHERE f.id = %s
            ''', (form_id,))
            form = cursor.fetchone()
        connection.close()
        
        if not form:
            return redirect('/dashboard')
        
        # Check permissions - only creator can edit
        if form['created_by'] != session['user_id']:
            return html_wrapper('Error', '<div class="alert alert-danger">Access denied</div>', get_navbar(), '')
        
        # Check if form is already approved or rejected
        if form['review_status'] == 'approved':
            return html_wrapper('Error', '''
            <div class="alert alert-success">
                <h4>Form Already Approved</h4>
                <p>This form has been approved and published. You cannot edit it anymore.</p>
                <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
            </div>
            ''', get_navbar(), '')
        
        if form['review_status'] == 'rejected':
            return html_wrapper('Error', f'''
            <div class="alert alert-danger">
                <h4>Form Rejected</h4>
                <p>This form was rejected by the reviewer. You cannot edit it.</p>
                <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
            </div>
            ''', get_navbar(), '')
        
        # Parse JSON questions
        try:
            if form['questions'] and isinstance(form['questions'], str):
                questions = json.loads(form['questions'])
            elif form['questions'] and isinstance(form['questions'], dict):
                questions = form['questions']
            else:
                questions = []
        except:
            questions = []
        
        reviewer_info = ''
        if form['reviewed_by']:
            reviewer_info = f'''
            <div class="alert alert-info">
                <i class="fas fa-user-check me-2"></i>
                <strong>Reviewer:</strong> {form['reviewer_name']} ({form['reviewer_email']})
            </div>
            '''
        
        # Create the publish button HTML conditionally
        publish_button_html = ''
        if session['role'] in ['admin', 'super_admin'] and form.get('review_status') == 'approved':
            btn_class = 'btn-warning' if form['is_published'] else 'btn-info'
            icon_class = 'fa-eye-slash' if form['is_published'] else 'fa-eye'
            btn_text = 'Unpublish' if form['is_published'] else 'Publish'
            publish_button_html = f'''
                        <button onclick="togglePublish()" class="btn {btn_class}">
                            <i class="fas {icon_class} me-2"></i>
                            {btn_text}
                        </button>
                        '''
        
        content = f'''
        <div class="row">
            <div class="col-md-3">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5 class="mb-0">Add Questions</h5>
                    </div>
                    <div class="card-body">
                        <button onclick="addQuestion('mcq')" class="btn btn-outline-primary w-100 mb-2">
                            <i class="fas fa-dot-circle me-2"></i>Multiple Choice
                        </button>
                        <button onclick="addQuestion('true_false')" class="btn btn-outline-primary w-100 mb-2">
                            <i class="fas fa-balance-scale me-2"></i>True/False
                        </button>
                        <button onclick="addQuestion('short_answer')" class="btn btn-outline-primary w-100 mb-2">
                            <i class="fas fa-pen me-2"></i>Short Answer
                        </button>
                    </div>
                </div>
            </div>
            
            <div class="col-md-9">
                <div class="card student-form-card">
                    <div class="card-header">
                        <h4 class="mb-0">
                            <i class="fas fa-user-graduate me-2"></i>Editing Student Form: {form['title']}
                            <span class="badge {'badge-warning' if form['review_status'] == 'pending' else 'badge-success'}">
                                {form['review_status'].title()}
                            </span>
                        </h4>
                        <p class="mb-0">{form['description'] or 'No description'}</p>
                        {reviewer_info}
                    </div>
                    <div class="card-body">
                        <div id="questions-container"></div>
                        
                        <div id="no-questions" class="text-center py-5">
                            <i class="fas fa-poll fa-3x text-muted mb-3"></i>
                            <h5>No questions added yet</h5>
                            <p class="text-muted">Click on question types to add questions</p>
                        </div>
                    </div>
                    <div class="card-footer">
                        <button onclick="saveForm()" class="btn btn-success">
                            <i class="fas fa-save me-2"></i>Save Questions
                        </button>
                        <button onclick="submitForReview()" class="btn btn-primary">
                            <i class="fas fa-paper-plane me-2"></i>Submit for Review
                        </button>
                        {publish_button_html}
                        <a href="/dashboard" class="btn btn-secondary">Back to Dashboard</a>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        scripts = f'''
        <script>
            let questions = {json.dumps(questions)};
            let formId = {form_id};
            
            function renderQuestions() {{
                const container = document.getElementById('questions-container');
                if (questions.length === 0) {{
                    document.getElementById('no-questions').style.display = 'block';
                    container.innerHTML = '';
                    return;
                }}
                
                document.getElementById('no-questions').style.display = 'none';
                container.innerHTML = '';
                
                questions.forEach((q, index) => {{
                    let optionsHtml = '';
                    if (q.type === 'mcq') {{
                        optionsHtml = '<div class="mb-3"><label>Options (Select correct one)</label>';
                        if (q.options) {{
                            q.options.forEach((option, optIndex) => {{
                                optionsHtml += `
                                    <div class="input-group mb-2">
                                        <div class="input-group-text">
                                            <input class="form-check-input" type="radio" name="correct_${{q.id}}" 
                                                   value="${{optIndex}}" ${{q.correct_answer == optIndex ? 'checked' : ''}}
                                                   onchange="updateQuestion(${{index}}, 'correct_answer', ${{optIndex}})">
                                        </div>
                                        <input type="text" class="form-control" value="${{option}}"
                                               onchange="updateOption(${{index}}, ${{optIndex}}, this.value)">
                                        <button class="btn btn-outline-danger" onclick="removeOption(${{index}}, ${{optIndex}})">
                                            <i class="fas fa-times"></i>
                                        </button>
                                    </div>
                                `;
                            }});
                        }}
                        optionsHtml += `
                            <button class="btn btn-sm btn-outline-primary" onclick="addOption(${{index}})">
                                <i class="fas fa-plus"></i> Add Option
                            </button>
                        `;
                        optionsHtml += '</div>';
                    }} else if (q.type === 'true_false') {{
                        optionsHtml = `
                            <div class="mb-3">
                                <label>Correct Answer</label>
                                <select class="form-select" onchange="updateQuestion(${{index}}, 'correct_answer', this.value)">
                                    <option value="true" ${{q.correct_answer === 'true' ? 'selected' : ''}}>True</option>
                                    <option value="false" ${{q.correct_answer === 'false' ? 'selected' : ''}}>False</option>
                                </select>
                            </div>
                        `;
                    }}
                    
                    const questionHTML = `
                        <div class="card question-card mb-3">
                            <div class="card-body">
                                <div class="d-flex justify-content-between mb-2">
                                    <span class="badge bg-secondary">${{q.type.toUpperCase()}}</span>
                                    <button class="btn btn-sm btn-outline-danger" onclick="deleteQuestion(${{index}})">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </div>
                                
                                <div class="mb-3">
                                    <label>Question</label>
                                    <input type="text" class="form-control" value="${{q.question || ''}}" 
                                           onchange="updateQuestion(${{index}}, 'question', this.value)">
                                </div>
                                
                                <div class="row mb-3">
                                    <div class="col-md-6">
                                        <label>Marks</label>
                                        <input type="number" class="form-control" value="${{q.marks || 1}}" min="1"
                                               onchange="updateQuestion(${{index}}, 'marks', this.value)">
                                    </div>
                                    <div class="col-md-6">
                                        <div class="form-check mt-4">
                                            <input type="checkbox" class="form-check-input" ${{q.required ? 'checked' : ''}}
                                                   onchange="updateQuestion(${{index}}, 'required', this.checked)">
                                            <label class="form-check-label">Required</label>
                                        </div>
                                    </div>
                                </div>
                                
                                ${{optionsHtml}}
                            </div>
                        </div>
                    `;
                    container.innerHTML += questionHTML;
                }});
            }}
            
            function addQuestion(type) {{
                const question = {{
                    id: Date.now(),
                    type: type,
                    question: '',
                    required: false,
                    marks: 1
                }};
                
                if (type === 'mcq') {{
                    question.options = ['Option 1', 'Option 2'];
                    question.correct_answer = 0;
                }} else if (type === 'true_false') {{
                    question.correct_answer = 'true';
                }}
                
                questions.push(question);
                renderQuestions();
            }}
            
            function updateQuestion(index, field, value) {{
                questions[index][field] = value;
            }}
            
            function addOption(index) {{
                if (!questions[index].options) questions[index].options = [];
                questions[index].options.push('Option ' + (questions[index].options.length + 1));
                renderQuestions();
            }}
            
            function removeOption(index, optIndex) {{
                questions[index].options.splice(optIndex, 1);
                if (questions[index].correct_answer == optIndex) {{
                    questions[index].correct_answer = '';
                }}
                renderQuestions();
            }}
            
            function updateOption(index, optIndex, value) {{
                questions[index].options[optIndex] = value;
            }}
            
            function deleteQuestion(index) {{
                if (confirm('Delete this question?')) {{
                    questions.splice(index, 1);
                    renderQuestions();
                }}
            }}
            
            function saveForm() {{
                fetch('/api/student-form/' + formId, {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{ questions: questions }})
                }})
                .then(res => {{
                    if (!res.ok) {{
                        return res.text().then(text => {{
                            throw new Error(`HTTP error! status: ${{res.status}}, body: ${{text}}`);
                        }});
                    }}
                    return res.json();
                }})
                .then(data => {{
                    if (data.success) {{
                        alert('Questions saved successfully!');
                    }} else {{
                        alert('Error saving questions: ' + data.error);
                    }}
                }})
                .catch(error => {{
                    console.error('Error:', error);
                    alert('Error saving form. Please try again. If the problem persists, contact support.');
                }});
            }}
            
            function submitForReview() {{
                if (questions.length === 0) {{
                    alert('Please add at least one question before submitting for review.');
                    return;
                }}
                
                if (confirm('Submit this form for review? Once submitted, you cannot edit it until it is reviewed.')) {{
                    fetch('/api/submit-for-review/' + formId, {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }}
                    }})
                    .then(res => res.json())
                    .then(data => {{
                        if (data.success) {{
                            alert('Form submitted for review successfully!');
                            window.location.href = '/my-submissions';
                        }} else {{
                            alert('Error: ' + data.error);
                        }}
                    }})
                    .catch(error => {{
                        alert('Error: ' + error);
                    }});
                }}
            }}
            
            // Initial render
            renderQuestions();
        </script>
        '''
        
        return html_wrapper('Edit Student Form', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"Edit student form error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/api/submit-for-review/<int:form_id>', methods=['POST'])
@student_required
def submit_for_review(form_id):
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Get form details first
            cursor.execute('''
                SELECT f.*, u2.email as reviewer_email, u2.name as reviewer_name
                FROM forms f
                JOIN users u2 ON f.reviewed_by = u2.id
                WHERE f.id = %s
            ''', (form_id,))
            form = cursor.fetchone()
            
            if not form:
                connection.close()
                return jsonify({'success': False, 'error': 'Form not found'})
            
            # Update form status to pending review
            cursor.execute('''
                UPDATE forms 
                SET review_status = 'pending', is_published = FALSE
                WHERE id = %s AND created_by = %s
            ''', (form_id, session['user_id']))
            
            connection.commit()
        connection.close()
        
        # Create notification for student
        create_notification(
            user_id=session['user_id'],
            title='Form Submitted for Review',
            message=f'Your form "{form["title"]}" has been submitted for review.',
            type='success',
            link='/my-submissions'
        )
        
        # Create notification for reviewer
        create_notification(
            user_id=form['reviewed_by'],
            title='New Form for Review',
            message=f'A new student form "{form["title"]}" has been submitted for your review.',
            type='warning',
            link='/review-forms'
        )
        
        # Send submission notification emails
        if ENABLE_EMAIL_NOTIFICATIONS:
            # Email to student
            html_content = f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #667eea;">Form Submitted for Review</h2>
                <p>Hello {session['name']},</p>
                <p>Your form "{form['title']}" has been submitted for review.</p>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 20px 0;">
                    <p><strong>Form Details:</strong></p>
                    <p>Title: {form['title']}</p>
                    <p>Description: {form['description'] or 'No description'}</p>
                    <p>Department: {form['department']}</p>
                    <p>Reviewer: {form['reviewer_name']}</p>
                    <p>Submission Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                <p>You will be notified when the reviewer approves or rejects your form.</p>
                <hr>
                <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
            </div>
            '''
            send_email(session['email'], 'Form Submitted for Review - FormMaster Pro', html_content)
            
            # Email to reviewer
            html_content_reviewer = f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #667eea;">Form Ready for Review</h2>
                <p>Hello {form['reviewer_name']},</p>
                <p>A student has submitted a form for your review.</p>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 20px 0;">
                    <p><strong>Form Details:</strong></p>
                    <p>Title: {form['title']}</p>
                    <p>Description: {form['description'] or 'No description'}</p>
                    <p>Department: {form['department']}</p>
                    <p>Student: {session['name']} ({session['email']})</p>
                    <p>Submission Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                <a href="https://formmaster.up.railway.app/review-forms" style="display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">Review Forms</a>
                <hr>
                <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
            </div>
            '''
            send_email(form['reviewer_email'], 'New Form for Review - FormMaster Pro', html_content_reviewer)
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Submit for review error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/my-submissions')
@student_required
def my_submissions():
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT f.*, u.name as reviewer_name, u.email as reviewer_email,
                       (SELECT COUNT(*) FROM responses WHERE form_id = f.id) as response_count
                FROM forms f 
                LEFT JOIN users u ON f.reviewed_by = u.id
                WHERE f.created_by = %s 
                AND f.is_student_submission = TRUE
                ORDER BY f.created_at DESC
            ''', (session['user_id'],))
            submissions = cursor.fetchall()
        connection.close()
        
        submissions_html = ''
        for sub in submissions:
            status_badge = 'warning'
            status_text = 'Pending Review'
            if sub['review_status'] == 'approved':
                status_badge = 'success'
                status_text = 'Approved & Published'
            elif sub['review_status'] == 'rejected':
                status_badge = 'danger'
                status_text = 'Rejected'
            
            type_badge = 'info' if sub['form_type'] == 'open' else 'purple'
            type_text = 'Open' if sub['form_type'] == 'open' else 'Confidential'
            
            reviewer_info = f'<small class="text-muted">Reviewer: {sub["reviewer_name"] or "Not assigned"}</small>'
            if sub['reviewed_at']:
                reviewer_info += f'<br><small class="text-muted">Reviewed: {sub["reviewed_at"]}</small>'
            
            actions = ''
            if sub['review_status'] == 'pending':
                actions = f'''
                <a href="/student-form/{sub['id']}/edit" class="btn btn-sm btn-outline-primary">
                    <i class="fas fa-edit"></i> Edit
                </a>
                '''
            
            submissions_html += f'''
            <div class="card mb-3 student-form-card">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <h5 class="mb-1">{sub['title']}</h5>
                            <p class="text-muted mb-2">{sub['description'][:100] if sub['description'] else 'No description'}...</p>
                            <small class="text-muted">
                                <span class="badge {type_badge}">{type_text}</span> |
                                <i class="fas fa-building me-1"></i>{sub['department']} |
                                {reviewer_info}
                            </small>
                        </div>
                        <span class="badge bg-{status_badge}">{status_text}</span>
                    </div>
                    <div class="mt-3">
                        <small class="text-muted">
                            <i class="fas fa-chart-bar me-1"></i>{sub['response_count']} responses |
                            <i class="fas fa-calendar me-1"></i>Created: {sub['created_at'].strftime('%Y-%m-%d')}
                        </small>
                        <div class="form-actions mt-2">
                            {actions}
                        </div>
                    </div>
                </div>
            </div>
            '''
        
        if not submissions_html:
            submissions_html = '''
            <div class="text-center py-5">
                <i class="fas fa-file-alt fa-3x text-muted mb-3"></i>
                <h4>No submissions yet</h4>
                <p class="text-muted">You haven't created any forms for review yet.</p>
                <a href="/create-student-form" class="btn btn-success">
                    <i class="fas fa-plus-circle me-2"></i>Create Your First Form
                </a>
            </div>
            '''
        
        content = f'''
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2 class="text-white">My Form Submissions</h2>
            <a href="/create-student-form" class="btn btn-success">
                <i class="fas fa-plus-circle me-2"></i>Create New Form
            </a>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-history me-2"></i>Submitted Forms ({len(submissions)})
                </h5>
            </div>
            <div class="card-body">
                {submissions_html}
            </div>
        </div>
        '''
        
        return html_wrapper('My Submissions', content, get_navbar(), '')
        
    except Exception as e:
        print(f"My submissions error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/my-responses')
@student_required
def my_responses():
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT r.*, f.title, f.department, u.name as teacher_name
                FROM responses r
                JOIN forms f ON r.form_id = f.id
                LEFT JOIN users u ON f.created_by = u.id
                WHERE r.student_id = %s
                ORDER BY r.submitted_at DESC
            ''', (session['user_id'],))
            responses = cursor.fetchall()
            
            cursor.execute('''
                SELECT 
                    AVG(percentage) as avg_score,
                    MAX(percentage) as highest_score,
                    MIN(percentage) as lowest_score,
                    COUNT(*) as total_responses
                FROM responses 
                WHERE student_id = %s
            ''', (session['user_id'],))
            stats = cursor.fetchone()
        connection.close()
        
        responses_html = ''
        for resp in responses:
            score_class = 'text-success' if resp['percentage'] >= 70 else 'text-warning' if resp['percentage'] >= 50 else 'text-danger'
            responses_html += f'''
            <tr>
                <td>{resp['title']}</td>
                <td>{resp['department']}</td>
                <td>{resp['teacher_name'] or 'N/A'}</td>
                <td><span class="{score_class} fw-bold">{resp['score']}/{resp['total_marks']}</span></td>
                <td><span class="{score_class} fw-bold">{resp['percentage']}%</span></td>
                <td>{resp['submitted_at'].strftime('%Y-%m-%d %H:%M')}</td>
            </tr>
            '''
        
        stats_html = ''
        if stats and stats['total_responses'] > 0:
            stats_html = f'''
            <div class="row mb-4">
                <div class="col-md-3">
                    <div class="stat-card student-stats-card">
                        <h5>Total Responses</h5>
                        <h2>{stats['total_responses']}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(45deg, #3b82f6, #1d4ed8);">
                        <h5>Average Score</h5>
                        <h2>{stats['avg_score']:.1f}%</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(45deg, #10b981, #059669);">
                        <h5>Highest Score</h5>
                        <h2>{stats['highest_score']:.1f}%</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(45deg, #f59e0b, #d97706);">
                        <h5>Lowest Score</h5>
                        <h2>{stats['lowest_score']:.1f}%</h2>
                    </div>
                </div>
            </div>
            '''
        
        content = f'''
        <div class="mb-4">
            <h2 class="text-white">My Form Results</h2>
            <p class="text-white-50">Track your performance across all forms you've taken</p>
        </div>
        
        {stats_html}
        
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-chart-bar me-2"></i>Response History ({len(responses)})
                </h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Form Title</th>
                                <th>Department</th>
                                <th>Teacher</th>
                                <th>Score</th>
                                <th>Percentage</th>
                                <th>Submitted</th>
                            </tr>
                        </thead>
                        <tbody>
                            {responses_html}
                        </tbody>
                    </table>
                </div>
                {f'<div class="text-center mt-3"><small class="text-muted">Showing {len(responses)} responses</small></div>' if responses else ''}
            </div>
        </div>
        
                ''' + ("""
        <div class="text-center py-5">
            <i class="fas fa-chart-line fa-3x text-muted mb-3"></i>
            <h4>No responses yet</h4>
            <p class="text-muted">You haven't taken any forms yet.</p>
            <a href="/dashboard" class="btn btn-primary">
                <i class="fas fa-list me-2"></i>Browse Available Forms
            </a>
        </div>
        """ if not responses else '') + '''
        '''
        
        return html_wrapper('My Results', content, get_navbar(), '')
        
    except Exception as e:
        print(f"My responses error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/review-forms')
@teacher_required
def review_forms():
    try:
        connection = get_db()
        user_dept = session['department']
        
        # Get selected department for admin/super_admin
        selected_dept = request.args.get('department', '')
        
        with connection.cursor() as cursor:
            if session['role'] in ['admin', 'super_admin']:
                query = '''
                    SELECT f.*, u.name as student_name, u.email as student_email, 
                           u2.name as reviewer_name, u2.email as reviewer_email
                    FROM forms f
                    JOIN users u ON f.created_by = u.id
                    LEFT JOIN users u2 ON f.reviewed_by = u2.id
                    WHERE f.is_student_submission = TRUE 
                    AND f.review_status = 'pending'
                '''
                params = []
                
                if selected_dept:
                    query += ' AND f.department = %s'
                    params.append(selected_dept)
                
                query += ' ORDER BY f.created_at DESC'
                cursor.execute(query, params)
            else:
                cursor.execute('''
                    SELECT f.*, u.name as student_name, u.email as student_email
                    FROM forms f
                    JOIN users u ON f.created_by = u.id
                    WHERE f.is_student_submission = TRUE 
                    AND f.review_status = 'pending'
                    AND f.department = %s
                    ORDER BY f.created_at DESC
                ''', (user_dept,))
            
            pending_forms = cursor.fetchall()
            
            # Get recently reviewed forms
            if session['role'] in ['admin', 'super_admin']:
                query = '''
                    SELECT f.*, u.name as student_name, u.email as student_email,
                           u2.name as reviewer_name
                    FROM forms f
                    JOIN users u ON f.created_by = u.id
                    LEFT JOIN users u2 ON f.reviewed_by = u2.id
                    WHERE f.is_student_submission = TRUE 
                    AND f.review_status IN ('approved', 'rejected')
                '''
                params = []
                
                if selected_dept:
                    query += ' AND f.department = %s'
                    params.append(selected_dept)
                
                query += ' ORDER BY f.reviewed_at DESC LIMIT 10'
                cursor.execute(query, params)
            else:
                cursor.execute('''
                    SELECT f.*, u.name as student_name, u.email as student_email,
                           u2.name as reviewer_name
                    FROM forms f
                    JOIN users u ON f.created_by = u.id
                    LEFT JOIN users u2 ON f.reviewed_by = u2.id
                    WHERE f.is_student_submission = TRUE 
                    AND f.review_status IN ('approved', 'rejected')
                    AND f.department = %s
                    ORDER BY f.reviewed_at DESC
                    LIMIT 10
                ''', (user_dept,))
            reviewed_forms = cursor.fetchall()
        
        connection.close()
        
        # Department filter for admin/super_admin
        dept_filter_html = ''
        if session['role'] in ['admin', 'super_admin']:
            departments_options = '<option value="">All Departments</option>'
            for dept in DEPARTMENTS:
                selected = 'selected' if dept == selected_dept else ''
                departments_options += f'<option value="{dept}" {selected}>{dept}</option>'
            
            dept_filter_html = f'''
            <div class="dept-filter mb-4">
                <h5 class="mb-3">Department Filter</h5>
                <form method="GET" action="/review-forms" class="row align-items-center">
                    <div class="col-md-4">
                        <select class="form-select" name="department" onchange="this.form.submit()">
                            {departments_options}
                        </select>
                    </div>
                    <div class="col-md-8">
                        <small class="text-muted">
                            Showing forms from: {selected_dept if selected_dept else "All Departments"}
                        </small>
                    </div>
                </form>
            </div>
            '''
        
        pending_html = ''
        for form in pending_forms:
            type_badge = 'info' if form['form_type'] == 'open' else 'purple'
            pending_html += f'''
            <div class="card mb-3 student-form-card">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <h5 class="mb-1">{form['title']}</h5>
                            <p class="text-muted mb-2">{form['description'][:150] if form['description'] else 'No description'}...</p>
                            <small class="text-muted">
                                <strong>Student:</strong> {form['student_name']} ({form['student_email']})<br>
                                <strong>Department:</strong> {form['department']} |
                                <span class="badge {type_badge}">{form['form_type'].title()}</span>
                            </small>
                        </div>
                        <span class="badge bg-warning">Pending Review</span>
                    </div>
                    <div class="mt-3">
                        <button onclick="viewForm({form['id']})" class="btn btn-sm btn-primary">
                            <i class="fas fa-eye"></i> View Form
                        </button>
                        <button onclick="approveForm({form['id']})" class="btn btn-sm btn-success">
                            <i class="fas fa-check"></i> Approve
                        </button>
                        <button onclick="rejectForm({form['id']})" class="btn btn-sm btn-danger">
                            <i class="fas fa-times"></i> Reject
                        </button>
                    </div>
                </div>
            </div>
            '''
        
        if not pending_html:
            pending_html = f'''
            <div class="alert alert-info">
                <i class="fas fa-info-circle me-2"></i>
                No forms pending review {f'for department: {selected_dept}' if selected_dept else ''}.
            </div>
            '''
        
        reviewed_html = ''
        for form in reviewed_forms:
            status_badge = 'success' if form['review_status'] == 'approved' else 'danger'
            status_text = 'Approved' if form['review_status'] == 'approved' else 'Rejected'
            reviewed_html += f'''
            <tr>
                <td>{form['title']}</td>
                <td>{form['student_name']}</td>
                <td>{form['department']}</td>
                <td><span class="badge bg-{status_badge}">{status_text}</span></td>
                <td>{form['reviewer_name'] or 'N/A'}</td>
                <td>{form['reviewed_at'].strftime('%Y-%m-%d') if form['reviewed_at'] else 'N/A'}</td>
            </tr>
            '''
        
        content = f'''
        <div class="mb-4">
            <h2 class="text-white">Review Student Forms</h2>
            <p class="text-white-50">Approve or reject forms created by students</p>
        </div>
        
        {dept_filter_html}
        
        <div class="row">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-clock me-2"></i>Pending Review ({len(pending_forms)})
                        </h5>
                    </div>
                    <div class="card-body">
                        {pending_html}
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-history me-2"></i>Recently Reviewed
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Form</th>
                                        <th>Student</th>
                                        <th>Dept</th>
                                        <th>Status</th>
                                        <th>Reviewer</th>
                                        <th>Date</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {reviewed_html}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        scripts = '''
        <script>
            function viewForm(formId) {
                window.open('/form/' + formId + '/preview', '_blank');
            }
            
            function approveForm(formId) {
                if (confirm('Approve this student form? It will be published and available to other students.')) {
                    fetch('/api/review-form/' + formId, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({action: 'approve'})
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            alert('Form approved successfully!');
                            window.location.reload();
                        } else {
                            alert('Error: ' + data.error);
                        }
                    });
                }
            }
            
            function rejectForm(formId) {
                const reason = prompt('Please enter reason for rejection:');
                if (reason !== null) {
                    fetch('/api/review-form/' + formId, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({action: 'reject', reason: reason})
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            alert('Form rejected successfully!');
                            window.location.reload();
                        } else {
                            alert('Error: ' + data.error);
                        }
                    });
                }
            }
        </script>
        '''
        
        return html_wrapper('Review Forms', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"Review forms error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/form/<int:form_id>/preview')
@login_required
def preview_form(form_id):
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT f.*, u.name as creator_name, u2.name as reviewer_name
                FROM forms f
                JOIN users u ON f.created_by = u.id
                LEFT JOIN users u2 ON f.reviewed_by = u2.id
                WHERE f.id = %s
            ''', (form_id,))
            form = cursor.fetchone()
        connection.close()
        
        if not form:
            return html_wrapper('Error', '<div class="alert alert-danger">Form not found</div>', get_navbar(), '')
        
        # Check permissions for teachers - can only preview forms from their department
        if session['role'] == 'teacher' and form['department'] != session['department']:
            return html_wrapper('Error', '''
            <div class="alert alert-danger">
                <h4>Access Denied</h4>
                <p>You can only preview forms from your department.</p>
                <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
            </div>
            ''', get_navbar(), '')
        
        # Parse JSON questions
        try:
            if form['questions'] and isinstance(form['questions'], str):
                questions = json.loads(form['questions'])
            elif form['questions'] and isinstance(form['questions'], dict):
                questions = form['questions']
            else:
                questions = []
        except:
            questions = []
        
        questions_html = ''
        for i, q in enumerate(questions):
            options = ''
            if q.get('type') == 'mcq':
                for j, opt in enumerate(q.get('options', [])):
                    is_correct = j == q.get('correct_answer', 0)
                    check_class = 'text-success' if is_correct else ''
                    check_icon = '<i class="fas fa-check-circle"></i>' if is_correct else '<i class="fas fa-circle"></i>'
                    options += f'''
                    <div class="form-check">
                        <div class="d-flex align-items-center">
                            <span class="me-2 {check_class}">{check_icon}</span>
                            <label class="form-check-label">{opt}</label>
                        </div>
                    </div>
                    '''
            elif q.get('type') == 'true_false':
                correct_answer = q.get('correct_answer', 'true')
                options = f'''
                <div class="form-check">
                    <div class="d-flex align-items-center">
                        <span class="me-2 {'text-success' if correct_answer == 'true' else ''}">
                            <i class="fas {'fa-check-circle' if correct_answer == 'true' else 'fa-circle'}"></i>
                        </span>
                        <label class="form-check-label">True</label>
                    </div>
                </div>
                <div class="form-check">
                    <div class="d-flex align-items-center">
                        <span class="me-2 {'text-success' if correct_answer == 'false' else ''}">
                            <i class="fas {'fa-check-circle' if correct_answer == 'false' else 'fa-circle'}"></i>
                        </span>
                        <label class="form-check-label">False</label>
                    </div>
                </div>
                '''
            elif q.get('type') == 'short_answer':
                options = '<div class="alert alert-info"><i class="fas fa-info-circle me-2"></i>Short answer question - no predefined answer</div>'
            
            questions_html += f'''
            <div class="card mb-3">
                <div class="card-body">
                    <h5>Q{i+1}: {q.get('question')}</h5>
                    <div class="mt-3">
                        {options}
                    </div>
                    <div class="mt-2">
                        <small class="text-muted">
                            <i class="fas fa-star me-1"></i>Marks: {q.get('marks', 1)} |
                            <i class="fas {'fa-check-circle text-success' if q.get('required') else 'fa-times-circle text-muted'} me-1"></i>
                            { 'Required' if q.get('required') else 'Optional' }
                        </small>
                    </div>
                </div>
            </div>
            '''
        
        student_badge = ''
        if form.get('is_student_submission'):
            student_badge = '<span class="badge student-stats-card"><i class="fas fa-user-graduate"></i> Student Created</span>'
        
        review_status = ''
        if form.get('review_status') == 'pending':
            review_status = '<span class="badge bg-warning">Pending Review</span>'
        elif form.get('review_status') == 'approved':
            review_status = '<span class="badge bg-success">Approved</span>'
        elif form.get('review_status') == 'rejected':
            review_status = '<span class="badge bg-danger">Rejected</span>'
        
        content = f'''
        <div class="card">
            <div class="card-header bg-primary text-white">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h3>{form['title']} {student_badge}</h3>
                        <p class="mb-0">{form['description']}</p>
                    </div>
                    {review_status}
                </div>
                <div class="row mt-2">
                    <div class="col-md-6">
                        <small><i class="fas fa-user me-1"></i>Creator: {form['creator_name']}</small><br>
                        <small><i class="fas fa-building me-1"></i>Department: {form['department']}</small>
                    </div>
                    <div class="col-md-6">
                        <small><i class="fas fa-user-check me-1"></i>Reviewer: {form['reviewer_name'] or 'Not assigned'}</small><br>
                        <small><i class="fas fa-calendar me-1"></i>Created: {form['created_at'].strftime('%Y-%m-%d')}</small>
                    </div>
                </div>
            </div>
            <div class="card-body">
                <h4 class="mb-4">Questions ({len(questions)})</h4>
                {questions_html if questions_html else '<div class="alert alert-info">No questions added yet.</div>'}
            </div>
            <div class="card-footer">
                <a href="javascript:window.close()" class="btn btn-secondary">Close Preview</a>
            </div>
        </div>
        '''
        
        return html_wrapper('Form Preview', content, get_navbar(), '')
        
    except Exception as e:
        print(f"Preview form error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/api/review-form/<int:form_id>', methods=['POST'])
@teacher_required
def review_form_action(form_id):
    try:
        data = request.json
        action = data.get('action')
        reason = data.get('reason', '')
        
        if action not in ['approve', 'reject']:
            return jsonify({'success': False, 'error': 'Invalid action'})
        
        connection = get_db()
        with connection.cursor() as cursor:
            # Check if user can review this form
            cursor.execute('''
                SELECT f.*, u.id as student_id, u.name as student_name, u.email as student_email
                FROM forms f
                JOIN users u ON f.created_by = u.id
                WHERE f.id = %s AND f.is_student_submission = TRUE
            ''', (form_id,))
            form = cursor.fetchone()
            
            if not form:
                connection.close()
                return jsonify({'success': False, 'error': 'Form not found'})
            
            # Admin/super_admin can review any form, teachers only from their department
            if session['role'] == 'teacher':
                if form['department'] != session['department']:
                    connection.close()
                    return jsonify({'success': False, 'error': 'Access denied - wrong department'})
            
            # Map action to review status
            review_status = 'approved' if action == 'approve' else 'rejected'
            
            # Update form status
            cursor.execute('''
                UPDATE forms 
                SET review_status = %s, 
                    reviewed_at = CURRENT_TIMESTAMP,
                    is_published = %s
                WHERE id = %s
            ''', (review_status, action == 'approve', form_id))
            
            # Update student_form_reviews table with correct status
            cursor.execute('''
                UPDATE student_form_reviews 
                SET review_status = %s, 
                    reviewed_at = CURRENT_TIMESTAMP,
                    review_notes = %s
                WHERE form_id = %s
            ''', (review_status, reason, form_id))
            
            connection.commit()
        
        connection.close()
        
        # Create notifications
        if action == 'approve':
            # Notification for student
            create_notification(
                user_id=form['student_id'],
                title='Form Approved!',
                message=f'Your form "{form["title"]}" has been approved and published.',
                type='success',
                link='/my-submissions'
            )
            
            # Notification for reviewer (self)
            create_notification(
                user_id=session['user_id'],
                title='Form Review Completed',
                message=f'You have approved the form "{form["title"]}" by {form["student_name"]}.',
                type='success',
                link='/review-forms'
            )
        else:
            # Notification for student
            create_notification(
                user_id=form['student_id'],
                title='Form Rejected',
                message=f'Your form "{form["title"]}" has been rejected. Reason: {reason}',
                type='danger',
                link='/my-submissions'
            )
            
            # Notification for reviewer (self)
            create_notification(
                user_id=session['user_id'],
                title='Form Review Completed',
                message=f'You have rejected the form "{form["title"]}" by {form["student_name"]}.',
                type='warning',
                link='/review-forms'
            )
        
        # Send notification emails
        if ENABLE_EMAIL_NOTIFICATIONS:
            if action == 'approve':
                # Email to student
                html_content = f'''
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #10b981;">Form Approved!</h2>
                    <p>Hello {form['student_name']},</p>
                    <p>Your form "{form['title']}" has been approved by the reviewer.</p>
                    <div style="background: #f0f9ff; padding: 15px; border-radius: 10px; margin: 20px 0;">
                        <p><strong>Form Details:</strong></p>
                        <p>Title: {form['title']}</p>
                        <p>Reviewer: {session['name']}</p>
                        <p>Status: Approved</p>
                        <p>Approval Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    <p>Your form is now published and available to other students.</p>
                    <a href="https://formmaster.up.railway.app/dashboard" style="display: inline-block; padding: 10px 20px; background: #10b981; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">View Dashboard</a>
                    <hr>
                    <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
                </div>
                '''
                send_email(form['student_email'], 'Form Approved - FormMaster Pro', html_content)
            else:
                # Email to student for rejection
                html_content = f'''
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #ef4444;">Form Rejected</h2>
                    <p>Hello {form['student_name']},</p>
                    <p>Your form "{form['title']}" has been rejected by the reviewer.</p>
                    <div style="background: #fef2f2; padding: 15px; border-radius: 10px; margin: 20px 0;">
                        <p><strong>Form Details:</strong></p>
                        <p>Title: {form['title']}</p>
                        <p>Reviewer: {session['name']}</p>
                        <p>Status: Rejected</p>
                        <p>Reason: {reason or 'No reason provided'}</p>
                        <p>Review Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    <p>You can edit and resubmit your form for review.</p>
                    <a href="https://formmaster.up.railway.app/my-submissions" style="display: inline-block; padding: 10px 20px; background: #ef4444; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">View Submissions</a>
                    <hr>
                    <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
                </div>
                '''
                send_email(form['student_email'], 'Form Rejected - FormMaster Pro', html_content)
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Review form action error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/form/<int:form_id>/edit')
@login_required
def edit_form(form_id):
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
        connection.close()
        
        if not form:
            return redirect('/dashboard')
        
        # Check permissions - admin/super_admin can edit any form
        if form['created_by'] != session['user_id'] and session['role'] not in ['teacher', 'admin', 'super_admin']:
            return html_wrapper('Error', '<div class="alert alert-danger">Access denied</div>', get_navbar(), '')
        
        # Teachers can only edit forms from their department
        if session['role'] == 'teacher' and form['department'] != session['department']:
            return html_wrapper('Error', '<div class="alert alert-danger">Access denied - wrong department</div>', get_navbar(), '')
        
        # Parse JSON questions
        try:
            if form['questions'] and isinstance(form['questions'], str):
                questions = json.loads(form['questions'])
            elif form['questions'] and isinstance(form['questions'], dict):
                questions = form['questions']
            else:
                questions = []
        except:
            questions = []
        
        # Calculate the button HTML before the f-string
        publish_button_html = ''
        if session['role'] in ['admin', 'super_admin']:
            btn_class = 'btn-warning' if form['is_published'] else 'btn-primary'
            icon_class = 'fa-eye-slash' if form['is_published'] else 'fa-eye'
            btn_text = 'Unpublish' if form['is_published'] else 'Publish'
            publish_button_html = f'''
            <button onclick="togglePublish()" class="btn {btn_class}">
                <i class="fas {icon_class} me-2"></i>
                {btn_text}
            </button>
            '''
        
        content = f'''
        <div class="row">
            <div class="col-md-3">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5 class="mb-0">Add Questions</h5>
                    </div>
                    <div class="card-body">
                        <button onclick="addQuestion('mcq')" class="btn btn-outline-primary w-100 mb-2">
                            <i class="fas fa-dot-circle me-2"></i>Multiple Choice
                        </button>
                        <button onclick="addQuestion('true_false')" class="btn btn-outline-primary w-100 mb-2">
                            <i class="fas fa-balance-scale me-2"></i>True/False
                        </button>
                        <button onclick="addQuestion('short_answer')" class="btn btn-outline-primary w-100 mb-2">
                            <i class="fas fa-pen me-2"></i>Short Answer
                        </button>
                    </div>
                </div>
            </div>
            
            <div class="col-md-9">
                <div class="card">
                    <div class="card-header">
                        <h4 class="mb-0">
                            Editing: {form['title']}
                            <span class="badge {'badge-info' if form['form_type'] == 'open' else 'badge-purple'}">
                                {form['form_type'].title()}
                            </span>
                            <span class="badge bg-secondary ms-2">{form['department']}</span>
                        </h4>
                        <p class="text-muted mb-0">{form['description'] or 'No description'}</p>
                    </div>
                    <div class="card-body">
                        <div id="questions-container"></div>
                        
                        <div id="no-questions" class="text-center py-5">
                            <i class="fas fa-poll fa-3x text-muted mb-3"></i>
                            <h5>No questions added yet</h5>
                            <p class="text-muted">Click on question types to add questions</p>
                        </div>
                    </div>
                    <div class="card-footer">
                        <button onclick="saveForm()" class="btn btn-success">
                            <i class="fas fa-save me-2"></i>Save Form
                        </button>
                        {publish_button_html}
                        <a href="/dashboard" class="btn btn-secondary">Back to Dashboard</a>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        scripts = f'''
        <script>
            let questions = {json.dumps(questions)};
            let formId = {form_id};
            
            function renderQuestions() {{
                const container = document.getElementById('questions-container');
                if (questions.length === 0) {{
                    document.getElementById('no-questions').style.display = 'block';
                    container.innerHTML = '';
                    return;
                }}
                
                document.getElementById('no-questions').style.display = 'none';
                container.innerHTML = '';
                
                questions.forEach((q, index) => {{
                    let optionsHtml = '';
                    if (q.type === 'mcq') {{
                        optionsHtml = '<div class="mb-3"><label>Options (Select correct one)</label>';
                        if (q.options) {{
                            q.options.forEach((option, optIndex) => {{
                                optionsHtml += `
                                    <div class="input-group mb-2">
                                        <div class="input-group-text">
                                            <input class="form-check-input" type="radio" name="correct_${{q.id}}" 
                                                   value="${{optIndex}}" ${{q.correct_answer == optIndex ? 'checked' : ''}}
                                                   onchange="updateQuestion(${{index}}, 'correct_answer', ${{optIndex}})">
                                        </div>
                                        <input type="text" class="form-control" value="${{option}}"
                                               onchange="updateOption(${{index}}, ${{optIndex}}, this.value)">
                                        <button class="btn btn-outline-danger" onclick="removeOption(${{index}}, ${{optIndex}})">
                                            <i class="fas fa-times"></i>
                                        </button>
                                    </div>
                                `;
                            }});
                        }}
                        optionsHtml += `
                            <button class="btn btn-sm btn-outline-primary" onclick="addOption(${{index}})">
                                <i class="fas fa-plus"></i> Add Option
                            </button>
                        `;
                        optionsHtml += '</div>';
                    }} else if (q.type === 'true_false') {{
                        optionsHtml = `
                            <div class="mb-3">
                                <label>Correct Answer</label>
                                <select class="form-select" onchange="updateQuestion(${{index}}, 'correct_answer', this.value)">
                                    <option value="true" ${{q.correct_answer === 'true' ? 'selected' : ''}}>True</option>
                                    <option value="false" ${{q.correct_answer === 'false' ? 'selected' : ''}}>False</option>
                                </select>
                            </div>
                        `;
                    }}
                    
                    const questionHTML = `
                        <div class="card question-card mb-3">
                            <div class="card-body">
                                <div class="d-flex justify-content-between mb-2">
                                    <span class="badge bg-secondary">${{q.type.toUpperCase()}}</span>
                                    <button class="btn btn-sm btn-outline-danger" onclick="deleteQuestion(${{index}})">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </div>
                                
                                <div class="mb-3">
                                    <label>Question</label>
                                    <input type="text" class="form-control" value="${{q.question || ''}}" 
                                           onchange="updateQuestion(${{index}}, 'question', this.value)">
                                </div>
                                
                                <div class="row mb-3">
                                    <div class="col-md-6">
                                        <label>Marks</label>
                                        <input type="number" class="form-control" value="${{q.marks || 1}}" min="1"
                                               onchange="updateQuestion(${{index}}, 'marks', this.value)">
                                    </div>
                                    <div class="col-md-6">
                                        <div class="form-check mt-4">
                                            <input type="checkbox" class="form-check-input" ${{q.required ? 'checked' : ''}}
                                                   onchange="updateQuestion(${{index}}, 'required', this.checked)">
                                            <label class="form-check-label">Required</label>
                                        </div>
                                    </div>
                                </div>
                                
                                ${{optionsHtml}}
                            </div>
                        </div>
                    `;
                    container.innerHTML += questionHTML;
                }});
            }}
            
            function addQuestion(type) {{
                const question = {{
                    id: Date.now(),
                    type: type,
                    question: '',
                    required: false,
                    marks: 1
                }};
                
                if (type === 'mcq') {{
                    question.options = ['Option 1', 'Option 2'];
                    question.correct_answer = 0;
                }} else if (type === 'true_false') {{
                    question.correct_answer = 'true';
                }}
                
                questions.push(question);
                renderQuestions();
            }}
            
            function updateQuestion(index, field, value) {{
                questions[index][field] = value;
            }}
            
            function addOption(index) {{
                if (!questions[index].options) questions[index].options = [];
                questions[index].options.push('Option ' + (questions[index].options.length + 1));
                renderQuestions();
            }}
            
            function removeOption(index, optIndex) {{
                questions[index].options.splice(optIndex, 1);
                if (questions[index].correct_answer == optIndex) {{
                    questions[index].correct_answer = '';
                }}
                renderQuestions();
            }}
            
            function updateOption(index, optIndex, value) {{
                questions[index].options[optIndex] = value;
            }}
            
            function deleteQuestion(index) {{
                if (confirm('Delete this question?')) {{
                    questions.splice(index, 1);
                    renderQuestions();
                }}
            }}
            
            function saveForm() {{
                fetch('/api/form/' + formId, {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{ questions: questions }})
                }})
                .then(res => res.json())
                .then(data => {{
                    if (data.success) {{
                        alert('Form saved successfully!');
                        window.location.href = '/dashboard';
                    }} else {{
                        alert('Error saving form');
                    }}
                }})
                .catch(error => {{
                    alert('Error: ' + error);
                }});
            }}
            
            // Initial render
            renderQuestions();
        </script>
        '''
        
        return html_wrapper('Edit Form', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"Edit form error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')
    
@app.route('/api/student-form/<int:form_id>', methods=['POST'])
@student_required
def update_student_form(form_id):
    try:
        data = request.json
        questions = data.get('questions', [])
        
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('SELECT title FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            # Check if form belongs to student
            cursor.execute('SELECT * FROM forms WHERE id = %s AND created_by = %s', (form_id, session['user_id']))
            student_form = cursor.fetchone()
            
            if not student_form:
                connection.close()
                return jsonify({'success': False, 'error': 'Access denied or form not found'})
            
            cursor.execute('UPDATE forms SET questions = %s WHERE id = %s', 
                          (json.dumps(questions), form_id))
            connection.commit()
        connection.close()
        
        # Create notification for saving form
        create_notification(
            user_id=session['user_id'],
            title='Student Form Saved',
            message=f'Your student form "{form["title"]}" has been saved successfully.',
            type='success',
            link=f'/student-form/{form_id}/edit'
        )
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Update student form error: {e}")
        return jsonify({'success': False, 'error': str(e)})
    
@app.route('/api/form/<int:form_id>', methods=['POST'])
@login_required
def update_form(form_id):
    try:
        data = request.json
        questions = data.get('questions', [])
        
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('SELECT title FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            cursor.execute('UPDATE forms SET questions = %s WHERE id = %s', 
                          (json.dumps(questions), form_id))
            connection.commit()
        connection.close()
        
        # Create notification for saving form
        create_notification(
            user_id=session['user_id'],
            title='Form Saved',
            message=f'Your form "{form["title"]}" has been saved successfully.',
            type='success',
            link=f'/form/{form_id}/edit'
        )
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Update form error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/form/<int:form_id>/assign', methods=['GET', 'POST'])
@teacher_required
def assign_form(form_id):
    try:
        connection = get_db()
        
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            if not form:
                connection.close()
                return html_wrapper('Error', '<div class="alert alert-danger">Form not found</div>', get_navbar(), '')
            
            # Teachers can only assign forms from their department
            if session['role'] == 'teacher' and form['department'] != session['department']:
                connection.close()
                return html_wrapper('Error', '''
                <div class="alert alert-danger">
                    <h4>Access Denied</h4>
                    <p>You can only assign forms from your department.</p>
                    <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
                </div>
                ''', get_navbar(), '')
        
        if request.method == 'POST':
            student_ids = request.form.getlist('student_ids')
            due_date = request.form.get('due_date')
            
            notifications_created = []
            
            with connection.cursor() as cursor:
                for student_id in student_ids:
                    cursor.execute('''
                        INSERT IGNORE INTO assignments (form_id, student_id, assigned_by, due_date)
                        VALUES (%s, %s, %s, %s)
                    ''', (form_id, student_id, session['user_id'], due_date))
                    
                    # Create notification for each student
                    create_notification(
                        user_id=int(student_id),
                        title='New Form Assigned',
                        message=f'A new form "{form["title"]}" has been assigned to you by {session["name"]}.',
                        type='info',
                        link='/dashboard'
                    )
                    notifications_created.append(student_id)
                
                # Get form details for email BEFORE committing
                cursor.execute('SELECT title FROM forms WHERE id = %s', (form_id,))
                form = cursor.fetchone()
            
            connection.commit()  # Move commit after all cursor operations
            
            # Create notification for teacher
            create_notification(
                user_id=session['user_id'],
                title='Forms Assigned',
                message=f'You have assigned the form "{form["title"]}" to {len(notifications_created)} student(s).',
                type='success',
                link=f'/form/{form_id}/responses'
            )
            
            # Send assignment notification emails
            if ENABLE_EMAIL_NOTIFICATIONS and student_ids and form:
                for student_id in student_ids:
                    # Get student details in a NEW cursor
                    with connection.cursor() as cursor:
                        cursor.execute('SELECT email, name FROM users WHERE id = %s', (student_id,))
                        student = cursor.fetchone()
                    
                    if student:
                        html_content = f'''
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #667eea;">New Form Assigned</h2>
                            <p>Hello {student['name']},</p>
                            <p>A new form has been assigned to you by {session['name']}.</p>
                            <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 20px 0;">
                                <p><strong>Form Details:</strong></p>
                                <p>Title: {form['title']}</p>
                                <p>Assigned By: {session['name']}</p>
                                {f'<p>Due Date: {due_date}</p>' if due_date else ''}
                                <p>Assignment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                            </div>
                            <p>Please complete the form before the due date.</p>
                            <a href="https://formmaster.up.railway.app/dashboard" style="display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">View Dashboard</a>
                            <hr>
                            <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
                        </div>
                        '''
                        send_email(student['email'], 'New Form Assigned - FormMaster Pro', html_content)
            
            # Return after POST to avoid showing form again
            return redirect('/dashboard')
        
        # GET request - show the form
        with connection.cursor() as cursor:
            # For admin/super_admin, show students from all departments, for teachers only from form's department
            if session['role'] in ['admin', 'super_admin']:
                cursor.execute('''
                    SELECT id, name, email, department FROM users 
                    WHERE role = "student"
                    ORDER BY department, name
                ''')
            else:
                cursor.execute('''
                    SELECT id, name, email FROM users 
                    WHERE role = "student" AND department = %s
                    ORDER BY name
                ''', (form['department'],))
            
            students = cursor.fetchall()
            
            cursor.execute('''
                SELECT u.id FROM assignments a 
                JOIN users u ON a.student_id = u.id 
                WHERE a.form_id = %s
            ''', (form_id,))
            assigned = cursor.fetchall()
            assigned_ids = [a['id'] for a in assigned]
        
        connection.close()
        
        students_options = ''
        if session['role'] in ['admin', 'super_admin']:
            # Group students by department for admin/super_admin
            students_by_dept = {}
            for s in students:
                if s['department'] not in students_by_dept:
                    students_by_dept[s['department']] = []
                students_by_dept[s['department']].append(s)
            
            for dept, dept_students in students_by_dept.items():
                students_options += f'<optgroup label="{dept} Department">'
                for s in dept_students:
                    selected = 'selected' if s['id'] in assigned_ids else ''
                    students_options += f'<option value="{s["id"]}" {selected}>{s["name"]} ({s["email"]})</option>'
                students_options += '</optgroup>'
        else:
            for s in students:
                selected = 'selected' if s['id'] in assigned_ids else ''
                students_options += f'<option value="{s["id"]}" {selected}>{s["name"]} ({s["email"]})</option>'
        
        content = f'''
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-body">
                        <h3 class="text-center mb-4">
                            Assign Form: {form['title']}
                            <br>
                            <small class="text-muted">Department: {form['department']}</small>
                        </h3>
                        <form method="POST">
                            <div class="mb-3">
                                <label class="form-label">Select Students</label>
                                <select class="form-select" name="student_ids" multiple size="8" required>
                                    {students_options}
                                </select>
                                <small class="text-muted">Hold Ctrl/Cmd to select multiple</small>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Due Date (Optional)</label>
                                <input type="date" class="form-control" name="due_date">
                            </div>
                            <div class="d-flex gap-2">
                                <a href="/dashboard" class="btn btn-secondary">Cancel</a>
                                <button type="submit" class="btn btn-primary">Assign Form</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        return html_wrapper('Assign Form', content, get_navbar(), '')
        
    except Exception as e:
        print(f"Assign form error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/request-form/<int:form_id>', methods=['POST'])
@login_required
def request_form(form_id):
    try:
        connection = get_db()
        
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            if not form:
                connection.close()
                return jsonify({'success': False, 'error': 'Form not found'})
            
            # Students can only request forms from their department
            if session['role'] == 'student' and form['department'] != session['department']:
                connection.close()
                return jsonify({'success': False, 'error': 'You can only request forms from your department'})
            
            # Check if already requested
            cursor.execute('''
                SELECT * FROM form_requests WHERE form_id = %s AND student_id = %s
            ''', (form_id, session['user_id']))
            existing = cursor.fetchone()
            
            if existing:
                connection.close()
                return jsonify({'success': False, 'error': 'Already requested'})
            
            # Create request
            cursor.execute('''
                INSERT INTO form_requests (form_id, student_id, status)
                VALUES (%s, %s, 'pending')
            ''', (form_id, session['user_id']))
            
            connection.commit()
            
            # Get form creator details
            cursor.execute('''
                SELECT u.id as creator_id, u.email as creator_email, u.name as creator_name,
                       f.title, f.form_type
                FROM forms f
                JOIN users u ON f.created_by = u.id
                WHERE f.id = %s
            ''', (form_id,))
            form_details = cursor.fetchone()
            
            # Get student details
            cursor.execute('SELECT email, name FROM users WHERE id = %s', (session['user_id'],))
            student = cursor.fetchone()
        
        connection.close()
        
        # Create notification for student
        create_notification(
            user_id=session['user_id'],
            title='Form Access Requested',
            message=f'Your request to access "{form["title"]}" has been submitted.',
            type='info',
            link='/dashboard'
        )
        
        # Create notification for form creator
        create_notification(
            user_id=form_details['creator_id'],
            title='New Form Access Request',
            message=f'{student["name"]} has requested access to your form "{form["title"]}".',
            type='warning',
            link='/form-requests'
        )
        
        # Send notification email to form creator
        if ENABLE_EMAIL_NOTIFICATIONS and form_details:
            html_content = f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #667eea;">New Form Access Request</h2>
                <p>Hello {form_details['creator_name']},</p>
                <p>A student has requested access to your form.</p>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 20px 0;">
                    <p><strong>Form Details:</strong></p>
                    <p>Title: {form_details['title']}</p>
                    <p>Type: {form_details['form_type'].title()}</p>
                    <p>Student: {student['name']} ({student['email']})</p>
                    <p>Request Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                <p>Please review and approve or reject this request.</p>
                <a href="https://formmaster.up.railway.app/form-requests" style="display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">Review Requests</a>
                <hr>
                <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
            </div>
            '''
            send_email(form_details['creator_email'], 'New Form Access Request - FormMaster Pro', html_content)
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Request form error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/form-requests')
@teacher_required
def form_requests():
    try:
        connection = get_db()
        
        # Get selected department for admin/super_admin
        selected_dept = request.args.get('department', '')
        
        with connection.cursor() as cursor:
            if session['role'] in ['admin', 'super_admin']:
                query = '''
                    SELECT fr.*, f.title, f.department, f.form_type, u.name as student_name, u.email as student_email
                    FROM form_requests fr
                    JOIN forms f ON fr.form_id = f.id
                    JOIN users u ON fr.student_id = u.id
                    WHERE fr.status = 'pending'
                '''
                params = []
                
                if selected_dept:
                    query += ' AND f.department = %s'
                    params.append(selected_dept)
                
                query += ' ORDER BY fr.requested_at DESC'
                cursor.execute(query, params)
            else:
                cursor.execute('''
                    SELECT fr.*, f.title, f.form_type, u.name as student_name, u.email as student_email
                    FROM form_requests fr
                    JOIN forms f ON fr.form_id = f.id
                    JOIN users u ON fr.student_id = u.id
                    WHERE f.created_by = %s AND fr.status = 'pending'
                    ORDER BY fr.requested_at DESC
                ''', (session['user_id'],))
            
            requests = cursor.fetchall()
        connection.close()
        
        # Department filter for admin/super_admin
        dept_filter_html = ''
        if session['role'] in ['admin', 'super_admin']:
            departments_options = '<option value="">All Departments</option>'
            for dept in DEPARTMENTS:
                selected = 'selected' if dept == selected_dept else ''
                departments_options += f'<option value="{dept}" {selected}>{dept}</option>'
            
            dept_filter_html = f'''
            <div class="dept-filter mb-4">
                <h5 class="mb-3">Department Filter</h5>
                <form method="GET" action="/form-requests" class="row align-items-center">
                    <div class="col-md-4">
                        <select class="form-select" name="department" onchange="this.form.submit()">
                            {departments_options}
                        </select>
                    </div>
                    <div class="col-md-8">
                        <small class="text-muted">
                            Showing requests from: {selected_dept if selected_dept else "All Departments"}
                        </small>
                    </div>
                </form>
            </div>
            '''
        
        requests_html = ''
        for req in requests:
            form_type_badge = 'badge-info' if req['form_type'] == 'open' else 'badge-purple'
            dept_info = f'<br><small class="text-muted">Department: {req["department"]}</small>' if 'department' in req else ''
            requests_html += f'''
            <div class="card mb-3">
                <div class="card-body">
                    <div class="d-flex justify-content-between">
                        <div>
                            <h5>{req['title']}</h5>
                            <p>
                                <strong>Student:</strong> {req['student_name']} ({req['student_email']})<br>
                                <span class="badge {form_type_badge}">{req['form_type'].title()} Form</span>
                                {dept_info}
                            </p>
                            <small class="text-muted">Requested: {req['requested_at']}</small>
                        </div>
                        <div>
                            <button onclick="handleRequest({req['id']}, 'approved')" class="btn btn-success btn-sm">
                                <i class="fas fa-check"></i> Approve
                            </button>
                            <button onclick="handleRequest({req['id']}, 'rejected')" class="btn btn-danger btn-sm">
                                <i class="fas fa-times"></i> Reject
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            '''
        
        if not requests_html:
            requests_html = f'''
            <div class="alert alert-info">
                <i class="fas fa-info-circle me-2"></i>
                No pending requests {f'for department: {selected_dept}' if selected_dept else ''}.
            </div>
            '''
        
        content = f'''
        <div class="mb-4">
            <h2 class="text-white">Form Access Requests</h2>
            <p class="text-white-50">Students requesting access to forms</p>
        </div>
        
        {dept_filter_html}
        
        <div class="card">
            <div class="card-header">
                <h4 class="mb-0">Pending Form Requests ({len(requests)})</h4>
                <p class="mb-0 text-muted">Students requesting access to forms</p>
            </div>
            <div class="card-body">
                {requests_html}
            </div>
        </div>
        '''
        
        scripts = '''
        <script>
            function handleRequest(requestId, action) {
                fetch('/handle-request/' + requestId + '/' + action, {
                    method: 'POST'
                })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        alert('Request ' + action + '!');
                        window.location.reload();
                    } else {
                        alert('Error: ' + data.error);
                    }
                });
            }
        </script>
        '''
        
        return html_wrapper('Form Requests', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"Form requests error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/handle-request/<int:request_id>/<action>', methods=['POST'])
@teacher_required
def handle_request(request_id, action):
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Check if user has permission to handle this request
            if session['role'] == 'teacher':
                cursor.execute('''
                    SELECT f.created_by 
                    FROM form_requests fr
                    JOIN forms f ON fr.form_id = f.id
                    WHERE fr.id = %s
                ''', (request_id,))
                req = cursor.fetchone()
                if not req or req['created_by'] != session['user_id']:
                    connection.close()
                    return jsonify({'success': False, 'error': 'Access denied'})
            
            # Get request details first
            cursor.execute('''
                SELECT fr.student_id, f.title, u.name as student_name, u.email as student_email
                FROM form_requests fr
                JOIN forms f ON fr.form_id = f.id
                JOIN users u ON fr.student_id = u.id
                WHERE fr.id = %s
            ''', (request_id,))
            request_details = cursor.fetchone()
            
            if not request_details:
                connection.close()
                return jsonify({'success': False, 'error': 'Request not found'})
            
            cursor.execute('''
                UPDATE form_requests 
                SET status = %s, approved_by = %s, approved_at = CURRENT_TIMESTAMP
                WHERE id = %s
            ''', (action, session['user_id'], request_id))
            
            if action == 'approved':
                cursor.execute('''
                    SELECT form_id, student_id FROM form_requests WHERE id = %s
                ''', (request_id,))
                req = cursor.fetchone()
                
                # Auto-assign the form to the student when approved
                cursor.execute('''
                    INSERT IGNORE INTO assignments (form_id, student_id, assigned_by)
                    VALUES (%s, %s, %s)
                ''', (req['form_id'], req['student_id'], session['user_id']))
            
            connection.commit()
        
        connection.close()
        
        # Create notifications
        if action == 'approved':
            # Notification for student
            create_notification(
                user_id=request_details['student_id'],
                title='Form Access Approved',
                message=f'Your request to access "{request_details["title"]}" has been approved.',
                type='success',
                link='/dashboard'
            )
            
            # Notification for teacher
            create_notification(
                user_id=session['user_id'],
                title='Request Approved',
                message=f'You have approved {request_details["student_name"]}\'s request to access "{request_details["title"]}".',
                type='success',
                link='/form-requests'
            )
        else:
            # Notification for student
            create_notification(
                user_id=request_details['student_id'],
                title='Form Access Rejected',
                message=f'Your request to access "{request_details["title"]}" has been rejected.',
                type='danger',
                link='/dashboard'
            )
            
            # Notification for teacher
            create_notification(
                user_id=session['user_id'],
                title='Request Rejected',
                message=f'You have rejected {request_details["student_name"]}\'s request to access "{request_details["title"]}".',
                type='warning',
                link='/form-requests'
            )
        
        # Send notification email
        if ENABLE_EMAIL_NOTIFICATIONS:
            if action == 'approved':
                html_content = f'''
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #10b981;">Form Access Approved</h2>
                    <p>Hello {request_details['student_name']},</p>
                    <p>Your request to access the form "{request_details['title']}" has been approved.</p>
                    <div style="background: #f0f9ff; padding: 15px; border-radius: 10px; margin: 20px 0;">
                        <p><strong>Form Details:</strong></p>
                        <p>Title: {request_details['title']}</p>
                        <p>Approved By: {session['name']}</p>
                        <p>Status: Approved</p>
                        <p>Approval Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    <p>You can now access the form from your dashboard.</p>
                    <a href="https://formmaster.up.railway.app/dashboard" style="display: inline-block; padding: 10px 20px; background: #10b981; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">View Dashboard</a>
                    <hr>
                    <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
                </div>
                '''
                send_email(request_details['student_email'], 'Form Access Approved - FormMaster Pro', html_content)
            else:
                html_content = f'''
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #ef4444;">Form Access Rejected</h2>
                    <p>Hello {request_details['student_name']},</p>
                    <p>Your request to access the form "{request_details['title']}" has been rejected.</p>
                    <div style="background: #fef2f2; padding: 15px; border-radius: 10px; margin: 20px 0;">
                        <p><strong>Form Details:</strong></p>
                        <p>Title: {request_details['title']}</p>
                        <p>Rejected By: {session['name']}</p>
                        <p>Status: Rejected</p>
                        <p>Rejection Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    <p>Please contact the form creator if you have any questions.</p>
                    <hr>
                    <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
                </div>
                '''
                send_email(request_details['student_email'], 'Form Access Rejected - FormMaster Pro', html_content)
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Handle request error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/form/<int:form_id>/take')
@login_required
def take_form(form_id):
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            if not form:
                connection.close()
                return html_wrapper('Error', '<div class="alert alert-danger">Form not found</div>', get_navbar(), '')
            
            # Check access based on request/assignment status
            cursor.execute('''
                SELECT fr.status as request_status
                FROM form_requests fr
                WHERE fr.form_id = %s AND fr.student_id = %s
            ''', (form_id, session['user_id']))
            access_info = cursor.fetchone()
            
            # Check if already assigned
            cursor.execute('''
                SELECT 1 FROM assignments WHERE form_id = %s AND student_id = %s
            ''', (form_id, session['user_id']))
            assigned = cursor.fetchone()
            
            # Admin/super_admin can access any form
            admin_access = session['role'] in ['admin', 'super_admin']
            
            # Check if user has submitted already
            cursor.execute('''
                SELECT * FROM responses WHERE form_id = %s AND student_id = %s
            ''', (form_id, session['user_id']))
            response = cursor.fetchone()
            
            if response:
                connection.close()
                return html_wrapper('Error', '<div class="alert alert-info">You have already submitted this form</div>', get_navbar(), '')
            
            # Determine access
            has_access = False
            if admin_access:
                has_access = True
            elif assigned:
                has_access = True
            elif access_info and access_info['request_status'] == 'approved':
                has_access = True
            elif form['form_type'] == 'public' and form['department'] == session['department']:
                # PUBLIC FORMS: Students from same department can access without request
                has_access = True
            
            if not has_access:
                connection.close()
                return html_wrapper('Error', '''
                <div class="alert alert-danger">
                    <h4>Access Denied</h4>
                    <p>You need to request access to this form first.</p>
                    <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
                </div>
                ''', get_navbar(), '')
        
        connection.close()
        
        # Create notification for starting form
        create_notification(
            user_id=session['user_id'],
            title='Form Started',
            message=f'You have started taking the form "{form["title"]}".',
            type='info',
            link=f'/form/{form_id}/take'
        )
        
        # Parse JSON questions
        try:
            if form['questions'] and isinstance(form['questions'], str):
                questions = json.loads(form['questions'])
            elif form['questions'] and isinstance(form['questions'], dict):
                questions = form['questions']
            else:
                questions = []
        except:
            questions = []
        
        # Add form type indicator
        form_type_badge = {
            'public': 'bg-success',
            'open': 'bg-info',
            'confidential': 'bg-purple'
        }.get(form['form_type'], 'bg-secondary')
        
        form_type_text = {
            'public': 'PUBLIC (No access request needed)',
            'open': 'OPEN',
            'confidential': 'CONFIDENTIAL'
        }.get(form['form_type'], 'UNKNOWN')
        
        questions_html = ''
        for i, q in enumerate(questions):
            options = ''
            if q.get('type') == 'mcq':
                for j, opt in enumerate(q.get('options', [])):
                    options += f'''
                    <div class="form-check">
                        <input class="form-check-input" type="radio" name="q_{q['id']}" value="{j}" id="opt_{i}_{j}" required>
                        <label class="form-check-label" for="opt_{i}_{j}">{opt}</label>
                    </div>
                    '''
            elif q.get('type') == 'true_false':
                options = f'''
                <div class="form-check">
                    <input class="form-check-input" type="radio" name="q_{q['id']}" value="true" id="true_{i}" required>
                    <label class="form-check-label" for="true_{i}">True</label>
                </div>
                <div class="form-check">
                    <input class="form-check-input" type="radio" name="q_{q['id']}" value="false" id="false_{i}" required>
                    <label class="form-check-label" for="false_{i}">False</label>
                </div>
                '''
            elif q.get('type') == 'short_answer':
                options = f'<input type="text" class="form-control" name="q_{q["id"]}" required>'
            
            required_star = ' <span class="text-danger">*</span>' if q.get('required', False) else ''
            questions_html += f'''
            <div class="card mb-3">
                <div class="card-body">
                    <h5>Q{i+1}: {q.get('question')}{required_star}</h5>
                    {options}
                    <small class="text-muted">Marks: {q.get('marks', 1)}</small>
                </div>
            </div>
            '''
        
        content = f'''
        <div class="card">
            <div class="card-header bg-primary text-white">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h3>{form['title']} {form_type_badge}</h3>
                        <p>{form['description']}</p>
                    </div>
                    {f'<span class="badge student-stats-card"><i class="fas fa-user-graduate"></i> Public Form - No Access Request Needed</span>' if form['form_type'] == 'public' else ''}
                </div>
                <small>Department: {form['department']} | Type: {form['form_type'].title()}</small>
            </div>
            <div class="card-body">
                <form id="responseForm">
                    {questions_html}
                </form>
            </div>
            <div class="card-footer">
                <button onclick="submitForm()" class="btn btn-success btn-lg w-100">
                    <i class="fas fa-paper-plane me-2"></i>Submit Form
                </button>
            </div>
        </div>
        '''
        
        scripts = f'''
        <script>
            function submitForm() {{
                const form = document.getElementById('responseForm');
                if (!form.checkValidity()) {{
                    form.reportValidity();
                    return;
                }}
                
                const answers = {{}};
                const formData = new FormData(form);
                
                for (let [key, value] of formData.entries()) {{
                    answers[key.replace('q_', '')] = value;
                }}
                
                fetch('/submit-form', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{
                        form_id: {form_id},
                        answers: answers
                    }})
                }})
                .then(res => res.json())
                .then(data => {{
                    if (data.success) {{
                        alert('Submitted successfully! Score: ' + data.score + '/' + data.total_marks + ' (' + data.percentage + '%)');
                        window.location.href = '/dashboard';
                    }} else {{
                        alert('Error: ' + data.error);
                    }}
                }});
            }}
        </script>
        '''
        
        return html_wrapper('Take Form', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"Take form error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/submit-form', methods=['POST'])
@login_required
def submit_form():
    try:
        data = request.json
        form_id = data.get('form_id')
        answers = data.get('answers', {})
        
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            # Parse JSON questions
            try:
                if form['questions'] and isinstance(form['questions'], str):
                    questions = json.loads(form['questions'])
                elif form['questions'] and isinstance(form['questions'], dict):
                    questions = form['questions']
                else:
                    questions = []
            except:
                questions = []
            
            score = 0
            total_marks = 0
            
            for q in questions:
                marks = q.get('marks', 1)
                total_marks += marks
                
                answer = answers.get(str(q.get('id')))
                if answer:
                    if q.get('type') == 'mcq':
                        if str(answer) == str(q.get('correct_answer', 0)):
                            score += marks
                    elif q.get('type') == 'true_false':
                        if str(answer).lower() == str(q.get('correct_answer', 'true')).lower():
                            score += marks
            
            percentage = (score / total_marks * 100) if total_marks > 0 else 0
            
            cursor.execute('''
                INSERT INTO responses (form_id, student_id, answers, score, total_marks, percentage)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (form_id, session['user_id'], json.dumps(answers), score, total_marks, percentage))
            response_id = cursor.lastrowid
            
            cursor.execute('''
                UPDATE assignments SET is_completed = TRUE 
                WHERE form_id = %s AND student_id = %s
            ''', (form_id, session['user_id']))
            
            # Create download entry based on form type
            if form['form_type'] == 'public':
                # Public forms: Auto-grant download access
                download_token, _ = create_response_download_entry(response_id, session['user_id'], form_id)
                if download_token:
                    cursor.execute('''
                        UPDATE response_downloads 
                        SET access_granted = TRUE,
                            granted_by = %s,
                            granted_at = CURRENT_TIMESTAMP
                        WHERE response_id = %s AND student_id = %s
                    ''', (session['user_id'], response_id, session['user_id']))
            else:
                # Open/Confidential forms: Create pending request
                download_token, form_details = create_response_download_entry(response_id, session['user_id'], form_id)
                
                # Create notification for form creator if different from student
                if form_details and form_details['creator_id'] != session['user_id']:
                    create_notification(
                        user_id=form_details['creator_id'],
                        title='New Response Download Request',
                        message=f'{session["name"]} has submitted your form "{form["title"]}" and requested download access.',
                        type='warning',
                        link=f'/form/{form_id}/response-downloads'
                    )
            
            connection.commit()
            
            # Get form creator details for notifications
            cursor.execute('''
                SELECT u.id as creator_id, u.email as creator_email, u.name as creator_name,
                       f.title, u2.email as student_email, u2.name as student_name
                FROM forms f
                JOIN users u ON f.created_by = u.id
                JOIN users u2 ON %s = u2.id
                WHERE f.id = %s
            ''', (session['user_id'], form_id))
            form_details = cursor.fetchone()
        
        connection.close()
        
        # Create notification for student
        create_notification(
            user_id=session['user_id'],
            title='Form Submitted',
            message=f'You have submitted the form "{form["title"]}". Score: {score}/{total_marks} ({percentage:.1f}%)',
            type='success',
            link=f'/my-responses'
        )
        
        # Create notification for form creator
        if form_details and form_details['creator_id'] != session['user_id']:
            create_notification(
                user_id=form_details['creator_id'],
                title='New Form Submission',
                message=f'{session["name"]} has submitted your form "{form["title"]}". Score: {score}/{total_marks}',
                type='info',
                link=f'/form/{form_id}/responses'
            )
        
        return jsonify({
            'success': True,
            'score': score,
            'total_marks': total_marks,
            'percentage': round(percentage, 2),
            'form_type': form['form_type'],
            'can_download': form['form_type'] == 'public',
            'download_requested': form['form_type'] != 'public',
            'message': 'Download access ' + ('automatically granted' if form['form_type'] == 'public' else 'request submitted')
        })
    except Exception as e:
        print(f"Submit form error: {e}")
        return jsonify({'success': False, 'error': str(e)})
    

@app.route('/my-responses/downloads')
@login_required
def my_response_downloads():
    """Student's view of their response downloads"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Get responses with download status
            cursor.execute('''
                SELECT r.*, f.title, f.form_type, f.department,
                       rd.access_granted, rd.granted_at, rd.download_count,
                       rd.last_downloaded_at, u.name as teacher_name
                FROM responses r
                JOIN forms f ON r.form_id = f.id
                LEFT JOIN response_downloads rd ON r.id = rd.response_id AND rd.student_id = r.student_id
                LEFT JOIN users u ON f.created_by = u.id
                WHERE r.student_id = %s
                ORDER BY r.submitted_at DESC
            ''', (session['user_id'],))
            responses = cursor.fetchall()
            
        connection.close()
        
        responses_html = ''
        for resp in responses:
            # Determine download status
            if resp['form_type'] == 'public':
                status_badge = '<span class="badge bg-success">Auto-Access</span>'
                download_btn = f'''
                <button onclick="downloadResponse({resp['id']})" class="btn btn-sm btn-success">
                    <i class="fas fa-download me-1"></i>Download PDF
                </button>
                '''
            elif resp['access_granted']:
                status_badge = f'<span class="badge bg-success">Granted</span>'
                if resp['granted_at']:
                    status_badge += f'<br><small>{resp["granted_at"].strftime("%Y-%m-%d")}</small>'
                download_btn = f'''
                <button onclick="downloadResponse({resp['id']})" class="btn btn-sm btn-success">
                    <i class="fas fa-download me-1"></i>Download PDF
                </button>
                <small class="text-muted">Downloads: {resp['download_count'] or 0}</small>
                '''
            else:
                status_badge = '<span class="badge bg-warning">Pending Approval</span>'
                download_btn = f'''
                <button onclick="requestDownload({resp['id']})" class="btn btn-sm btn-outline-warning" 
                        {'disabled' if resp.get('download_requested') else ''}>
                    <i class="fas fa-paper-plane me-1"></i>
                    {'Request Sent' if resp.get('download_requested') else 'Request Download'}
                </button>
                '''
            
            score_class = 'text-success' if resp['percentage'] >= 70 else 'text-warning' if resp['percentage'] >= 50 else 'text-danger'
            
            responses_html += f'''
            <div class="card mb-3">
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-8">
                            <h5>{resp['title']}</h5>
                            <p class="text-muted mb-1">
                                <i class="fas fa-building me-1"></i>{resp['department']} | 
                                <i class="fas fa-chalkboard-teacher me-1"></i>{resp['teacher_name'] or 'N/A'}
                            </p>
                            <div class="d-flex align-items-center mb-2">
                                <span class="{score_class} fw-bold me-3">
                                    Score: {resp['score']}/{resp['total_marks']} ({resp['percentage']}%)
                                </span>
                                <span class="badge {'bg-info' if resp['form_type'] == 'open' else 'bg-success' if resp['form_type'] == 'public' else 'bg-purple'}">
                                    {resp['form_type'].upper()}
                                </span>
                            </div>
                            <small class="text-muted">
                                <i class="fas fa-calendar me-1"></i>Submitted: {resp['submitted_at'].strftime('%Y-%m-%d %H:%M')}
                            </small>
                        </div>
                        <div class="col-md-4 text-end">
                            <div class="mb-2">
                                {status_badge}
                            </div>
                            {download_btn}
                        </div>
                    </div>
                </div>
            </div>
            '''
        
        if not responses_html:
            responses_html = '''
            <div class="text-center py-5">
                <i class="fas fa-file-download fa-3x text-muted mb-3"></i>
                <h4>No responses yet</h4>
                <p class="text-muted">You haven't submitted any forms yet.</p>
                <a href="/dashboard" class="btn btn-primary">
                    <i class="fas fa-list me-2"></i>Browse Available Forms
                </a>
            </div>
            '''
        
        content = f'''
        <div class="mb-4">
            <h2 class="text-white">My Response Downloads</h2>
            <p class="text-white-50">Download your form responses as PDF</p>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-download me-2"></i>Available Downloads ({len(responses)})
                </h5>
            </div>
            <div class="card-body">
                {responses_html}
            </div>
        </div>
        
        <!-- Download Stats -->
        <div class="row mt-4">
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body text-center">
                        <h6>Total Responses</h6>
                        <h3>{len(responses)}</h3>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body text-center">
                        <h6>Downloadable</h6>
                        <h3>{len([r for r in responses if r['access_granted'] or r['form_type'] == 'public'])}</h3>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body text-center">
                        <h6>Pending Requests</h6>
                        <h3>{len([r for r in responses if not r['access_granted'] and r['form_type'] != 'public'])}</h3>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        scripts = '''
        <script>
            function downloadResponse(responseId) {
                // Show loading
                const btn = event.target.closest('button');
                const originalHTML = btn.innerHTML;
                btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Generating PDF...';
                btn.disabled = true;
                
                fetch('/download-response/' + responseId)
                    .then(res => {
                        if (!res.ok) throw new Error('Download failed');
                        return res.blob();
                    })
                    .then(blob => {
                        // Create download link
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `response_${responseId}.pdf`;
                        document.body.appendChild(a);
                        a.click();
                        window.URL.revokeObjectURL(url);
                        document.body.removeChild(a);
                        
                        // Update button
                        btn.innerHTML = '<i class="fas fa-check me-1"></i>Downloaded';
                        setTimeout(() => {
                            btn.innerHTML = originalHTML;
                            btn.disabled = false;
                        }, 2000);
                    })
                    .catch(error => {
                        console.error('Download error:', error);
                        alert('Error downloading response: ' + error.message);
                        btn.innerHTML = originalHTML;
                        btn.disabled = false;
                    });
            }
            
            function requestDownload(responseId) {
                if (confirm('Request download permission for this response?')) {
                    fetch('/request-download/' + responseId, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            alert(data.message);
                            window.location.reload();
                        } else {
                            alert('Error: ' + data.error);
                        }
                    })
                    .catch(error => {
                        alert('Network error: ' + error);
                    });
                }
            }
        </script>
        '''
        
        return html_wrapper('Response Downloads', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"My response downloads error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/form/<int:form_id>/response-downloads')
@teacher_required
def manage_response_downloads(form_id):
    """Manage response download requests for a form"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Check if user owns the form or is admin
            cursor.execute('SELECT created_by FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            if not form:
                connection.close()
                return html_wrapper('Error', '<div class="alert alert-danger">Form not found</div>', get_navbar(), '')
            
            if form['created_by'] != session['user_id'] and session['role'] not in ['admin', 'super_admin']:
                connection.close()
                return html_wrapper('Error', '<div class="alert alert-danger">Access denied</div>', get_navbar(), '')
            
            # Get pending download requests
            cursor.execute('''
                SELECT rd.*, r.student_id, u.name as student_name, 
                       u.email as student_email, r.score, r.total_marks,
                       r.percentage, r.submitted_at, f.title as form_title
                FROM response_downloads rd
                JOIN responses r ON rd.response_id = r.id
                JOIN forms f ON rd.form_id = f.id
                JOIN users u ON rd.student_id = u.id
                WHERE rd.form_id = %s AND rd.access_granted = FALSE
                ORDER BY rd.created_at DESC
            ''', (form_id,))
            pending_requests = cursor.fetchall()
            
            # Get granted downloads
            cursor.execute('''
                SELECT rd.*, r.student_id, u.name as student_name, 
                       u.email as student_email, r.score, r.total_marks,
                       r.percentage, r.submitted_at, f.title as form_title,
                       u2.name as granted_by_name, rd.granted_at, rd.download_count
                FROM response_downloads rd
                JOIN responses r ON rd.response_id = r.id
                JOIN forms f ON rd.form_id = f.id
                JOIN users u ON rd.student_id = u.id
                LEFT JOIN users u2 ON rd.granted_by = u2.id
                WHERE rd.form_id = %s AND rd.access_granted = TRUE
                ORDER BY rd.granted_at DESC
            ''', (form_id,))
            granted_downloads = cursor.fetchall()
            
            # Get form details
            cursor.execute('SELECT title, form_type FROM forms WHERE id = %s', (form_id,))
            form_details = cursor.fetchone()
        
        connection.close()
        
        pending_html = ''
        for req in pending_requests:
            pending_html += f'''
            <div class="card mb-3">
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-8">
                            <h6>{req['student_name']}</h6>
                            <p class="text-muted mb-1">
                                <i class="fas fa-envelope me-1"></i>{req['student_email']}<br>
                                <i class="fas fa-chart-bar me-1"></i>Score: {req['score']}/{req['total_marks']} ({req['percentage']}%)<br>
                                <i class="fas fa-calendar me-1"></i>Submitted: {req['submitted_at'].strftime('%Y-%m-%d')}
                            </p>
                        </div>
                        <div class="col-md-4 text-end">
                            <button onclick="handleDownloadRequest({req['id']}, 'approve')" class="btn btn-success btn-sm mb-2">
                                <i class="fas fa-check me-1"></i>Approve
                            </button>
                            <button onclick="handleDownloadRequest({req['id']}, 'reject')" class="btn btn-danger btn-sm">
                                <i class="fas fa-times me-1"></i>Reject
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            '''
        
        if not pending_html:
            pending_html = '<div class="alert alert-info">No pending download requests.</div>'
        
        granted_html = ''
        for download in granted_downloads:
            granted_html += f'''
            <tr>
                <td>{download['student_name']}</td>
                <td>{download['student_email']}</td>
                <td>{download['score']}/{download['total_marks']} ({download['percentage']}%)</td>
                <td>
                    <span class="badge bg-success">Granted</span><br>
                    <small>{download['granted_at'].strftime('%Y-%m-%d') if download['granted_at'] else 'N/A'}</small>
                </td>
                <td>{download['granted_by_name'] or 'Auto'}</td>
                <td>{download['download_count']}</td>
                <td>
                    <button onclick="revokeDownload({download['id']})" class="btn btn-sm btn-outline-danger">
                        <i class="fas fa-ban"></i> Revoke
                    </button>
                </td>
            </tr>
            '''
        
        content = f'''
        <div class="mb-4">
            <h2 class="text-white">Manage Response Downloads</h2>
            <p class="text-white-50">Form: {form_details['title']} ({form_details['form_type'].upper()})</p>
        </div>
        
        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-clock me-2"></i>Pending Requests ({len(pending_requests)})
                        </h5>
                    </div>
                    <div class="card-body">
                        {pending_html}
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-check-circle me-2"></i>Granted Downloads ({len(granted_downloads)})
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Student</th>
                                        <th>Email</th>
                                        <th>Score</th>
                                        <th>Status</th>
                                        <th>Granted By</th>
                                        <th>Downloads</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {granted_html}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        scripts = '''
        <script>
            function handleDownloadRequest(downloadId, action) {
                const actionText = action === 'approve' ? 'approve' : 'reject';
                if (confirm(`Are you sure you want to ${actionText} this download request?`)) {
                    fetch('/handle-download-request/' + downloadId + '/' + action, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            alert(`Download request ${actionText}d successfully!`);
                            window.location.reload();
                        } else {
                            alert('Error: ' + data.error);
                        }
                    })
                    .catch(error => {
                        alert('Network error: ' + error);
                    });
                }
            }
            
            function revokeDownload(downloadId) {
                if (confirm('Revoke download access? The student will no longer be able to download this response.')) {
                    fetch('/revoke-download/' + downloadId, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            alert('Download access revoked!');
                            window.location.reload();
                        } else {
                            alert('Error: ' + data.error);
                        }
                    })
                    .catch(error => {
                        alert('Network error: ' + error);
                    });
                }
            }
        </script>
        '''
        
        return html_wrapper('Manage Downloads', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"Manage response downloads error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/request-download/<int:response_id>', methods=['POST'])
@login_required
def request_download(response_id):
    """Request download permission for a response - FIXED VERSION"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Check if response belongs to student
            cursor.execute('''
                SELECT r.*, f.title, f.form_type, f.created_by
                FROM responses r
                JOIN forms f ON r.form_id = f.id
                WHERE r.id = %s AND r.student_id = %s
            ''', (response_id, session['user_id']))
            response = cursor.fetchone()
            
            if not response:
                connection.close()
                return jsonify({'success': False, 'error': 'Response not found or access denied'}), 404
            
            # Check if already has permission
            if response['form_type'] == 'public':
                connection.close()
                return jsonify({'success': False, 'error': 'Public forms have automatic download access'}), 400
            
            # Check if request already exists
            cursor.execute('''
                SELECT id FROM response_downloads 
                WHERE response_id = %s AND student_id = %s
            ''', (response_id, session['user_id']))
            existing = cursor.fetchone()
            
            if existing:
                connection.close()
                return jsonify({'success': False, 'error': 'Download request already exists'}), 400
            
            # Create download request
            download_token, form_details = create_response_download_entry(
                response_id, session['user_id'], response['form_id']
            )
            
            if not download_token:
                connection.close()
                return jsonify({'success': False, 'error': 'Failed to create download request'}), 500
            
            connection.close()
            
            # Create notifications
            create_notification(
                user_id=session['user_id'],
                title='Download Request Sent',
                message=f'Download request sent for your response to "{response["title"]}".',
                type='info',
                link='/my-responses/downloads'
            )
            
            # Check if form_details exists and has creator_id
            if form_details and 'creator_id' in form_details:
                creator_id = form_details['creator_id']
                if creator_id != session['user_id']:
                    create_notification(
                        user_id=creator_id,
                        title='New Download Request',
                        message=f'{session["name"]} has requested to download their response to "{response["title"]}".',
                        type='warning',
                        link=f'/form/{response["form_id"]}/response-downloads'
                    )
            
            return jsonify({
                'success': True,
                'message': 'Download request submitted successfully'
            })
            
    except Exception as e:
        print(f"Request download error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    
@app.route('/debug/check-response/<int:response_id>')
@login_required
def debug_check_response(response_id):
    """Debug endpoint to check response details"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Get response details
            cursor.execute('''
                SELECT r.*, f.title, f.created_by, u.name as student_name
                FROM responses r
                JOIN forms f ON r.form_id = f.id
                JOIN users u ON r.student_id = u.id
                WHERE r.id = %s
            ''', (response_id,))
            response = cursor.fetchone()
            
            if not response:
                return jsonify({'error': 'Response not found'})
            
            # Check download entries
            cursor.execute('''
                SELECT * FROM response_downloads 
                WHERE response_id = %s AND student_id = %s
            ''', (response_id, session['user_id']))
            download_entry = cursor.fetchone()
            
            # Check form details
            cursor.execute('''
                SELECT f.*, u.name as creator_name, u.email as creator_email
                FROM forms f
                JOIN users u ON f.created_by = u.id
                WHERE f.id = %s
            ''', (response['form_id'],))
            form_details = cursor.fetchone()
            
        connection.close()
        
        return jsonify({
            'success': True,
            'response': response,
            'download_entry': download_entry,
            'form_details': form_details,
            'user_id': session['user_id'],
            'has_creator_id': 'created_by' in response if response else False,
            'form_details_keys': list(form_details.keys()) if form_details else []
        })
        
    except Exception as e:
        return jsonify({'error': str(e), 'traceback': traceback.format_exc()})

@app.route('/handle-download-request/<int:download_id>/<action>', methods=['POST'])
@teacher_required
def handle_download_request(download_id, action):
    """Approve or reject download request"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Get download request details
            cursor.execute('''
                SELECT rd.*, r.student_id, f.title, f.created_by as form_owner,
                       u.name as student_name, u.email as student_email
                FROM response_downloads rd
                JOIN responses r ON rd.response_id = r.id
                JOIN forms f ON rd.form_id = f.id
                JOIN users u ON rd.student_id = u.id
                WHERE rd.id = %s
            ''', (download_id,))
            download = cursor.fetchone()
            
            if not download:
                connection.close()
                return jsonify({'success': False, 'error': 'Download request not found'})
            
            # Check permissions
            if download['form_owner'] != session['user_id'] and session['role'] not in ['admin', 'super_admin']:
                connection.close()
                return jsonify({'success': False, 'error': 'Access denied'})
            
            if action == 'approve':
                # Grant access
                details = grant_download_access(download_id, session['user_id'])
                
                # Create notifications
                create_notification(
                    user_id=download['student_id'],
                    title='Download Access Granted',
                    message=f'Your download request for "{download["title"]}" has been approved.',
                    type='success',
                    link='/my-responses/downloads'
                )
                
                create_notification(
                    user_id=session['user_id'],
                    title='Download Request Approved',
                    message=f'You have approved {download["student_name"]}\'s download request.',
                    type='success',
                    link=f'/form/{download["form_id"]}/response-downloads'
                )
                
                # Send email notification
                if ENABLE_EMAIL_NOTIFICATIONS:
                    html_content = f'''
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #10b981;">Download Access Granted</h2>
                        <p>Hello {download['student_name']},</p>
                        <p>Your request to download your response has been approved.</p>
                        <div style="background: #f0f9ff; padding: 15px; border-radius: 10px; margin: 20px 0;">
                            <p><strong>Response Details:</strong></p>
                            <p>Form: {download['title']}</p>
                            <p>Approved By: {session['name']}</p>
                            <p>Approval Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        </div>
                        <p>You can now download your response from your dashboard.</p>
                        <a href="https://formmaster.up.railway.app/my-responses/downloads" style="display: inline-block; padding: 10px 20px; background: #10b981; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">Download Now</a>
                    </div>
                    '''
                    send_email(download['student_email'], 'Download Access Granted - FormMaster Pro', html_content)
                
                connection.close()
                return jsonify({'success': True, 'message': 'Download request approved'})
                
            elif action == 'reject':
                # Delete the download request
                cursor.execute('DELETE FROM response_downloads WHERE id = %s', (download_id,))
                connection.commit()
                connection.close()
                
                # Create notifications
                create_notification(
                    user_id=download['student_id'],
                    title='Download Request Rejected',
                    message=f'Your download request for "{download["title"]}" has been rejected.',
                    type='danger',
                    link='/my-responses/downloads'
                )
                
                create_notification(
                    user_id=session['user_id'],
                    title='Download Request Rejected',
                    message=f'You have rejected {download["student_name"]}\'s download request.',
                    type='warning',
                    link=f'/form/{download["form_id"]}/response-downloads'
                )
                
                return jsonify({'success': True, 'message': 'Download request rejected'})
            else:
                connection.close()
                return jsonify({'success': False, 'error': 'Invalid action'})
                
    except Exception as e:
        print(f"Handle download request error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/revoke-download/<int:download_id>', methods=['POST'])
@teacher_required
def revoke_download(download_id):
    """Revoke download access"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Get download details
            cursor.execute('''
                SELECT rd.*, r.student_id, f.title, f.created_by as form_owner,
                       u.name as student_name, u.email as student_email
                FROM response_downloads rd
                JOIN responses r ON rd.response_id = r.id
                JOIN forms f ON rd.form_id = f.id
                JOIN users u ON rd.student_id = u.id
                WHERE rd.id = %s
            ''', (download_id,))
            download = cursor.fetchone()
            
            if not download:
                connection.close()
                return jsonify({'success': False, 'error': 'Download not found'})
            
            # Check permissions
            if download['form_owner'] != session['user_id'] and session['role'] not in ['admin', 'super_admin']:
                connection.close()
                return jsonify({'success': False, 'error': 'Access denied'})
            
            # Revoke access
            cursor.execute('''
                UPDATE response_downloads 
                SET access_granted = FALSE,
                    granted_by = NULL,
                    granted_at = NULL
                WHERE id = %s
            ''', (download_id,))
            connection.commit()
            
            connection.close()
            
            # Create notifications
            create_notification(
                user_id=download['student_id'],
                title='Download Access Revoked',
                message=f'Your download access for "{download["title"]}" has been revoked.',
                type='danger',
                link='/my-responses/downloads'
            )
            
            create_notification(
                user_id=session['user_id'],
                title='Download Access Revoked',
                message=f'You have revoked {download["student_name"]}\'s download access.',
                type='warning',
                link=f'/form/{download["form_id"]}/response-downloads'
            )
            
            return jsonify({'success': True, 'message': 'Download access revoked'})
            
    except Exception as e:
        print(f"Revoke download error: {e}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/download-response/<int:response_id>')
@login_required
def download_response(response_id):
    """Download response as PDF - Improved Version"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Get response details with proper permission checks
            cursor.execute('''
                SELECT r.*, f.title, f.description, f.form_type, f.created_by as form_owner,
                       u.name as student_name, u2.name as teacher_name
                FROM responses r
                JOIN forms f ON r.form_id = f.id
                JOIN users u ON r.student_id = u.id
                LEFT JOIN users u2 ON f.created_by = u2.id
                WHERE r.id = %s
            ''', (response_id,))
            response = cursor.fetchone()
            
            if not response:
                connection.close()
                return '''
                <script>
                    alert("Response not found");
                    window.history.back();
                </script>
                ''', 404
            
            # Check download permissions
            admin_access = session['role'] in ['admin', 'super_admin']
            is_form_creator = response['form_owner'] == session['user_id']
            is_response_owner = response['student_id'] == session['user_id']
            
            # Check for explicit download permission
            cursor.execute('''
                SELECT rd.* FROM response_downloads rd
                WHERE rd.response_id = %s AND rd.student_id = %s
            ''', (response_id, session['user_id']))
            permission = cursor.fetchone()
            
            has_permission = False
            
            # Admin/Form Creator can always download
            if admin_access or is_form_creator:
                has_permission = True
            # Response owner with permission or public form
            elif is_response_owner:
                if response['form_type'] == 'public':
                    has_permission = True
                elif permission and permission['access_granted']:
                    has_permission = True
            
            if not has_permission:
                connection.close()
                return '''
                <script>
                    alert("You don't have permission to download this response");
                    window.history.back();
                </script>
                ''', 403
            
            # Update download count if there's a permission entry
            if permission:
                update_download_count(permission['id'])
            
            # Get form questions
            cursor.execute('SELECT questions FROM forms WHERE id = %s', (response['form_id'],))
            form_data = cursor.fetchone()
            
        connection.close()
        
        # Parse questions and answers
        try:
            if form_data and form_data['questions']:
                if isinstance(form_data['questions'], str):
                    questions = json.loads(form_data['questions'])
                elif isinstance(form_data['questions'], dict):
                    questions = form_data['questions']
                else:
                    questions = []
            else:
                questions = []
        except Exception as e:
            print(f"Error parsing questions: {e}")
            questions = []
        
        try:
            if response['answers'] and isinstance(response['answers'], str):
                answers = json.loads(response['answers'])
            elif response['answers'] and isinstance(response['answers'], dict):
                answers = response['answers']
            else:
                answers = {}
        except Exception as e:
            print(f"Error parsing answers: {e}")
            answers = {}
        
        # Generate PDF - Simplified version
        from io import BytesIO
        from flask import make_response
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        
        # Create PDF buffer
        buffer = BytesIO()
        
        try:
            # Create PDF document with error handling
            c = canvas.Canvas(buffer, pagesize=letter)
            width, height = letter
            
            # Simple header
            c.setFont("Helvetica-Bold", 16)
            c.drawString(100, height - 50, f"Response Report: {response['title']}")
            c.setFont("Helvetica", 12)
            
            # Basic information
            y = height - 80
            c.drawString(100, y, f"Student: {response['student_name']}")
            y -= 20
            c.drawString(100, y, f"Score: {response['score']}/{response['total_marks']} ({response['percentage']}%)")
            y -= 20
            c.drawString(100, y, f"Teacher: {response['teacher_name'] or 'N/A'}")
            y -= 20
            c.drawString(100, y, f"Submitted: {response['submitted_at'].strftime('%Y-%m-%d %H:%M:%S')}")
            y -= 40
            
            # Questions and Answers
            if questions:
                c.setFont("Helvetica-Bold", 14)
                c.drawString(100, y, "Questions & Answers:")
                y -= 30
                c.setFont("Helvetica", 12)
                
                for i, q in enumerate(questions, 1):
                    # Check if we need a new page
                    if y < 100:
                        c.showPage()
                        c.setFont("Helvetica", 12)
                        y = height - 50
                    
                    # Question
                    question_text = q.get('question', f'Question {i}')
                    c.setFont("Helvetica-Bold", 12)
                    c.drawString(100, y, f"Q{i}: {question_text}")
                    y -= 20
                    
                    # Answer
                    q_id = str(q.get('id', i-1))
                    student_answer = answers.get(q_id, 'Not answered')
                    
                    c.setFont("Helvetica", 10)
                    # Wrap answer text
                    answer_text = f"Answer: {student_answer}"
                    words = answer_text.split()
                    line = ""
                    
                    for word in words:
                        if len(line + " " + word) < 60:
                            line = line + " " + word if line else word
                        else:
                            c.drawString(120, y, line)
                            y -= 15
                            line = word
                    
                    if line:
                        c.drawString(120, y, line)
                        y -= 20
                    
                    # Add spacing between questions
                    y -= 10
            
            c.save()
            
            # Get PDF data
            pdf_data = buffer.getvalue()
            buffer.close()
            
            # Create response
            response_pdf = make_response(pdf_data)
            response_pdf.headers['Content-Type'] = 'application/pdf'
            response_pdf.headers['Content-Disposition'] = f'attachment; filename="response_{response_id}.pdf"'
            
            return response_pdf
            
        except Exception as pdf_error:
            print(f"PDF generation error: {pdf_error}")
            buffer.close()
            raise pdf_error
            
    except Exception as e:
        print(f"Download response error: {e}")
        traceback.print_exc()
        return '''
        <script>
            alert("Error downloading response. Please try again.");
            window.history.back();
        </script>
        ''', 500
    
@app.route('/test-pdf-generate')
@login_required
def test_pdf_generate():
    """Test PDF generation with sample data"""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from io import BytesIO
        from flask import make_response
        
        # Create simple test PDF
        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        
        c.setFont("Helvetica", 16)
        c.drawString(100, 750, "Test PDF Generation")
        c.setFont("Helvetica", 12)
        c.drawString(100, 720, f"User: {session['name']}")
        c.drawString(100, 700, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(100, 680, "This is a test PDF to verify generation works.")
        
        c.save()
        
        pdf_data = buffer.getvalue()
        buffer.close()
        
        response = make_response(pdf_data)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename="test_pdf.pdf"'
        
        return response
        
    except Exception as e:
        return f'''
        <html>
        <body>
            <script>
                alert("PDF Test Error: {str(e)}");
                window.history.back();
            </script>
        </body>
        </html>
        ''', 500

@app.route('/form/<int:form_id>/responses')
@login_required
def view_responses(form_id):
    try:
        # Get selected department for admin/super_admin
        selected_dept = request.args.get('department', '')
        
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            # Admin/super_admin can view all responses
            if session['role'] not in ['admin', 'super_admin']:
                if not form or (form['created_by'] != session['user_id'] and session['role'] not in ['admin', 'super_admin']):
                    connection.close()
                    return html_wrapper('Error', '<div class="alert alert-danger">Access denied</div>', get_navbar(), '')
            
            # Teachers can only view responses from their department
            if session['role'] == 'teacher' and form['department'] != session['department']:
                connection.close()
                return html_wrapper('Error', '''
                <div class="alert alert-danger">
                    <h4>Access Denied</h4>
                    <p>You can only view responses from forms in your department.</p>
                    <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
                </div>
                ''', get_navbar(), '')
            
            # Get responses with department filter for admin/super_admin
            if session['role'] in ['admin', 'super_admin'] and selected_dept:
                cursor.execute('''
                    SELECT r.*, u.name, u.email, u.department
                    FROM responses r 
                    JOIN users u ON r.student_id = u.id 
                    WHERE r.form_id = %s AND u.department = %s
                ''', (form_id, selected_dept))
            else:
                cursor.execute('''
                    SELECT r.*, u.name, u.email, u.department
                    FROM responses r 
                    JOIN users u ON r.student_id = u.id 
                    WHERE r.form_id = %s
                ''', (form_id,))
            responses = cursor.fetchall()
        connection.close()
        
        # Department filter for admin/super_admin
        dept_filter_html = ''
        if session['role'] in ['admin', 'super_admin']:
            departments_options = '<option value="">All Departments</option>'
            for dept in DEPARTMENTS:
                selected = 'selected' if dept == selected_dept else ''
                departments_options += f'<option value="{dept}" {selected}>{dept}</option>'
            
            dept_filter_html = f'''
            <div class="dept-filter mb-4">
                <h5 class="mb-3">Department Filter</h5>
                <form method="GET" action="/form/{form_id}/responses" class="row align-items-center">
                    <div class="col-md-4">
                        <select class="form-select" name="department" onchange="this.form.submit()">
                            {departments_options}
                        </select>
                    </div>
                    <div class="col-md-8">
                        <small class="text-muted">
                            Showing responses from: {selected_dept if selected_dept else "All Departments"}
                        </small>
                    </div>
                </form>
            </div>
            '''
        
        responses_html = ''
        for r in responses:
            responses_html += f'''
            <tr>
                <td>{r['name']}</td>
                <td>{r['email']}</td>
                <td>{r['department']}</td>
                <td>{r['score']}/{r['total_marks']}</td>
                <td>{r['percentage']}%</td>
                <td>{r['submitted_at']}</td>
            </tr>
            '''
        
        content = f'''
        <div class="mb-4">
            <h2 class="text-white">Responses for: {form['title']}</h2>
            <p class="text-white-50">Department: {form['department']} | Type: {form['form_type'].title()}</p>
        </div>
        
        {dept_filter_html}
        
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">
                    <i class="fas fa-chart-bar me-2"></i>Student Responses ({len(responses)})
                </h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Email</th>
                                <th>Department</th>
                                <th>Score</th>
                                <th>Percentage</th>
                                <th>Submitted</th>
                            </tr>
                        </thead>
                        <tbody>
                            {responses_html}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        '''
        
        return html_wrapper('Responses', content, get_navbar(), '')
        
    except Exception as e:
        print(f"View responses error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/teacher-analytics')
@teacher_required
def teacher_analytics():
    try:
        connection = get_db()
        user_dept = session['department']
        user_id = session['user_id']
        
        with connection.cursor() as cursor:
            # Get total forms created by teacher
            cursor.execute('''
                SELECT COUNT(*) as total_forms,
                       SUM(CASE WHEN form_type = 'open' THEN 1 ELSE 0 END) as open_forms,
                       SUM(CASE WHEN form_type = 'confidential' THEN 1 ELSE 0 END) as confidential_forms,
                       SUM(CASE WHEN is_student_submission = TRUE THEN 1 ELSE 0 END) as student_forms
                FROM forms 
                WHERE created_by = %s AND department = %s
            ''', (user_id, user_dept))
            form_stats = cursor.fetchone()
            
            # Get total responses for teacher's forms
            cursor.execute('''
                SELECT COUNT(*) as total_responses,
                       AVG(r.percentage) as avg_score,
                       MAX(r.percentage) as highest_score,
                       MIN(r.percentage) as lowest_score
                FROM responses r
                JOIN forms f ON r.form_id = f.id
                WHERE f.created_by = %s AND f.department = %s
            ''', (user_id, user_dept))
            response_stats = cursor.fetchone()
            
            # Get department-wise student statistics
            cursor.execute('''
                SELECT u.department,
                       COUNT(DISTINCT u.id) as total_students,
                       COUNT(DISTINCT r.student_id) as active_students,
                       AVG(r.percentage) as avg_score
                FROM users u
                LEFT JOIN responses r ON u.id = r.student_id
                LEFT JOIN forms f ON r.form_id = f.id AND f.created_by = %s
                WHERE u.role = 'student' AND u.department = %s
                GROUP BY u.department
            ''', (user_id, user_dept))
            dept_stats = cursor.fetchall()
            
            # Get recent form submissions
            cursor.execute('''
                SELECT f.title, r.submitted_at, u.name as student_name, r.percentage, 
                       r.score, r.total_marks, u.email as student_email
                FROM responses r
                JOIN forms f ON r.form_id = f.id
                JOIN users u ON r.student_id = u.id
                WHERE f.created_by = %s AND f.department = %s
                ORDER BY r.submitted_at DESC
                LIMIT 10
            ''', (user_id, user_dept))
            recent_submissions = cursor.fetchall()
            
            # Get form performance statistics
            cursor.execute('''
                SELECT f.id, f.title,
                       COUNT(r.id) as response_count,
                       AVG(r.percentage) as avg_score,
                       MAX(r.percentage) as highest_score,
                       MIN(r.percentage) as lowest_score,
                       SUM(CASE WHEN r.percentage >= 70 THEN 1 ELSE 0 END) as passed,
                       SUM(CASE WHEN r.percentage < 70 THEN 1 ELSE 0 END) as failed
                FROM forms f
                LEFT JOIN responses r ON f.id = r.form_id
                WHERE f.created_by = %s AND f.department = %s
                GROUP BY f.id, f.title
                ORDER BY response_count DESC
                LIMIT 10
            ''', (user_id, user_dept))
            form_performance = cursor.fetchall()
            
            # Get student performance details
            cursor.execute('''
                SELECT u.id, u.name, u.email,
                       COUNT(r.id) as forms_taken,
                       AVG(r.percentage) as avg_score,
                       MAX(r.percentage) as highest_score,
                       MIN(r.percentage) as lowest_score,
                       SUM(CASE WHEN r.percentage >= 70 THEN 1 ELSE 0 END) as passed_forms,
                       SUM(CASE WHEN r.percentage < 70 THEN 1 ELSE 0 END) as failed_forms
                FROM users u
                LEFT JOIN responses r ON u.id = r.student_id
                LEFT JOIN forms f ON r.form_id = f.id AND f.created_by = %s
                WHERE u.role = 'student' AND u.department = %s
                GROUP BY u.id, u.name, u.email
                ORDER BY avg_score DESC
            ''', (user_id, user_dept))
            student_performance = cursor.fetchall()
            
            # Get forms created by teacher
            cursor.execute('''
                SELECT f.id, f.title, f.form_type, f.is_published,
                       COUNT(DISTINCT r.id) as total_responses,
                       COUNT(DISTINCT a.student_id) as total_assignments,
                       f.created_at
                FROM forms f
                LEFT JOIN responses r ON f.id = r.form_id
                LEFT JOIN assignments a ON f.id = a.form_id
                WHERE f.created_by = %s AND f.department = %s
                GROUP BY f.id, f.title, f.form_type, f.is_published, f.created_at
                ORDER BY f.created_at DESC
            ''', (user_id, user_dept))
            teacher_forms = cursor.fetchall()

            # Get pending requests count
            cursor.execute('''
                SELECT COUNT(*) as pending_requests
                FROM form_requests fr
                JOIN forms f ON fr.form_id = f.id
                WHERE f.created_by = %s AND fr.status = 'pending'
            ''', (user_id,))
            pending_requests = cursor.fetchone()
            
            # Get pending reviews count
            cursor.execute('''
                SELECT COUNT(*) as pending_reviews
                FROM forms f
                WHERE f.is_student_submission = TRUE 
                AND f.review_status = 'pending'
                AND f.department = %s
            ''', (user_dept,))
            pending_reviews = cursor.fetchone()
            
        connection.close()
        
        # Helper function to convert datetime objects to strings
        def convert_datetimes(obj):
            if isinstance(obj, dict):
                return {k: convert_datetimes(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_datetimes(item) for item in obj]
            elif hasattr(obj, 'strftime'):  # Check if it's a datetime object
                return obj.strftime('%Y-%m-%d %H:%M:%S')
            elif hasattr(obj, 'isoformat'):  # Check if it's a date object
                return obj.isoformat()
            else:
                return obj
        
        # Convert datetime objects to strings for JSON serialization
        teacher_forms_converted = convert_datetimes(teacher_forms)
        recent_submissions_converted = convert_datetimes(recent_submissions)
        student_performance_converted = convert_datetimes(student_performance)
        
        # Recent submissions HTML
        recent_submissions_html = ''
        for sub in recent_submissions:
            score_class = 'success' if sub['percentage'] >= 70 else 'warning' if sub['percentage'] >= 50 else 'danger'
            recent_submissions_html += f'''
            <tr>
                <td>{sub['title']}</td>
                <td>{sub['student_name']}</td>
                <td><span class="badge bg-{score_class}">{sub['score']}/{sub['total_marks']} ({sub['percentage']}%)</span></td>
                <td>{sub['submitted_at'].strftime('%Y-%m-%d %H:%M')}</td>
            </tr>
            '''
        
        # Form performance HTML
        form_performance_html = ''
        for form in form_performance:
            if form['response_count'] > 0:
                avg_score = form['avg_score'] or 0
                passed_percent = (form['passed'] / form['response_count'] * 100) if form['response_count'] > 0 else 0
                form_performance_html += f'''
                <tr onclick="showFormDetails({form['id']})" style="cursor: pointer;">
                    <td>{form['title']}</td>
                    <td>{form['response_count']}</td>
                    <td>{avg_score:.1f}%</td>
                    <td>{form['highest_score']}%</td>
                    <td>{form['lowest_score']}%</td>
                    <td><span class="badge bg-success">{form['passed']}</span> / <span class="badge bg-danger">{form['failed']}</span></td>
                </tr>
                '''
        
        # Student performance HTML
        student_performance_html = ''
        for student in student_performance:
            if student['forms_taken'] > 0:
                score_class = 'success' if student['avg_score'] >= 70 else 'warning' if student['avg_score'] >= 50 else 'danger'
                student_performance_html += f'''
                <tr onclick="showStudentDetails({student['id']})" style="cursor: pointer;">
                    <td>{student['name']}</td>
                    <td>{student['email']}</td>
                    <td>{student['forms_taken']}</td>
                    <td><span class="badge bg-{score_class}">{student['avg_score']:.1f}%</span></td>
                    <td><span class="badge bg-success">{student['passed_forms']}</span> / <span class="badge bg-danger">{student['failed_forms']}</span></td>
                </tr>
                '''
        
        # Teacher forms HTML
        teacher_forms_html = ''
        for form in teacher_forms:
            type_badge = 'info' if form['form_type'] == 'open' else 'purple'
            status_badge = 'success' if form['is_published'] else 'warning'
            
            # Add publish button for admin/super_admin
            publish_button = ''
            if session['role'] in ['admin', 'super_admin']:
                publish_text = 'Unpublish' if form['is_published'] else 'Publish'
                publish_class = 'warning' if form['is_published'] else 'success'
                publish_button = f'''
                <button onclick="togglePublish({form['id']}, {form['is_published']}, '{form['title']}')" 
                        class="btn btn-sm btn-outline-{publish_class}">
                    <i class="fas {'fa-eye-slash' if form['is_published'] else 'fa-eye'}"></i>
                </button>
                '''
            
            teacher_forms_html += f'''
            <tr onclick="showFormDetails({form['id']})" style="cursor: pointer;">
                <td>{form['title']}</td>
                <td><span class="badge bg-{type_badge}">{form['form_type'].title()}</span></td>
                <td>
                    <span class="badge bg-{status_badge}">{'Published' if form['is_published'] else 'Draft'}</span>
                    {publish_button}
                </td>
                <td>{form['total_responses']}</td>
                <td>{form['total_assignments']}</td>
                <td>{form['created_at'].strftime('%Y-%m-%d')}</td>
            </tr>
            '''
        
        content = f'''
        <div class="mb-4">
            <h2 class="text-white">Teacher Analytics - {session['department']} Department</h2>
            <p class="text-white-50">Track your department's form performance and student engagement</p>
        </div>
        
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="stat-card" style="background: linear-gradient(45deg, #667eea, #764ba2); cursor: pointer;" 
                     onclick="showDetails('forms')" data-bs-toggle="modal" data-bs-target="#detailsModal">
                    <h5>Total Forms</h5>
                    <h2>{form_stats['total_forms'] or 0}</h2>
                    <small>Open: {form_stats['open_forms'] or 0} | Confidential: {form_stats['confidential_forms'] or 0}</small>
                    <small>Student Forms: {form_stats['student_forms'] or 0}</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card" style="background: linear-gradient(45deg, #10b981, #059669); cursor: pointer;"
                     onclick="showDetails('responses')" data-bs-toggle="modal" data-bs-target="#detailsModal">
                    <h5>Total Responses</h5>
                    <h2>{response_stats['total_responses'] or 0}</h2>
                    <small>Average: {response_stats['avg_score'] or 0:.1f}%</small>
                    <small>Best: {response_stats['highest_score'] or 0}% | Lowest: {response_stats['lowest_score'] or 0}%</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card" style="background: linear-gradient(45deg, #f59e0b, #d97706); cursor: pointer;"
                     onclick="showDetails('students')" data-bs-toggle="modal" data-bs-target="#detailsModal">
                    <h5>Students</h5>
                    <h2>{dept_stats[0]['total_students'] if dept_stats else 0}</h2>
                    <small>Active: {dept_stats[0]['active_students'] if dept_stats else 0}</small>
                    <small>Avg Score: {'%.1f' % (dept_stats[0].get('avg_score', 0) if dept_stats else 0)}%</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card" style="background: linear-gradient(45deg, #ef4444, #dc2626); cursor: pointer;"
                     onclick="showDetails('pending')" data-bs-toggle="modal" data-bs-target="#detailsModal">
                    <h5>Pending</h5>
                    <h2>{pending_requests['pending_requests'] + pending_reviews['pending_reviews']}</h2>
                    <small>Requests: {pending_requests['pending_requests']}</small>
                    <small>Reviews: {pending_reviews['pending_reviews']}</small>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5>Recent Submissions ({len(recent_submissions)})</h5>
                        <a href="/form-requests" class="btn btn-sm btn-primary">View All</a>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Form</th>
                                        <th>Student</th>
                                        <th>Score</th>
                                        <th>Submitted</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {recent_submissions_html}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5>Top Performing Forms</h5>
                        <a href="/dashboard" class="btn btn-sm btn-primary">View All</a>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Form Title</th>
                                        <th>Responses</th>
                                        <th>Avg Score</th>
                                        <th>Highest</th>
                                        <th>Lowest</th>
                                        <th>Pass/Fail</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {form_performance_html}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5>Student Performance</h5>
                        <button onclick="exportStudentData()" class="btn btn-sm btn-success">
                            <i class="fas fa-download me-1"></i>Export
                        </button>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Student Name</th>
                                        <th>Email</th>
                                        <th>Forms Taken</th>
                                        <th>Avg Score</th>
                                        <th>Pass/Fail</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {student_performance_html}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5>My Forms ({len(teacher_forms)})</h5>
                        <a href="/dashboard" class="btn btn-sm btn-primary">Manage</a>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Form Title</th>
                                        <th>Type</th>
                                        <th>Status</th>
                                        <th>Responses</th>
                                        <th>Assignments</th>
                                        <th>Created</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {teacher_forms_html}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Details Modal -->
        <div class="modal fade" id="detailsModal" tabindex="-1" aria-labelledby="detailsModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="detailsModalLabel">Detailed Statistics</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body" id="modalContent">
                        <!-- Content will be loaded dynamically -->
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-primary" onclick="exportData()">Export as CSV</button>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        # Convert Decimal objects to float for JSON serialization
        def convert_decimals(obj):
            if isinstance(obj, dict):
                return {k: convert_decimals(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_decimals(item) for item in obj]
            elif isinstance(obj, Decimal):
                return float(obj)
            else:
                return obj
        
        # Convert all data for JavaScript
        teacher_forms_js = json.dumps(convert_decimals(teacher_forms_converted))
        recent_submissions_js = json.dumps(convert_decimals(recent_submissions_converted))
        student_performance_js = json.dumps(convert_decimals(student_performance_converted))
        
        scripts = f'''
        <script>
            let currentView = '';
            let currentData = {{
                forms: {teacher_forms_js},
                responses: {recent_submissions_js},
                students: {student_performance_js},
                pending: {{
                    requests: {pending_requests['pending_requests']},
                    reviews: {pending_reviews['pending_reviews']}
                }}
            }};
            
            function showDetails(viewType) {{
                currentView = viewType;
                let modalTitle = document.getElementById('detailsModalLabel');
                let modalContent = document.getElementById('modalContent');
                
                switch(viewType) {{
                    case 'forms':
                        modalTitle.textContent = 'Forms Created by You';
                        modalContent.innerHTML = generateFormsHTML();
                        break;
                    case 'responses':
                        modalTitle.textContent = 'Recent Form Responses';
                        modalContent.innerHTML = generateResponsesHTML();
                        break;
                    case 'students':
                        modalTitle.textContent = 'Student Performance Details';
                        modalContent.innerHTML = generateStudentsHTML();
                        break;
                    case 'pending':
                        modalTitle.textContent = 'Pending Tasks';
                        modalContent.innerHTML = generatePendingHTML();
                        break;
                }}
            }}
            
            function generateFormsHTML() {{
                let html = `
                    <div class="table-responsive">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Form Title</th>
                                    <th>Type</th>
                                    <th>Status</th>
                                    <th>Responses</th>
                                    <th>Assignments</th>
                                    <th>Created Date</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                `;
                
                currentData.forms.forEach(form => {{
                    let typeBadge = form.form_type === 'open' ? 'info' : 'purple';
                    let statusBadge = form.is_published ? 'success' : 'warning';
                    
                    html += `
                        <tr>
                            <td>${{form.title}}</td>
                            <td><span class="badge bg-${{typeBadge}}">${{form.form_type.toUpperCase()}}</span></td>
                            <td><span class="badge bg-${{statusBadge}}">${{form.is_published ? 'PUBLISHED' : 'DRAFT'}}</span></td>
                            <td>${{form.total_responses || 0}}</td>
                            <td>${{form.total_assignments || 0}}</td>
                            <td>${{form.created_at}}</td>
                            <td>
                                <div class="btn-group btn-group-sm">
                                    <a href="/form/${{form.id}}/edit" class="btn btn-outline-primary">Edit</a>
                                    <a href="/form/${{form.id}}/responses" class="btn btn-outline-success">Results</a>
                                    <a href="/form/${{form.id}}/assign" class="btn btn-outline-warning">Assign</a>
                                </div>
                            </td>
                        </tr>
                    `;
                }});
                
                html += `
                            </tbody>
                        </table>
                    </div>
                    <div class="mt-3">
                        <h6>Form Statistics:</h6>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="card">
                                    <div class="card-body">
                                        <h6>Form Types</h6>
                                        <ul class="list-unstyled">
                                            <li>Open Forms: ${{currentData.forms.filter(f => f.form_type === 'open').length}}</li>
                                            <li>Confidential Forms: ${{currentData.forms.filter(f => f.form_type === 'confidential').length}}</li>
                                        </ul>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="card">
                                    <div class="card-body">
                                        <h6>Status</h6>
                                        <ul class="list-unstyled">
                                            <li>Published: ${{currentData.forms.filter(f => f.is_published).length}}</li>
                                            <li>Drafts: ${{currentData.forms.filter(f => !f.is_published).length}}</li>
                                        </ul>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
                
                return html;
            }}
            
            function generateResponsesHTML() {{
                let html = `
                    <div class="table-responsive">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Form Title</th>
                                    <th>Student</th>
                                    <th>Email</th>
                                    <th>Score</th>
                                    <th>Percentage</th>
                                    <th>Submitted</th>
                                </tr>
                            </thead>
                            <tbody>
                `;
                
                currentData.responses.forEach(response => {{
                    let scoreClass = response.percentage >= 70 ? 'success' : response.percentage >= 50 ? 'warning' : 'danger';
                    
                    html += `
                        <tr>
                            <td>${{response.title}}</td>
                            <td>${{response.student_name}}</td>
                            <td>${{response.student_email}}</td>
                            <td><span class="badge bg-${{scoreClass}}">${{response.score}}/${{response.total_marks}}</span></td>
                            <td>${{response.percentage}}%</td>
                            <td>${{response.submitted_at}}</td>
                        </tr>
                    `;
                }});
                
                // Calculate statistics
                let totalResponses = currentData.responses.length;
                let avgScore = totalResponses > 0 ? currentData.responses.reduce((sum, r) => sum + r.percentage, 0) / totalResponses : 0;
                let passed = currentData.responses.filter(r => r.percentage >= 70).length;
                let failed = currentData.responses.filter(r => r.percentage < 70).length;
                
                html += `
                            </tbody>
                        </table>
                    </div>
                    <div class="mt-3">
                        <h6>Response Statistics:</h6>
                        <div class="row">
                            <div class="col-md-4">
                                <div class="card">
                                    <div class="card-body">
                                        <h6>Overall</h6>
                                        <ul class="list-unstyled">
                                            <li>Total Responses: ${{totalResponses}}</li>
                                            <li>Average Score: ${{avgScore.toFixed(1)}}%</li>
                                        </ul>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="card">
                                    <div class="card-body">
                                        <h6>Pass/Fail</h6>
                                        <ul class="list-unstyled">
                                            <li>Passed: ${{passed}} (${{((passed/totalResponses)*100).toFixed(1)}}%)</li>
                                            <li>Failed: ${{failed}} (${{((failed/totalResponses)*100).toFixed(1)}}%)</li>
                                        </ul>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="card">
                                    <div class="card-body">
                                        <h6>Score Distribution</h6>
                                        <ul class="list-unstyled">
                                            <li>90-100%: ${{currentData.responses.filter(r => r.percentage >= 90).length}}</li>
                                            <li>70-89%: ${{currentData.responses.filter(r => r.percentage >= 70 && r.percentage < 90).length}}</li>
                                            <li>50-69%: ${{currentData.responses.filter(r => r.percentage >= 50 && r.percentage < 70).length}}</li>
                                            <li>Below 50%: ${{currentData.responses.filter(r => r.percentage < 50).length}}</li>
                                        </ul>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
                
                return html;
            }}
            
            function generateStudentsHTML() {{
                let html = `
                    <div class="table-responsive">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Student Name</th>
                                    <th>Email</th>
                                    <th>Forms Taken</th>
                                    <th>Avg Score</th>
                                    <th>Highest Score</th>
                                    <th>Lowest Score</th>
                                    <th>Passed Forms</th>
                                    <th>Failed Forms</th>
                                </tr>
                            </thead>
                            <tbody>
                `;
                
                currentData.students.forEach(student => {{
                    let scoreClass = student.avg_score >= 70 ? 'success' : student.avg_score >= 50 ? 'warning' : 'danger';
                    
                    html += `
                        <tr onclick="showStudentDetails(${{student.id}})" style="cursor: pointer;">
                            <td>${{student.name}}</td>
                            <td>${{student.email}}</td>
                            <td>${{student.forms_taken || 0}}</td>
                            <td><span class="badge bg-${{scoreClass}}">${{student.avg_score ? student.avg_score.toFixed(1) : 0}}%</span></td>
                            <td>${{student.highest_score || 0}}%</td>
                            <td>${{student.lowest_score || 0}}%</td>
                            <td><span class="badge bg-success">${{student.passed_forms || 0}}</span></td>
                            <td><span class="badge bg-danger">${{student.failed_forms || 0}}</span></td>
                        </tr>
                    `;
                }});
                
                // Calculate statistics
                let totalStudents = currentData.students.length;
                let activeStudents = currentData.students.filter(s => s.forms_taken > 0).length;
                let avgScore = totalStudents > 0 ? currentData.students.reduce((sum, s) => sum + (s.avg_score || 0), 0) / totalStudents : 0;
                
                html += `
                            </tbody>
                        </table>
                    </div>
                    <div class="mt-3">
                        <h6>Student Statistics:</h6>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="card">
                                    <div class="card-body">
                                        <h6>Participation</h6>
                                        <ul class="list-unstyled">
                                            <li>Total Students: ${{totalStudents}}</li>
                                            <li>Active Students: ${{activeStudents}} (${{((activeStudents/totalStudents)*100).toFixed(1)}}%)</li>
                                            <li>Inactive Students: ${{totalStudents - activeStudents}}</li>
                                        </ul>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="card">
                                    <div class="card-body">
                                        <h6>Performance</h6>
                                        <ul class="list-unstyled">
                                            <li>Class Average: ${{avgScore.toFixed(1)}}%</li>
                                            <li>Top Performers: ${{currentData.students.filter(s => s.avg_score >= 70).length}}</li>
                                            <li>Need Improvement: ${{currentData.students.filter(s => s.avg_score < 50).length}}</li>
                                        </ul>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
                
                return html;
            }}
            
            function generatePendingHTML() {{
                let html = `
                    <div class="row">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header bg-warning text-dark">
                                    <h6 class="mb-0">Pending Form Requests</h6>
                                </div>
                                <div class="card-body">
                                    <h2 class="text-center">${{currentData.pending.requests}}</h2>
                                    <p class="text-center">Students waiting for form access approval</p>
                                    <div class="text-center">
                                        <a href="/form-requests" class="btn btn-warning">Review Requests</a>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header bg-info text-dark">
                                    <h6 class="mb-0">Pending Form Reviews</h6>
                                </div>
                                <div class="card-body">
                                    <h2 class="text-center">${{currentData.pending.reviews}}</h2>
                                    <p class="text-center">Student forms waiting for your review</p>
                                    <div class="text-center">
                                        <a href="/review-forms" class="btn btn-info">Review Forms</a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
                
                return html;
            }}
            
            function showFormDetails(formId) {{
                window.location.href = '/form/' + formId + '/responses';
            }}
            
            function showStudentDetails(studentId) {{
                // Create a modal to show student details
                fetch('/api/student-details/' + studentId)
                    .then(res => res.json())
                    .then(data => {{
                        if (data.success) {{
                            let modal = new bootstrap.Modal(document.getElementById('studentDetailsModal'));
                            document.getElementById('studentModalContent').innerHTML = data.html;
                            modal.show();
                        }}
                    }});
            }}
            
            function exportData() {{
                let csvContent = "data:text/csv;charset=utf-8,";
                
                switch(currentView) {{
                    case 'forms':
                        csvContent += "Form Title,Type,Status,Responses,Assignments,Created Date\\n";
                        currentData.forms.forEach(form => {{
                            csvContent += `${{form.title}},${{form.form_type}},${{form.is_published ? 'Published' : 'Draft'}},${{form.total_responses || 0}},${{form.total_assignments || 0}},${{form.created_at}}\\n`;
                        }});
                        break;
                    case 'responses':
                        csvContent += "Form Title,Student Name,Student Email,Score,Percentage,Submitted\\n";
                        currentData.responses.forEach(response => {{
                            csvContent += `${{response.title}},${{response.student_name}},${{response.student_email}},${{response.score}}/${{response.total_marks}},${{response.percentage}}%,${{response.submitted_at}}\\n`;
                        }});
                        break;
                    case 'students':
                        csvContent += "Student Name,Email,Forms Taken,Avg Score,Highest Score,Lowest Score,Passed Forms,Failed Forms\\n";
                        currentData.students.forEach(student => {{
                            csvContent += `${{student.name}},${{student.email}},${{student.forms_taken || 0}},${{student.avg_score ? student.avg_score.toFixed(1) : 0}}%,${{student.highest_score || 0}}%,${{student.lowest_score || 0}}%,${{student.passed_forms || 0}},${{student.failed_forms || 0}}\\n`;
                        }});
                        break;
                }}
                
                let encodedUri = encodeURI(csvContent);
                let link = document.createElement("a");
                link.setAttribute("href", encodedUri);
                link.setAttribute("download", `teacher_analytics_${{currentView}}.csv`);
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }}
            
            function exportStudentData() {{
                let csvContent = "data:text/csv;charset=utf-8,";
                csvContent += "Student Name,Email,Forms Taken,Avg Score,Highest Score,Lowest Score,Passed Forms,Failed Forms\\n";
                
                let students = {json.dumps(convert_decimals(student_performance))};
                students.forEach(student => {{
                    csvContent += `${{student.name}},${{student.email}},${{student.forms_taken || 0}},${{student.avg_score ? student.avg_score.toFixed(1) : 0}}%,${{student.highest_score || 0}}%,${{student.lowest_score || 0}}%,${{student.passed_forms || 0}},${{student.failed_forms || 0}}\\n`;
                }});
                
                let encodedUri = encodeURI(csvContent);
                let link = document.createElement("a");
                link.setAttribute("href", encodedUri);
                link.setAttribute("download", "student_performance.csv");
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }}
        </script>
        
        <!-- Student Details Modal -->
        <div class="modal fade" id="studentDetailsModal" tabindex="-1" aria-labelledby="studentDetailsModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="studentDetailsModalLabel">Student Details</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body" id="studentModalContent">
                        <!-- Content loaded dynamically -->
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        return html_wrapper('Teacher Analytics', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"Teacher analytics error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')
    
@app.route('/form/<int:form_id>/delete', methods=['POST'])
@super_admin_required
def delete_form(form_id):
    """Delete a form (Super Admin only)"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Get form details for notification
            cursor.execute('SELECT title, created_by FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            if not form:
                connection.close()
                return jsonify({'success': False, 'error': 'Form not found'})
            
            # Delete the form
            cursor.execute('DELETE FROM forms WHERE id = %s', (form_id,))
            connection.commit()
        
        connection.close()
        
        # Create notification for super admin
        create_notification(
            user_id=session['user_id'],
            title='Form Deleted',
            message=f'Form "{form["title"]}" has been deleted.',
            type='danger'
        )
        
        # Create notification for form creator (if different from super admin)
        if form['created_by'] != session['user_id']:
            create_notification(
                user_id=form['created_by'],
                title='Your Form Was Deleted',
                message=f'Your form "{form["title"]}" was deleted by the super administrator.',
                type='danger',
                link='/dashboard'
            )
        
        # Send deletion email notification
        if ENABLE_EMAIL_NOTIFICATIONS:
            # Get creator details
            connection = get_db()
            with connection.cursor() as cursor:
                cursor.execute('SELECT email, name FROM users WHERE id = %s', (form['created_by'],))
                creator = cursor.fetchone()
            connection.close()
            
            if creator:
                html_content = f'''
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #ef4444;">Form Deleted</h2>
                    <p>Hello {creator['name']},</p>
                    <p>Your form has been deleted by the super administrator.</p>
                    <div style="background: #fef2f2; padding: 15px; border-radius: 10px; margin: 20px 0;">
                        <p><strong>Form Details:</strong></p>
                        <p>Title: {form['title']}</p>
                        <p>Deleted By: {session['name']} (Super Admin)</p>
                        <p>Deletion Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    <p>If you believe this was a mistake, please contact the system administrator.</p>
                    <hr>
                    <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
                </div>
                '''
                send_email(creator['email'], 'Form Deleted - FormMaster Pro', html_content)
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Delete form error: {e}")
        return jsonify({'success': False, 'error': str(e)})
@app.route('/form/<int:form_id>/share')
@teacher_required
def share_form(form_id):
    """Share form page"""
    try:
        # First, ensure the form has a share token
        share_token = ensure_form_has_share_token(form_id)
        if not share_token:
            return html_wrapper('Error', '<div class="alert alert-danger">Could not generate share link</div>', get_navbar(), '')
        
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            if not form:
                connection.close()
                return html_wrapper('Error', '<div class="alert alert-danger">Form not found</div>', get_navbar(), '')
            
            # Check permissions
            if form['created_by'] != session['user_id'] and session['role'] not in ['admin', 'super_admin']:
                connection.close()
                return html_wrapper('Error', '''
                <div class="alert alert-danger">
                    <h4>Access Denied</h4>
                    <p>You can only share forms that you created.</p>
                    <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
                </div>
                ''', get_navbar(), '')
            
            # Teachers can only share forms from their department
            if session['role'] == 'teacher' and form['department'] != session['department']:
                connection.close()
                return html_wrapper('Error', '''
                <div class="alert alert-danger">
                    <h4>Access Denied</h4>
                    <p>You can only share forms from your department.</p>
                    <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
                </div>
                ''', get_navbar(), '')
        
        connection.close()
        
        # Create public link
        public_link = f"http://{request.host}/public/form/{share_token}"
        
        # Check form status for warnings
        status_warnings = []
        if not form.get('is_published'):
            status_warnings.append('<li><i class="fas fa-exclamation-triangle text-warning me-2"></i>Form is not published</li>')
        
        if form.get('is_student_submission') and form.get('review_status') != 'approved':
            status_text = 'pending review' if form.get('review_status') == 'pending' else 'rejected'
            status_warnings.append(f'<li><i class="fas fa-exclamation-triangle text-warning me-2"></i>Student form is {status_text}</li>')
        
        if not form.get('public_link_enabled'):
            status_warnings.append('<li><i class="fas fa-exclamation-triangle text-warning me-2"></i>Public link is disabled</li>')
        
        status_warning_html = ''
        if status_warnings:
            status_warning_html = f'''
            <div class="alert alert-warning">
                <h6><i class="fas fa-exclamation-triangle me-2"></i>Important Status Notes:</h6>
                <ul class="mb-0">
                    {''.join(status_warnings)}
                </ul>
                <p class="mb-0 mt-2"><small>Users may not be able to access the form until these issues are resolved.</small></p>
            </div>
            '''
        
        # Add QR code option for easier sharing
        qr_code_url = f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={public_link}"
        
        content = f'''
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h4 class="mb-0">Share Form: {form['title']}</h4>
                                <p class="mb-0">{form['description'] or 'No description'}</p>
                            </div>
                            <div>
                                <span class="badge {'bg-success' if form.get('public_link_enabled') else 'bg-secondary'}">
                                    {'PUBLIC LINK ENABLED' if form.get('public_link_enabled') else 'LINK DISABLED'}
                                </span>
                            </div>
                        </div>
                    </div>
                    <div class="card-body">
                        {status_warning_html}
                        
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle me-2"></i>
                            <strong>How it works:</strong> When users click the shared link, they will be:
                            <ol class="mt-2 mb-0">
                                <li>Redirected to login if not authenticated</li>
                                <li>After login, taken directly to the form</li>
                                <li>Access will be granted based on their role and permissions</li>
                            </ol>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-8">
                                <div class="share-link-box">
                                    <h5><i class="fas fa-link me-2"></i>Public Share Link</h5>
                                    <div class="input-group mb-3">
                                        <input type="text" class="form-control" id="shareLink" value="{public_link}" readonly>
                                        <button class="btn btn-outline-primary copy-btn" onclick="copyToClipboard('shareLink', event)">                                            <i class="fas fa-copy"></i> Copy
                                        </button>
                                    </div>
                                    
                                    <div class="form-check mb-3">
                                        <input class="form-check-input" type="checkbox" id="enablePublicLink" 
                                               onchange="togglePublicLink({form_id})" {'checked' if form.get('public_link_enabled') else ''}>
                                        <label class="form-check-label" for="enablePublicLink">
                                            <strong>Enable public link</strong>
                                            <small class="d-block text-muted">When disabled, the link will show "Form Not Found"</small>
                                        </label>
                                    </div>
                                    
                                    <div class="share-actions">
                                        <a href="mailto:?subject=Check%20this%20form:%20{form['title']}&body=Hello,%0A%0APlease%20check%20this%20form:%20{public_link}%0A%0ABest%20regards,%0A{session['name']}" 
                                           class="btn btn-outline-primary">
                                            <i class="fas fa-envelope me-2"></i>Email
                                        </a>
                                        <a href="https://wa.me/?text=Check%20this%20form:%20{form['title']}%0A{public_link}" 
                                           class="btn btn-outline-success" target="_blank">
                                            <i class="fab fa-whatsapp me-2"></i>WhatsApp
                                        </a>
                                        <button onclick="regenerateToken({form_id})" class="btn btn-outline-danger">
                                            <i class="fas fa-sync-alt me-2"></i>Regenerate
                                        </button>
                                        <button onclick="testShareLink()" class="btn btn-outline-info">
                                            <i class="fas fa-test me-2"></i>Test Link
                                        </button>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="card">
                                    <div class="card-body text-center">
                                        <h6>QR Code</h6>
                                        <img src="{qr_code_url}" alt="QR Code" class="img-fluid mb-2" style="max-width: 150px;">
                                        <p class="text-muted small">Scan to open on mobile devices</p>
                                        <button onclick="downloadQRCode()" class="btn btn-sm btn-outline-secondary">
                                            <i class="fas fa-download me-1"></i>Download QR
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="row mt-4">
                            <div class="col-md-6">
                                <div class="card">
                                    <div class="card-header">
                                        <h6 class="mb-0"><i class="fas fa-info-circle me-2"></i>Form Information</h6>
                                    </div>
                                    <div class="card-body">
                                        <table class="table table-sm">
                                            <tr>
                                                <th>Title:</th>
                                                <td>{form['title']}</td>
                                            </tr>
                                            <tr>
                                                <th>Department:</th>
                                                <td><span class="badge bg-dark">{form['department']}</span></td>
                                            </tr>
                                            <tr>
                                                <th>Type:</th>
                                                <td><span class="badge {'bg-info' if form['form_type'] == 'open' else 'bg-purple'}">{form['form_type'].upper()}</span></td>
                                            </tr>
                                            <tr>
                                                <th>Status:</th>
                                                <td>
                                                    <span class="badge {'bg-success' if form['is_published'] else 'bg-warning'}">
                                                        {'PUBLISHED' if form['is_published'] else 'DRAFT'}
                                                    </span>
                                                    {f'<span class="badge bg-warning ms-1">STUDENT CREATED</span>' if form.get('is_student_submission') else ''}
                                                    {f'<span class="badge bg-info ms-1">{form["review_status"].upper()}</span>' if form.get('is_student_submission') and form.get('review_status') else ''}
                                                </td>
                                            </tr>
                                            <tr>
                                                <th>Created:</th>
                                                <td>{form['created_at'].strftime('%Y-%m-%d')}</td>
                                            </tr>
                                        </table>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="card">
                                    <div class="card-header">
                                        <h6 class="mb-0"><i class="fas fa-user-shield me-2"></i>Access Rules</h6>
                                    </div>
                                    <div class="card-body">
                                        <h6>Who can access via this link:</h6>
                                        <ul class="mb-3">
                                            <li><strong>Admins/Super Admins:</strong> Can always access</li>
                                            <li><strong>Teachers:</strong> Only from {form['department']} department</li>
                                            <li><strong>Students:</strong>
                                            <ul>
                                                <li>From {form['department']} department</li>
                                                <li><strong>Public forms:</strong> Direct access without request</li>
                                                <li><strong>Open forms:</strong> Direct access</li>
                                                <li><strong>Confidential forms:</strong> Need to request access</li>
                                                <li>Must not have already submitted</li>
                                            </ul>
                                        </li>
                                        </ul>
                                        <div class="alert alert-light">
                                            <i class="fas fa-lightbulb me-2"></i>
                                            <small>For best results, ensure the form is published and accessible to your intended audience.</small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="mt-4">
                            <h5><i class="fas fa-history me-2"></i>Share History</h5>
                            <div class="table-responsive">
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Date</th>
                                            <th>Action</th>
                                            <th>Link Status</th>
                                            <th>Form Status</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td>{form['created_at'].strftime('%Y-%m-%d %H:%M')}</td>
                                            <td>Form Created</td>
                                            <td><span class="badge bg-secondary">N/A</span></td>
                                            <td><span class="badge {'bg-success' if form['is_published'] else 'bg-warning'}">{'Published' if form['is_published'] else 'Draft'}</span></td>
                                        </tr>
                                        <tr>
                                            <td>{form['updated_at'].strftime('%Y-%m-%d %H:%M') if form['updated_at'] else 'N/A'}</td>
                                            <td>Last Updated</td>
                                            <td><span class="badge {'bg-success' if form.get('public_link_enabled') else 'bg-secondary'}">{'Enabled' if form.get('public_link_enabled') else 'Disabled'}</span></td>
                                            <td>—</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    <div class="card-footer">
                        <div class="d-flex justify-content-between">
                            <div>
                                <a href="/dashboard" class="btn btn-secondary">
                                    <i class="fas fa-arrow-left me-2"></i>Back to Dashboard
                                </a>
                                <a href="/form/{form_id}/edit" class="btn btn-primary ms-2">
                                    <i class="fas fa-edit me-2"></i>Edit Form
                                </a>
                            </div>
                            <div>
                                <a href="/form/{form_id}/responses" class="btn btn-success">
                                    <i class="fas fa-chart-bar me-2"></i>View Responses
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        scripts = f'''
        <script>
            function copyToClipboard(elementId, event) {{
                if (event) event.preventDefault();
                
                const copyText = document.getElementById(elementId);
                copyText.select();
                copyText.setSelectionRange(0, 99999);
                
                try {{
                    // Try using the modern Clipboard API first
                    navigator.clipboard.writeText(copyText.value).then(() => {{
                        // Show feedback
                        const btn = event ? event.target.closest('.copy-btn') : document.querySelector('.copy-btn');
                        if (btn) {{
                            const originalHTML = btn.innerHTML;
                            btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                            btn.classList.remove('btn-outline-primary');
                            btn.classList.add('btn-success');
                            
                            setTimeout(() => {{
                                btn.innerHTML = originalHTML;
                                btn.classList.remove('btn-success');
                                btn.classList.add('btn-outline-primary');
                            }}, 2000);
                        }}
                        
                        // Show toast notification
                        showToast('Link copied to clipboard!', 'success');
                    }}).catch(err => {{
                        // Fallback to older method
                        fallbackCopyTextToClipboard(copyText.value);
                    }});
                }} catch (err) {{
                    // Fallback to older method
                    fallbackCopyTextToClipboard(copyText.value);
                }}
            }}
            
            // Fallback method for older browsers
            function fallbackCopyTextToClipboard(text) {{
                const textArea = document.createElement('textarea');
                textArea.value = text;
                textArea.style.position = 'fixed';
                textArea.style.top = '0';
                textArea.style.left = '0';
                textArea.style.width = '2em';
                textArea.style.height = '2em';
                textArea.style.padding = '0';
                textArea.style.border = 'none';
                textArea.style.outline = 'none';
                textArea.style.boxShadow = 'none';
                textArea.style.background = 'transparent';
                
                document.body.appendChild(textArea);
                textArea.focus();
                textArea.select();
                
                try {{
                    const successful = document.execCommand('copy');
                    if (successful) {{
                        showToast('Link copied to clipboard!', 'success');
                    }} else {{
                        showToast('Failed to copy link', 'error');
                    }}
                }} catch (err) {{
                    showToast('Failed to copy link: ' + err, 'error');
                }}
                
                document.body.removeChild(textArea);
            }}
            
            function togglePublicLink(formId) {{
                const isEnabled = document.getElementById('enablePublicLink').checked;
                const button = event.target;
                const originalText = button.nextElementSibling?.textContent || '';
                
                // Show loading state
                button.disabled = true;
                if (button.nextElementSibling) {{
                    button.nextElementSibling.textContent = ' Updating...';
                }}
                
                fetch('/api/form/' + formId + '/toggle-public-link', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{enabled: isEnabled}})
                }})
                .then(res => res.json())
                .then(data => {{
                    if (data.success) {{
                        showToast('Public link ' + (isEnabled ? 'enabled' : 'disabled') + ' successfully!', 'success');
                        setTimeout(() => window.location.reload(), 1000);
                    }} else {{
                        showToast('Error: ' + data.error, 'error');
                        document.getElementById('enablePublicLink').checked = !isEnabled;
                    }}
                    button.disabled = false;
                    if (button.nextElementSibling) {{
                        button.nextElementSibling.textContent = originalText;
                    }}
                }})
                .catch(error => {{
                    showToast('Network error: ' + error, 'error');
                    document.getElementById('enablePublicLink').checked = !isEnabled;
                    button.disabled = false;
                    if (button.nextElementSibling) {{
                        button.nextElementSibling.textContent = originalText;
                    }}
                }});
            }}
            
            function regenerateToken(formId) {{
                if (confirm('Regenerate share link?\\n\\n⚠️ Warning: This will:\\n• Invalidate the previous link\\n• Make old links show "Form Not Found"\\n• Generate a new QR code')) {{
                    fetch('/api/form/' + formId + '/regenerate-token', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}}
                    }})
                    .then(res => res.json())
                    .then(data => {{
                        if (data.success) {{
                            showToast('Share link regenerated successfully!', 'success');
                            setTimeout(() => window.location.reload(), 1000);
                        }} else {{
                            showToast('Error: ' + data.error, 'error');
                        }}
                    }});
                }}
            }}
            
            function testShareLink() {{
                const link = document.getElementById('shareLink').value;
                if (!link) {{
                    showToast('No link to test', 'warning');
                    return;
                }}
                
                if (!document.getElementById('enablePublicLink').checked) {{
                    if (!confirm('Public link is currently disabled. The test will show "Form Not Found".\\n\\nEnable it first?')) {{
                        return;
                    }}
                }}
                
                // Open in new tab
                window.open(link, '_blank');
                showToast('Opening test link in new tab...', 'info');
            }}
            
            function downloadQRCode() {{
                const qrCodeUrl = '{qr_code_url}';
                const link = document.createElement('a');
                link.href = qrCodeUrl.replace('size=200x200', 'size=400x400');
                link.download = 'form_qr_code.png';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                showToast('QR Code downloaded!', 'success');
            }}
            
            function showToast(message, type = 'info') {{
                // Create toast container if not exists
                let toastContainer = document.getElementById('toast-container');
                if (!toastContainer) {{
                    toastContainer = document.createElement('div');
                    toastContainer.id = 'toast-container';
                    toastContainer.style.position = 'fixed';
                    toastContainer.style.top = '20px';
                    toastContainer.style.right = '20px';
                    toastContainer.style.zIndex = '9999';
                    document.body.appendChild(toastContainer);
                }}
                
                // Create toast
                const toastId = 'toast-' + Date.now();
                const bgColor = type === 'success' ? 'bg-success' : type === 'error' ? 'bg-danger' : type === 'warning' ? 'bg-warning' : 'bg-info';
                const toast = document.createElement('div');
                toast.id = toastId;
                toast.className = `toast align-items-center text-white ${{bgColor}} border-0`;
                toast.setAttribute('role', 'alert');
                toast.setAttribute('aria-live', 'assertive');
                toast.setAttribute('aria-atomic', 'true');
                toast.innerHTML = `
                    <div class="d-flex">
                        <div class="toast-body">
                            ${{message}}
                        </div>
                        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
                    </div>
                `;
                
                toastContainer.appendChild(toast);
                const bsToast = new bootstrap.Toast(toast, {{delay: 3000}});
                bsToast.show();
                
                // Remove toast after hiding
                toast.addEventListener('hidden.bs.toast', function () {{
                    toast.remove();
                }});
            }}
            
            // Initialize tooltips
            document.addEventListener('DOMContentLoaded', function() {{
                var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
                var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {{
                    return new bootstrap.Tooltip(tooltipTriggerEl);
                }});
            }});
        </script>
        
        <style>
            .share-link-box {{
                background: #f8f9fa;
                border: 2px dashed #dee2e6;
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 20px;
            }}
            
            .share-actions {{
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
                margin-top: 15px;
            }}
            
            .share-actions .btn {{
                flex: 1;
                min-width: 120px;
            }}
            
            .copy-btn {{
                cursor: pointer;
                transition: all 0.3s;
            }}
            
            .copy-btn:hover {{
                transform: scale(1.05);
            }}
            
            .public-link-badge {{
                background: linear-gradient(45deg, #8b5cf6, #7c3aed);
                color: white;
                padding: 5px 15px;
                border-radius: 20px;
                font-size: 0.9rem;
                font-weight: 600;
            }}
            
            .toast {{
                min-width: 250px;
                margin-bottom: 10px;
            }}
            
            .form-check-input:checked {{
                background-color: #10b981;
                border-color: #10b981;
            }}
            
            @media (max-width: 768px) {{
                .share-actions .btn {{
                    flex: 1 0 calc(50% - 10px);
                }}
            }}
        </style>
        '''
        
        return html_wrapper('Share Form', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"Share form error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')
    
@app.route('/form/<int:form_id>/toggle-publish', methods=['POST'])
@admin_required
def toggle_form_publish(form_id):
    """Toggle form publish status (Admin/Super Admin only)"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Get form details
            cursor.execute('SELECT * FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            if not form:
                connection.close()
                return jsonify({'success': False, 'error': 'Form not found'})
            
            # Check permissions - admins/super_admins can toggle any form, teachers only their own
            if session['role'] == 'teacher':
                if form['created_by'] != session['user_id'] and form['department'] != session['department']:
                    connection.close()
                    return jsonify({'success': False, 'error': 'Access denied'})
            
            # Toggle publish status
            new_status = not form['is_published']
            
            # For student forms, ensure they're approved before publishing
            if form.get('is_student_submission'):
                if new_status and form.get('review_status') != 'approved':
                    connection.close()
                    return jsonify({'success': False, 'error': 'Student forms must be approved before publishing'})
            
            cursor.execute('UPDATE forms SET is_published = %s WHERE id = %s', (new_status, form_id))
            connection.commit()
        
        connection.close()
        
        status_text = 'published' if new_status else 'unpublished'
        
        # Create notification
        create_notification(
            user_id=session['user_id'],
            title=f'Form {status_text.title()}',
            message=f'Form "{form["title"]}" has been {status_text}.',
            type='success' if new_status else 'warning',
            link=f'/form/{form_id}/edit'
        )
        
        # Create notification for form creator if different
        if form['created_by'] != session['user_id']:
            create_notification(
                user_id=form['created_by'],
                title=f'Your Form Was {status_text.title()}',
                message=f'Your form "{form["title"]}" was {status_text} by {session["name"]}.',
                type='info',
                link=f'/form/{form_id}/edit'
            )
        
        # Send email notification
        if ENABLE_EMAIL_NOTIFICATIONS:
            # Get creator details
            connection = get_db()
            with connection.cursor() as cursor:
                cursor.execute('SELECT email, name FROM users WHERE id = %s', (form['created_by'],))
                creator = cursor.fetchone()
            connection.close()
            
            if creator:
                html_content = f'''
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: {"#10b981" if new_status else "#f59e0b"};">Form {status_text.title()}</h2>
                    <p>Hello {creator['name']},</p>
                    <p>Your form has been {status_text} by an administrator.</p>
                    <div style="background: {"#f0f9ff" if new_status else "#fefce8"}; padding: 15px; border-radius: 10px; margin: 20px 0;">
                        <p><strong>Form Details:</strong></p>
                        <p>Title: {form['title']}</p>
                        <p>Status: <strong>{status_text.upper()}</strong></p>
                        <p>Changed By: {session['name']}</p>
                        <p>Change Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    <p>{"The form is now visible to students who have access." if new_status else "The form is no longer visible to students."}</p>
                    <a href="https://formmaster.up.railway.app/form/{form_id}/edit" style="display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">View Form</a>
                    <hr>
                    <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
                </div>
                '''
                send_email(creator['email'], f'Form {status_text.title()} - FormMaster Pro', html_content)
        
        return jsonify({'success': True, 'new_status': new_status, 'status_text': status_text})
    except Exception as e:
        print(f"Toggle form publish error: {e}")
        return jsonify({'success': False, 'error': str(e)})
    

@app.route('/debug/share-tokens')
@admin_required
def debug_share_tokens():
    """Debug page to see all forms with share tokens"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT id, title, share_token, public_link_enabled, is_published, 
                       review_status, department, created_by
                FROM forms 
                ORDER BY id
            ''')
            forms = cursor.fetchall()
        connection.close()
        
        html_content = '''
        <div class="card">
            <div class="card-header">
                <h4>Debug: Form Share Tokens</h4>
            </div>
            <div class="card-body">
                <table class="table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Title</th>
                            <th>Share Token</th>
                            <th>Public Enabled</th>
                            <th>Published</th>
                            <th>Review Status</th>
                            <th>Department</th>
                            <th>Link</th>
                        </tr>
                    </thead>
                    <tbody>
        '''
        
        for form in forms:
            token = form['share_token'] or 'NO TOKEN'
            public_enabled = '✅' if form['public_link_enabled'] else '❌'
            published = '✅' if form['is_published'] else '❌'
            
            if form['share_token']:
                link = f'<a href="/public/form/{form["share_token"]}" target="_blank">Test Link</a>'
            else:
                link = 'No token'
            
            html_content += f'''
                <tr>
                    <td>{form['id']}</td>
                    <td>{form['title']}</td>
                    <td><code>{token[:20]}...</code></td>
                    <td>{public_enabled}</td>
                    <td>{published}</td>
                    <td>{form['review_status']}</td>
                    <td>{form['department']}</td>
                    <td>{link}</td>
                </tr>
            '''
        
        html_content += '''
                    </tbody>
                </table>
            </div>
        </div>
        '''
        
        return html_wrapper('Debug Share Tokens', html_content, get_navbar(), '')
        
    except Exception as e:
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')
    

@app.route('/api/form/<int:form_id>/toggle-public-link', methods=['POST'])
@teacher_required
def toggle_public_link(form_id):
    """Toggle public link enabled/disabled"""
    try:
        data = request.json
        enabled = data.get('enabled', False)
        
        connection = get_db()
        with connection.cursor() as cursor:
            # Check permissions
            cursor.execute('SELECT created_by FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            if not form:
                connection.close()
                return jsonify({'success': False, 'error': 'Form not found'})
            
            if form['created_by'] != session['user_id'] and session['role'] not in ['admin', 'super_admin']:
                connection.close()
                return jsonify({'success': False, 'error': 'Access denied'})
            
            # Update public link status
            cursor.execute('UPDATE forms SET public_link_enabled = %s WHERE id = %s', (enabled, form_id))
            connection.commit()
        
        connection.close()
        
        # Create notification
        status = 'enabled' if enabled else 'disabled'
        create_notification(
            user_id=session['user_id'],
            title='Public Link Updated',
            message=f'Public link has been {status} for the form.',
            type='info',
            link=f'/form/{form_id}/share'
        )
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Toggle public link error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/form/<int:form_id>/regenerate-token', methods=['POST'])
@teacher_required
def regenerate_token(form_id):
    """Regenerate share token"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Check permissions
            cursor.execute('SELECT created_by FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            if not form:
                connection.close()
                return jsonify({'success': False, 'error': 'Form not found'})
            
            if form['created_by'] != session['user_id'] and session['role'] not in ['admin', 'super_admin']:
                connection.close()
                return jsonify({'success': False, 'error': 'Access denied'})
            
            # Generate new token
            new_token = generate_share_token()
            cursor.execute('UPDATE forms SET share_token = %s WHERE id = %s', (new_token, form_id))
            connection.commit()
        
        connection.close()
        
        # Create notification
        create_notification(
            user_id=session['user_id'],
            title='Share Link Regenerated',
            message='Share link has been regenerated. Previous link is now invalid.',
            type='warning',
            link=f'/form/{form_id}/share'
        )
        
        return jsonify({'success': True, 'new_token': new_token})
    except Exception as e:
        print(f"Regenerate token error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/public/form/<token>')
def public_form_access(token):
    """Public form access route - redirects to login if not authenticated"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT * FROM forms WHERE share_token = %s AND public_link_enabled = TRUE
            ''', (token,))
            form = cursor.fetchone()
        
        connection.close()
        
        if not form:
            # Check if form exists but public link is disabled
            connection = get_db()
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM forms WHERE share_token = %s', (token,))
                form_exists = cursor.fetchone()
            connection.close()
            
            if form_exists:
                return html_wrapper('Form Access Disabled', '''
                <div class="alert alert-warning">
                    <h4>Form Access Disabled</h4>
                    <p>The public link for this form has been disabled by the form creator.</p>
                    <a href="/login" class="btn btn-primary">Go to Login</a>
                </div>
                ''', '', '')
            else:
                return html_wrapper('Form Not Found', '''
                <div class="alert alert-danger">
                    <h4>Form Not Found</h4>
                    <p>The requested form is not available or the link has expired.</p>
                    <p>Possible reasons:</p>
                    <ul>
                        <li>The form has been deleted</li>
                        <li>The share link has been regenerated</li>
                        <li>The link is incorrect</li>
                    </ul>
                    <a href="/login" class="btn btn-primary">Go to Login</a>
                </div>
                ''', '', '')
        
        # Check if user is logged in
        if 'user_id' not in session:
            # Store the form_id and token in session to redirect after login
            session['redirect_after_login'] = f'/public/form/{token}'
            # Also pass as query parameter for GET requests
            return redirect(f'/login?redirect=/public/form/{token}')
        
        # Check if form is published
        if not form.get('is_published'):
            return html_wrapper('Form Not Published', f'''
            <div class="alert alert-warning">
                <h4>Form Not Published</h4>
                <p>The form "{form['title']}" is not currently published.</p>
                <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
            </div>
            ''', get_navbar(), '')
        
        # Check if form is a student submission and needs review
        if form.get('is_student_submission') and form.get('review_status') != 'approved':
            status_map = {
                'pending': 'pending review',
                'rejected': 'rejected'
            }
            status = status_map.get(form.get('review_status'), 'not approved')
            return html_wrapper('Form Under Review', f'''
            <div class="alert alert-warning">
                <h4>Form Under Review</h4>
                <p>The form "{form['title']}" is currently {status}.</p>
                <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
            </div>
            ''', get_navbar(), '')
        
        # For logged-in users, check access based on role
        connection = get_db()
        with connection.cursor() as cursor:
            # Admin/super_admin can access any form
            if session['role'] in ['admin', 'super_admin']:
                connection.close()
                return redirect(f'/form/{form["id"]}/take')
            
            # Teachers can access forms from their department
            if session['role'] == 'teacher':
                if form['department'] == session['department']:
                    connection.close()
                    return redirect(f'/form/{form["id"]}/take')
                else:
                    connection.close()
                    return html_wrapper('Access Denied', f'''
                    <div class="alert alert-danger">
                        <h4>Access Denied</h4>
                        <p>You can only access forms from your department ({session['department']}).</p>
                        <p>This form belongs to the {form['department']} department.</p>
                        <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
                    </div>
                    ''', get_navbar(), '')
            
            # For students, check access
            if session['role'] == 'student':
                # Check if already submitted
                cursor.execute('''
                    SELECT 1 FROM responses WHERE form_id = %s AND student_id = %s
                ''', (form['id'], session['user_id']))
                submitted = cursor.fetchone()
                
                if submitted:
                    connection.close()
                    return html_wrapper('Already Submitted', f'''
                    <div class="alert alert-info">
                        <h4>Already Submitted</h4>
                        <p>You have already submitted this form.</p>
                        <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
                    </div>
                    ''', get_navbar(), '')
                
                # Determine access
                has_access = False
                
                # PUBLIC FORMS: Students from same department can access without request
                if form['form_type'] == 'public' and form['department'] == session['department']:
                    has_access = True
                else:
                    # For non-public forms, check request/assignment status
                    cursor.execute('''
                        SELECT fr.status as request_status
                        FROM form_requests fr
                        WHERE fr.form_id = %s AND fr.student_id = %s
                    ''', (form['id'], session['user_id']))
                    access_info = cursor.fetchone()
                    
                    # Check if assigned
                    cursor.execute('''
                        SELECT 1 FROM assignments WHERE form_id = %s AND student_id = %s
                    ''', (form['id'], session['user_id']))
                    assigned = cursor.fetchone()
                    
                    if assigned:
                        has_access = True
                    elif access_info and access_info['request_status'] == 'approved':
                        has_access = True
                    elif form['form_type'] == 'open' and form['department'] == session['department']:
                        # Open forms from same department are accessible
                        has_access = True
                
                if not has_access:
                    connection.close()
                    # Different message for public vs other forms
                    if form['form_type'] == 'public':
                        return html_wrapper('Access Denied', f'''
                        <div class="alert alert-danger">
                            <h4>Access Denied</h4>
                            <p>This is a PUBLIC form, but you cannot access it because:</p>
                            <ul>
                                <li>You are from {session['department']} department</li>
                                <li>This form is for {form['department']} department</li>
                            </ul>
                            <p><strong>Form:</strong> {form['title']}</p>
                            <div class="mt-3">
                                <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
                            </div>
                        </div>
                        ''', get_navbar(), '')
                    else:
                        return html_wrapper('Access Required', f'''
                        <div class="alert alert-danger">
                            <h4>Access Required</h4>
                            <p>You need to request access to this form.</p>
                            <p><strong>Form:</strong> {form['title']}</p>
                            <p><strong>Department:</strong> {form['department']}</p>
                            <p><strong>Type:</strong> {form['form_type'].title()}</p>
                            <div class="mt-3">
                                <button onclick="requestForm({form['id']})" class="btn btn-primary">
                                    Request Access
                                </button>
                                <a href="/dashboard" class="btn btn-secondary">Back to Dashboard</a>
                            </div>
                        </div>
                        ''', get_navbar(), f'''
                        <script>
                            function requestForm(formId) {{
                                fetch('/request-form/' + formId, {{
                                    method: 'POST',
                                    headers: {{'Content-Type': 'application/json'}}
                                }})
                                .then(res => res.json())
                                .then(data => {{
                                    if (data.success) {{
                                        alert('Request submitted successfully!');
                                        window.location.reload();
                                    }} else {{
                                        alert('Error: ' + data.error);
                                    }}
                                }});
                            }}
                        </script>
                        ''')
        
        connection.close()
        
        # Redirect to take form
        return redirect(f'/form/{form["id"]}/take')
        
    except Exception as e:
        print(f"Public form access error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', '', '')
        
@app.route('/notifications')
@login_required
def notifications_page():
    """Notification center page"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Get all notifications for user
            cursor.execute('''
                SELECT * FROM notifications 
                WHERE user_id = %s 
                ORDER BY created_at DESC
            ''', (session['user_id'],))
            notifications = cursor.fetchall()
            
            # Count statistics
            cursor.execute('''
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN is_read = FALSE THEN 1 ELSE 0 END) as unread,
                    SUM(CASE WHEN type = 'success' THEN 1 ELSE 0 END) as success,
                    SUM(CASE WHEN type = 'warning' THEN 1 ELSE 0 END) as warning,
                    SUM(CASE WHEN type = 'danger' THEN 1 ELSE 0 END) as danger
                FROM notifications 
                WHERE user_id = %s
            ''', (session['user_id'],))
            stats = cursor.fetchone()
        
        connection.close()
        
        # Mark all as read when visiting the page
        mark_all_notifications_as_read(session['user_id'])
        
        notifications_html = ''
        if notifications:
            for notif in notifications:
                type_icon = {
                    'info': 'fa-info-circle text-primary',
                    'success': 'fa-check-circle text-success',
                    'warning': 'fa-exclamation-triangle text-warning',
                    'danger': 'fa-times-circle text-danger'
                }.get(notif['type'], 'fa-info-circle')
                
                read_class = '' if notif['is_read'] else 'fw-bold'
                
                link_attr = ''
                if notif['link']:
                    link_attr = f'onclick="window.location.href=\'{notif["link"]}\'" style="cursor: pointer;"'
                
                time_ago = get_time_ago(notif['created_at'])
                
                notifications_html += f'''
                <div class="card mb-2 {read_class}" {link_attr}>
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <h6 class="mb-1">
                                    <i class="fas {type_icon} me-2"></i>
                                    {notif['title']}
                                </h6>
                                <p class="mb-1">{notif['message']}</p>
                                <small class="text-muted">{time_ago}</small>
                            </div>
                            <div>
                                <button onclick="deleteNotification({notif['id']})" class="btn btn-sm btn-outline-danger">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
                '''
        else:
            notifications_html = '''
            <div class="text-center py-5">
                <i class="fas fa-bell-slash fa-3x text-muted mb-3"></i>
                <h4>No notifications yet</h4>
                <p class="text-muted">You don't have any notifications at the moment.</p>
            </div>
            '''
        
        content = f'''
        <div class="mb-4">
            <div class="d-flex justify-content-between align-items-center">
                <h2 class="text-white">Notifications</h2>
                <div>
                    <button onclick="markAllAsRead()" class="btn btn-outline-primary me-2">
                        <i class="fas fa-check-double me-2"></i>Mark All as Read
                    </button>
                    <button onclick="clearAllNotifications()" class="btn btn-outline-danger">
                        <i class="fas fa-trash me-2"></i>Clear All
                    </button>
                </div>
            </div>
        </div>
        
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="stat-card" style="background: linear-gradient(45deg, #667eea, #764ba2);">
                    <h5>Total</h5>
                    <h2>{stats['total'] or 0}</h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card" style="background: linear-gradient(45deg, #ef4444, #dc2626);">
                    <h5>Unread</h5>
                    <h2>{stats['unread'] or 0}</h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card" style="background: linear-gradient(45deg, #10b981, #059669);">
                    <h5>Success</h5>
                    <h2>{stats['success'] or 0}</h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card" style="background: linear-gradient(45deg, #f59e0b, #d97706);">
                    <h5>Warnings</h5>
                    <h2>{stats['warning'] or 0}</h2>
                </div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">All Notifications ({stats['total'] or 0})</h5>
            </div>
            <div class="card-body">
                {notifications_html}
            </div>
        </div>
        '''
        
        scripts = '''
        <script>
            function markAllAsRead() {
                fetch('/api/notifications/mark-all-read', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'}
                })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        alert('All notifications marked as read!');
                        window.location.reload();
                    } else {
                        alert('Error: ' + data.error);
                    }
                });
            }
            
            function deleteNotification(notificationId) {
                if (confirm('Delete this notification?')) {
                    fetch('/api/notifications/' + notificationId + '/delete', {
                        method: 'DELETE'
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            alert('Notification deleted!');
                            window.location.reload();
                        } else {
                            alert('Error: ' + data.error);
                        }
                    });
                }
            }
            
            function clearAllNotifications() {
                if (confirm('Clear all notifications? This action cannot be undone.')) {
                    fetch('/api/notifications/clear-all', {
                        method: 'DELETE'
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            alert('All notifications cleared!');
                            window.location.reload();
                        } else {
                            alert('Error: ' + data.error);
                        }
                    });
                }
            }
        </script>
        '''
        
        return html_wrapper('Notifications', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"Notifications page error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/api/notifications/recent')
@login_required
def get_recent_notifications():
    """Get recent notifications for the navbar dropdown"""
    try:
        notifications = get_user_notifications(session['user_id'], limit=5)
        
        notifications_html = ''
        if notifications:
            for notif in notifications:
                type_icon = {
                    'info': 'fa-info-circle text-primary',
                    'success': 'fa-check-circle text-success',
                    'warning': 'fa-exclamation-triangle text-warning',
                    'danger': 'fa-times-circle text-danger'
                }.get(notif['type'], 'fa-info-circle')
                
                read_class = 'text-muted' if notif['is_read'] else 'fw-bold'
                time_ago = get_time_ago(notif['created_at'])
                
                onclick = ''
                if notif['link']:
                    onclick = f'onclick="window.location.href=\'{notif["link"]}\'; markAsRead({notif["id"]})"'
                
                notifications_html += f'''
                <li>
                    <div class="dropdown-item {read_class}" {onclick} style="cursor: pointer; white-space: normal;">
                        <div class="d-flex">
                            <div class="flex-shrink-0">
                                <i class="fas {type_icon} mt-1"></i>
                            </div>
                            <div class="flex-grow-1 ms-3">
                                <div class="small">{notif['title']}</div>
                                <div class="text-muted">{notif['message'][:50]}...</div>
                                <div class="text-muted"><small>{time_ago}</small></div>
                            </div>
                        </div>
                    </div>
                </li>
                '''
        else:
            notifications_html = '''
            <li class="text-center py-3">
                <i class="fas fa-bell-slash fa-lg text-muted mb-2"></i>
                <p class="text-muted mb-0">No notifications</p>
            </li>
            '''
        
        return jsonify({
            'success': True,
            'html': notifications_html,
            'unread_count': get_unread_notification_count(session['user_id'])
        })
    except Exception as e:
        print(f"Error getting recent notifications: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark a notification as read"""
    try:
        success = mark_notification_as_read(notification_id, session['user_id'])
        return jsonify({'success': success})
    except Exception as e:
        print(f"Error marking notification as read: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_read():
    """Mark all notifications as read"""
    try:
        success = mark_all_notifications_as_read(session['user_id'])
        return jsonify({'success': success})
    except Exception as e:
        print(f"Error marking all notifications as read: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/notifications/clear-all', methods=['DELETE'])
@login_required
def clear_all_notifications():
    """Clear all notifications for the user"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('DELETE FROM notifications WHERE user_id = %s', (session['user_id'],))
            connection.commit()
        connection.close()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error clearing all notifications: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/student-details/<int:student_id>')
@teacher_required
def get_student_details(student_id):
    """Get detailed student information for teacher analytics"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Get student basic info
            cursor.execute('''
                SELECT u.name, u.email, u.department, u.created_at as joined_date
                FROM users u
                WHERE u.id = %s AND u.role = 'student'
            ''', (student_id,))
            student = cursor.fetchone()
            
            if not student:
                connection.close()
                return jsonify({'success': False, 'error': 'Student not found'})
            
            # Get student form responses
            cursor.execute('''
                SELECT r.*, f.title, f.created_by as teacher_id, u2.name as teacher_name
                FROM responses r
                JOIN forms f ON r.form_id = f.id
                LEFT JOIN users u2 ON f.created_by = u2.id
                WHERE r.student_id = %s
                ORDER BY r.submitted_at DESC
            ''', (student_id,))
            responses = cursor.fetchall()
            
            # Get assigned forms
            cursor.execute('''
                SELECT a.*, f.title, f.department, u.name as assigned_by_name
                FROM assignments a
                JOIN forms f ON a.form_id = f.id
                JOIN users u ON a.assigned_by = u.id
                WHERE a.student_id = %s
                ORDER BY a.assigned_at DESC
            ''', (student_id,))
            assignments = cursor.fetchall()
            
            # Get form requests
            cursor.execute('''
                SELECT fr.*, f.title, f.department, u.name as reviewer_name
                FROM form_requests fr
                JOIN forms f ON fr.form_id = f.id
                LEFT JOIN users u ON fr.approved_by = u.id
                WHERE fr.student_id = %s
                ORDER BY fr.requested_at DESC
            ''', (student_id,))
            requests = cursor.fetchall()
            
            # Calculate statistics
            total_forms = len(responses)
            avg_score = sum([r['percentage'] for r in responses]) / total_forms if total_forms > 0 else 0
            passed_forms = len([r for r in responses if r['percentage'] >= 70])
            failed_forms = total_forms - passed_forms
        
        connection.close()
        
        # Prepare response data
        stats = {
            'total_forms': total_forms,
            'avg_score': round(avg_score, 1),
            'passed_forms': passed_forms,
            'failed_forms': failed_forms,
            'completion_rate': round((len([a for a in assignments if a['is_completed']]) / len(assignments) * 100), 1) if assignments else 0
        }
        
        # Generate HTML content for modal
        html_content = f'''
        <div class="container-fluid">
            <div class="row mb-4">
                <div class="col-md-12">
                    <h4>Student Details: {student['name']}</h4>
                    <p class="text-muted">
                        <i class="fas fa-envelope me-2"></i>{student['email']} |
                        <i class="fas fa-building me-2"></i>{student['department']} |
                        <i class="fas fa-calendar me-2"></i>Joined: {student['joined_date'].strftime('%Y-%m-%d')}
                    </p>
                </div>
            </div>
            
            <div class="row mb-4">
                <div class="col-md-3">
                    <div class="card bg-primary text-white">
                        <div class="card-body text-center">
                            <h6>Forms Taken</h6>
                            <h3>{stats['total_forms']}</h3>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card bg-success text-white">
                        <div class="card-body text-center">
                            <h6>Average Score</h6>
                            <h3>{stats['avg_score']}%</h3>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card bg-info text-white">
                        <div class="card-body text-center">
                            <h6>Pass Rate</h6>
                            <h3>{round((stats['passed_forms']/stats['total_forms']*100), 1) if stats['total_forms'] > 0 else 0}%</h3>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card bg-warning text-white">
                        <div class="card-body text-center">
                            <h6>Completion Rate</h6>
                            <h3>{stats['completion_rate']}%</h3>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h6 class="mb-0">Recent Form Responses ({len(responses)})</h6>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Form</th>
                                            <th>Score</th>
                                            <th>Status</th>
                                            <th>Date</th>
                                        </tr>
                                    </thead>
                                    <tbody>
        '''
        
        for response in responses[:5]:  # Show only 5 most recent
            score_class = 'success' if response['percentage'] >= 70 else 'warning' if response['percentage'] >= 50 else 'danger'
            html_content += f'''
                                        <tr>
                                            <td>{response['title']}</td>
                                            <td><span class="badge bg-{score_class}">{response['score']}/{response['total_marks']}</span></td>
                                            <td>{response['percentage']}%</td>
                                            <td>{response['submitted_at'].strftime('%Y-%m-%d')}</td>
                                        </tr>
            '''
        
        view_all_responses_link = f'<p class="text-center"><a href="#" onclick="viewAllResponses({student_id})">View All Responses</a></p>' if len(responses) > 5 else ''
        
        html_content += f'''
                                    </tbody>
                                </table>
                            </div>
                            {view_all_responses_link}
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h6 class="mb-0">Current Assignments ({len(assignments)})</h6>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Form</th>
                                            <th>Status</th>
                                            <th>Assigned By</th>
                                            <th>Due Date</th>
                                        </tr>
                                    </thead>
                                    <tbody>
        '''
        
        for assignment in assignments[:5]:  # Show only 5 most recent
            status_badge = 'success' if assignment['is_completed'] else 'warning'
            status_text = 'Completed' if assignment['is_completed'] else 'Pending'
            due_date = assignment['due_date'].strftime('%Y-%m-%d') if assignment['due_date'] else 'No due date'
            
            html_content += f'''
                                        <tr>
                                            <td>{assignment['title']}</td>
                                            <td><span class="badge bg-{status_badge}">{status_text}</span></td>
                                            <td>{assignment['assigned_by_name']}</td>
                                            <td>{due_date}</td>
                                        </tr>
            '''
        
        view_all_assignments_link = f'<p class="text-center"><a href="#" onclick="viewAllAssignments({student_id})">View All Assignments</a></p>' if len(assignments) > 5 else ''
        
        html_content += f'''
                                    </tbody>
                                </table>
                            </div>
                            {view_all_assignments_link}
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="row mt-3">
                <div class="col-md-12">
                    <div class="card">
                        <div class="card-header">
                            <h6 class="mb-0">Form Access Requests ({len(requests)})</h6>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Form</th>
                                            <th>Department</th>
                                            <th>Status</th>
                                            <th>Requested</th>
                                            <th>Reviewed By</th>
                                        </tr>
                                    </thead>
                                    <tbody>
        '''
        
        for request in requests[:5]:  # Show only 5 most recent
            status_badge = 'success' if request['status'] == 'approved' else 'danger' if request['status'] == 'rejected' else 'warning'
            reviewed_by = request['reviewer_name'] or 'Pending'
            
            html_content += f'''
                                        <tr>
                                            <td>{request['title']}</td>
                                            <td>{request['department']}</td>
                                            <td><span class="badge bg-{status_badge}">{request['status'].title()}</span></td>
                                            <td>{request['requested_at'].strftime('%Y-%m-%d')}</td>
                                            <td>{reviewed_by}</td>
                                        </tr>
            '''
        
        view_all_requests_link = f'<p class="text-center"><a href="#" onclick="viewAllRequests({student_id})">View All Requests</a></p>' if len(requests) > 5 else ''
        
        html_content += f'''
                                    </tbody>
                                </table>
                            </div>
                            {view_all_requests_link}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            function viewAllResponses(studentId) {{
                // Implement view all responses functionality
                alert('View all responses for student ' + studentId);
            }}
            
            function viewAllAssignments(studentId) {{
                // Implement view all assignments functionality
                alert('View all assignments for student ' + studentId);
            }}
            
            function viewAllRequests(studentId) {{
                // Implement view all requests functionality
                alert('View all requests for student ' + studentId);
            }}
        </script>
        '''
        
        return jsonify({
            'success': True,
            'html': html_content,
            'stats': stats
        })
        
    except Exception as e:
        print(f"Error getting student details: {e}")
        return jsonify({'success': False, 'error': str(e)})
    

@app.route('/admin')
@admin_required
def admin_panel():
    """Admin panel for system management"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            # Get system statistics
            cursor.execute('''
                SELECT 
                    COUNT(DISTINCT id) as total_users,
                    SUM(CASE WHEN role = 'student' THEN 1 ELSE 0 END) as total_students,
                    SUM(CASE WHEN role = 'teacher' THEN 1 ELSE 0 END) as total_teachers,
                    SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as total_admins,
                    SUM(CASE WHEN role = 'super_admin' THEN 1 ELSE 0 END) as total_super_admins
                FROM users
            ''')
            user_stats = cursor.fetchone()
            
            cursor.execute('''
                SELECT 
                    COUNT(DISTINCT id) as total_forms,
                    SUM(CASE WHEN is_student_submission = TRUE THEN 1 ELSE 0 END) as student_forms,
                    SUM(CASE WHEN review_status = 'approved' THEN 1 ELSE 0 END) as approved_forms,
                    SUM(CASE WHEN review_status = 'pending' THEN 1 ELSE 0 END) as pending_forms,
                    SUM(CASE WHEN review_status = 'rejected' THEN 1 ELSE 0 END) as rejected_forms,
                    SUM(CASE WHEN form_type = 'open' THEN 1 ELSE 0 END) as open_forms,
                    SUM(CASE WHEN form_type = 'confidential' THEN 1 ELSE 0 END) as confidential_forms
                FROM forms
            ''')
            form_stats = cursor.fetchone()
            
            cursor.execute('''
                SELECT 
                    COUNT(DISTINCT id) as total_responses,
                    AVG(percentage) as avg_score,
                    MAX(percentage) as highest_score,
                    MIN(percentage) as lowest_score,
                    SUM(CASE WHEN percentage >= 70 THEN 1 ELSE 0 END) as passed_responses,
                    SUM(CASE WHEN percentage < 70 THEN 1 ELSE 0 END) as failed_responses
                FROM responses
            ''')
            response_stats = cursor.fetchone()
            
            cursor.execute('''
                SELECT 
                    COUNT(DISTINCT id) as total_assignments,
                    SUM(CASE WHEN is_completed = TRUE THEN 1 ELSE 0 END) as completed_assignments,
                    SUM(CASE WHEN is_completed = FALSE THEN 1 ELSE 0 END) as pending_assignments
                FROM assignments
            ''')
            assignment_stats = cursor.fetchone()
            
            cursor.execute('''
                SELECT 
                    COUNT(DISTINCT id) as total_requests,
                    SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved_requests,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_requests,
                    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_requests
                FROM form_requests
            ''')
            request_stats = cursor.fetchone()
            
            # Get department-wise statistics
            cursor.execute('''
                SELECT 
                    department,
                    COUNT(DISTINCT id) as user_count,
                    SUM(CASE WHEN role = 'student' THEN 1 ELSE 0 END) as students,
                    SUM(CASE WHEN role = 'teacher' THEN 1 ELSE 0 END) as teachers
                FROM users
                WHERE role IN ('student', 'teacher')
                GROUP BY department
                ORDER BY department
            ''')
            dept_stats = cursor.fetchall()
            
            # Get recent activities
            cursor.execute('''
                (SELECT 
                    'form_created' as type,
                    f.title as description,
                    u.name as user_name,
                    f.created_at as timestamp,
                    CONCAT('/form/', f.id, '/edit') as link
                FROM forms f
                JOIN users u ON f.created_by = u.id
                ORDER BY f.created_at DESC
                LIMIT 5)
                
                UNION ALL
                
                (SELECT 
                    'response_submitted' as type,
                    CONCAT('Submitted form: ', f.title) as description,
                    u.name as user_name,
                    r.submitted_at as timestamp,
                    CONCAT('/form/', f.id, '/responses') as link
                FROM responses r
                JOIN forms f ON r.form_id = f.id
                JOIN users u ON r.student_id = u.id
                ORDER BY r.submitted_at DESC
                LIMIT 5)
                
                UNION ALL
                
                (SELECT 
                    'user_registered' as type,
                    CONCAT('New ', role, ' registered') as description,
                    name as user_name,
                    created_at as timestamp,
                    '#' as link
                FROM users
                ORDER BY created_at DESC
                LIMIT 5)
                
                ORDER BY timestamp DESC
                LIMIT 10
            ''')
            recent_activities = cursor.fetchall()
            
            # Get system information
            cursor.execute('SELECT VERSION() as mysql_version')
            mysql_version = cursor.fetchone()['mysql_version']
            
        connection.close()
        
        # Format Decimal values
        def format_decimal(value):
            return round(float(value), 2) if value else 0
        
        # Department statistics HTML
        dept_stats_html = ''
        for dept in dept_stats:
            dept_stats_html += f'''
            <tr>
                <td>{dept['department']}</td>
                <td>{dept['user_count']}</td>
                <td>{dept['students']}</td>
                <td>{dept['teachers']}</td>
                <td>
                    <a href="/dashboard?department={dept['department']}" class="btn btn-sm btn-outline-primary">
                        View Forms
                    </a>
                </td>
            </tr>
            '''
        
        # Recent activities HTML
        recent_activities_html = ''
        for activity in recent_activities:
            icon = {
                'form_created': 'fa-file-alt text-primary',
                'response_submitted': 'fa-paper-plane text-success',
                'user_registered': 'fa-user-plus text-info'
            }.get(activity['type'], 'fa-info-circle')
            
            time_ago = get_time_ago(activity['timestamp'])
            link = 'javascript:void(0)' if activity['link'] == '#' else activity['link']
            
            recent_activities_html += f'''
            <div class="d-flex mb-3">
                <div class="flex-shrink-0">
                    <i class="fas {icon} fa-2x"></i>
                </div>
                <div class="flex-grow-1 ms-3">
                    <h6 class="mb-1">{activity['description']}</h6>
                    <p class="mb-0 text-muted">By {activity['user_name']}</p>
                    <small class="text-muted">{time_ago}</small>
                    {f'<a href="{link}" class="btn btn-sm btn-outline-primary mt-1">View</a>' if activity['link'] != '#' else ''}
                </div>
            </div>
            '''
        
        content = f'''
        <div class="mb-4">
            <h2 class="text-white">Admin Panel</h2>
            <p class="text-white-50">System Administration and Monitoring</p>
        </div>
        
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="stat-card" style="background: linear-gradient(45deg, #667eea, #764ba2);">
                    <h5>Total Users</h5>
                    <h2>{user_stats['total_users'] or 0}</h2>
                    <small>Students: {user_stats['total_students'] or 0}</small><br>
                    <small>Teachers: {user_stats['total_teachers'] or 0}</small><br>
                    <small>Admins: {user_stats['total_admins'] or 0}</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card" style="background: linear-gradient(45deg, #10b981, #059669);">
                    <h5>Total Forms</h5>
                    <h2>{form_stats['total_forms'] or 0}</h2>
                    <small>Student Forms: {form_stats['student_forms'] or 0}</small><br>
                    <small>Open: {form_stats['open_forms'] or 0}</small><br>
                    <small>Confidential: {form_stats['confidential_forms'] or 0}</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card" style="background: linear-gradient(45deg, #3b82f6, #1d4ed8);">
                    <h5>Total Responses</h5>
                    <h2>{response_stats['total_responses'] or 0}</h2>
                    <small>Avg Score: {format_decimal(response_stats['avg_score'])}%</small><br>
                    <small>Passed: {response_stats['passed_responses'] or 0}</small><br>
                    <small>Failed: {response_stats['failed_responses'] or 0}</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card" style="background: linear-gradient(45deg, #8b5cf6, #7c3aed);">
                    <h5>System Status</h5>
                    <h2><i class="fas fa-check-circle"></i> Active</h2>
                    <small>MySQL: {mysql_version}</small><br>
                    <small>Emails: {'Enabled' if ENABLE_EMAIL_NOTIFICATIONS else 'Disabled'}</small><br>
                    <small>Forms Pending: {form_stats['pending_forms'] or 0}</small>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Department Statistics</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>Department</th>
                                        <th>Total Users</th>
                                        <th>Students</th>
                                        <th>Teachers</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {dept_stats_html}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Recent Activities</h5>
                    </div>
                    <div class="card-body">
                        {recent_activities_html}
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mt-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Quick Actions</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-3 mb-3">
                                <a href="/admin/test" class="btn btn-outline-primary w-100">
                                    <i class="fas fa-vial me-2"></i>System Test
                                </a>
                            </div>
                            <div class="col-md-3 mb-3">
                                <a href="/review-forms" class="btn btn-outline-warning w-100">
                                    <i class="fas fa-check-circle me-2"></i>Review Forms
                                    {f'<span class="badge bg-danger ms-2">{form_stats["pending_forms"] or 0}</span>' if form_stats['pending_forms'] else ''}
                                </a>
                            </div>
                            <div class="col-md-3 mb-3">
                                <a href="/form-requests" class="btn btn-outline-info w-100">
                                    <i class="fas fa-clock me-2"></i>Pending Requests
                                    {f'<span class="badge bg-danger ms-2">{request_stats["pending_requests"] or 0}</span>' if request_stats['pending_requests'] else ''}
                                </a>
                            </div>
                            <div class="col-md-3 mb-3">
                                <button onclick="exportSystemData()" class="btn btn-outline-success w-100">
                                    <i class="fas fa-download me-2"></i>Export Data
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        scripts = '''
        <script>
            function exportSystemData() {
                if (confirm('Export all system data as CSV?')) {
                    fetch('/admin/export-data')
                        .then(res => res.json())
                        .then(data => {
                            if (data.success) {
                                alert('Data exported successfully!');
                                // Trigger download
                                const link = document.createElement('a');
                                link.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(data.csv);
                                link.download = 'system_data_export.csv';
                                link.click();
                            } else {
                                alert('Error: ' + data.error);
                            }
                        });
                }
            }
        </script>
        '''
        
        return html_wrapper('Admin Panel', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"Admin panel error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/admin/test')
@admin_required
def admin_test():
    """Admin system test page"""
    try:
        test_results = []
        
        # Test 1: Database Connection
        try:
            connection = get_db()
            with connection.cursor() as cursor:
                cursor.execute('SELECT 1 as test')
                result = cursor.fetchone()
            connection.close()
            test_results.append({
                'name': 'Database Connection',
                'status': 'success' if result and result['test'] == 1 else 'failed',
                'message': 'Database connection successful' if result and result['test'] == 1 else 'Database connection failed'
            })
        except Exception as e:
            test_results.append({
                'name': 'Database Connection',
                'status': 'failed',
                'message': f'Error: {str(e)}'
            })
        
        # Test 2: Email Configuration
        try:
            if ENABLE_EMAIL_NOTIFICATIONS:
                test_results.append({
                    'name': 'Email Configuration',
                    'status': 'success',
                    'message': f'Email notifications enabled using {EMAIL_HOST}:{EMAIL_PORT}'
                })
            else:
                test_results.append({
                    'name': 'Email Configuration',
                    'status': 'warning',
                    'message': 'Email notifications are disabled'
                })
        except Exception as e:
            test_results.append({
                'name': 'Email Configuration',
                'status': 'failed',
                'message': f'Error: {str(e)}'
            })
        
        # Test 3: Table Counts
        try:
            connection = get_db()
            with connection.cursor() as cursor:
                tables = ['users', 'forms', 'responses', 'assignments', 'form_requests', 'notifications', 'student_form_reviews']
                for table in tables:
                    cursor.execute(f'SELECT COUNT(*) as count FROM {table}')
                    result = cursor.fetchone()
                    test_results.append({
                        'name': f'{table.capitalize()} Table',
                        'status': 'success',
                        'message': f'{result["count"]} records found'
                    })
            connection.close()
        except Exception as e:
            test_results.append({
                'name': 'Table Counts',
                'status': 'failed',
                'message': f'Error: {str(e)}'
            })
        
        # Test 4: File Permissions
        try:
            import os
            files_to_check = [__file__]
            for file in files_to_check:
                if os.path.exists(file):
                    test_results.append({
                        'name': f'File Access: {os.path.basename(file)}',
                        'status': 'success',
                        'message': 'File accessible'
                    })
                else:
                    test_results.append({
                        'name': f'File Access: {os.path.basename(file)}',
                        'status': 'failed',
                        'message': 'File not found'
                    })
        except Exception as e:
            test_results.append({
                'name': 'File Permissions',
                'status': 'failed',
                'message': f'Error: {str(e)}'
            })
        
        # Test 5: Session Management
        try:
            if 'user_id' in session:
                test_results.append({
                    'name': 'Session Management',
                    'status': 'success',
                    'message': f'Session active for user: {session.get("name")}'
                })
            else:
                test_results.append({
                    'name': 'Session Management',
                    'status': 'failed',
                    'message': 'No active session'
                })
        except Exception as e:
            test_results.append({
                'name': 'Session Management',
                'status': 'failed',
                'message': f'Error: {str(e)}'
            })
        
        # Test 6: Configuration Values
        try:
            config_tests = [
                ('MYSQL_HOST', MYSQL_HOST),
                ('MYSQL_DB', MYSQL_DB),
                ('EMAIL_HOST', EMAIL_HOST),
                ('ENABLE_EMAIL_NOTIFICATIONS', ENABLE_EMAIL_NOTIFICATIONS)
            ]
            
            for config_name, config_value in config_tests:
                test_results.append({
                    'name': f'Config: {config_name}',
                    'status': 'success' if config_value else 'warning',
                    'message': f'Value: {config_value}'
                })
        except Exception as e:
            test_results.append({
                'name': 'Configuration',
                'status': 'failed',
                'message': f'Error: {str(e)}'
            })
        
        # Import necessary modules for system info
        import sys
        import flask
        
        # Generate test results HTML
        results_html = ''
        for test in test_results:
            badge_color = {
                'success': 'success',
                'failed': 'danger',
                'warning': 'warning'
            }.get(test['status'], 'secondary')
            
            icon = {
                'success': 'fa-check-circle',
                'failed': 'fa-times-circle',
                'warning': 'fa-exclamation-triangle'
            }.get(test['status'], 'fa-question-circle')
            
            results_html += f'''
            <div class="card mb-2">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h6 class="mb-1">
                                <i class="fas {icon} me-2 text-{badge_color}"></i>
                                {test['name']}
                            </h6>
                            <p class="mb-0 text-muted">{test['message']}</p>
                        </div>
                        <span class="badge bg-{badge_color}">{test['status'].upper()}</span>
                    </div>
                </div>
            </div>
            '''
        
        # Calculate statistics
        total_tests = len(test_results)
        passed_tests = len([t for t in test_results if t['status'] == 'success'])
        failed_tests = len([t for t in test_results if t['status'] == 'failed'])
        warning_tests = len([t for t in test_results if t['status'] == 'warning'])
        
        content = f'''
        <div class="mb-4">
            <h2 class="text-white">System Test</h2>
            <p class="text-white-50">Diagnostic tests for system components</p>
        </div>
        
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="stat-card" style="background: linear-gradient(45deg, #10b981, #059669);">
                    <h5>Tests Passed</h5>
                    <h2>{passed_tests}/{total_tests}</h2>
                    <small>{round((passed_tests/total_tests)*100, 1)}% success rate</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card" style="background: linear-gradient(45deg, #ef4444, #dc2626);">
                    <h5>Tests Failed</h5>
                    <h2>{failed_tests}</h2>
                    <small>{round((failed_tests/total_tests)*100, 1)}% failure rate</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card" style="background: linear-gradient(45deg, #f59e0b, #d97706);">
                    <h5>Warnings</h5>
                    <h2>{warning_tests}</h2>
                    <small>Requires attention</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card" style="background: linear-gradient(45deg, #3b82f6, #1d4ed8);">
                    <h5>System Status</h5>
                    <h2>{'HEALTHY' if failed_tests == 0 else 'ISSUES'}</h2>
                    <small>{'All systems operational' if failed_tests == 0 else 'Some tests failed'}</small>
                </div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <div class="d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">Test Results ({total_tests} tests)</h5>
                    <div>
                        <button onclick="runTests()" class="btn btn-primary">
                            <i class="fas fa-sync-alt me-2"></i>Run Tests Again
                        </button>
                        <button onclick="exportTestResults()" class="btn btn-success">
                            <i class="fas fa-download me-2"></i>Export Results
                        </button>
                    </div>
                </div>
            </div>
            <div class="card-body">
                {results_html}
            </div>
        </div>
        
        <div class="card mt-4">
            <div class="card-header">
                <h5 class="mb-0">System Information</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <table class="table table-sm">
                            <tbody>
                                <tr>
                                    <th>Python Version</th>
                                    <td>{sys.version.split()[0]}</td>
                                </tr>
                                <tr>
                                    <th>Flask Version</th>
                                    <td>{flask.__version__}</td>
                                </tr>
                                <tr>
                                    <th>PyMySQL Version</th>
                                    <td>{pymysql.__version__}</td>
                                </tr>
                                <tr>
                                    <th>App Version</th>
                                    <td>1.0.0</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <table class="table table-sm">
                            <tbody>
                                <tr>
                                    <th>Database Host</th>
                                    <td>{MYSQL_HOST}</td>
                                </tr>
                                <tr>
                                    <th>Database Name</th>
                                    <td>{MYSQL_DB}</td>
                                </tr>
                                <tr>
                                    <th>Email Host</th>
                                    <td>{EMAIL_HOST}</td>
                                </tr>
                                <tr>
                                    <th>Email Notifications</th>
                                    <td>{'Enabled' if ENABLE_EMAIL_NOTIFICATIONS else 'Disabled'}</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        scripts = '''
        <script>
            function runTests() {
                if (confirm('Run system tests again?')) {
                    window.location.reload();
                }
            }
            
            function exportTestResults() {
                // Create CSV content
                let csvContent = "Test Name,Status,Message\\n";
                
                // Get all test results from the page
                document.querySelectorAll('.card.mb-2').forEach(card => {
                    const name = card.querySelector('h6').textContent.trim();
                    const status = card.querySelector('.badge').textContent.trim();
                    const message = card.querySelector('.text-muted').textContent.trim();
                    
                    csvContent += `"${name}","${status}","${message}"\\n`;
                });
                
                // Create download link
                const encodedUri = encodeURI(csvContent);
                const link = document.createElement("a");
                link.setAttribute("href", encodedUri);
                link.setAttribute("download", "system_test_results.csv");
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }
        </script>
        '''
        
        return html_wrapper('System Test', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"Admin test error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/admin/export-data')
@admin_required
def export_system_data():
    """Export system data as CSV"""
    try:
        connection = get_db()
        
        # Collect data from all tables
        data_sections = []
        
        # Users data
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT id, name, email, role, department, created_at
                FROM users
                ORDER BY created_at DESC
            ''')
            users = cursor.fetchall()
            
            users_csv = "Users Export\n"
            users_csv += "ID,Name,Email,Role,Department,Created At\n"
            for user in users:
                users_csv += f'{user["id"]},{user["name"]},{user["email"]},{user["role"]},{user["department"]},{user["created_at"]}\n'
            
            data_sections.append(users_csv)
        
        # Forms data
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT f.id, f.title, f.description, u.name as creator, f.department, 
                       f.form_type, f.is_published, f.review_status, f.created_at
                FROM forms f
                JOIN users u ON f.created_by = u.id
                ORDER BY f.created_at DESC
            ''')
            forms = cursor.fetchall()
            
            forms_csv = "\n\nForms Export\n"
            forms_csv += "ID,Title,Description,Creator,Department,Type,Published,Review Status,Created At\n"
            for form in forms:
                forms_csv += f'{form["id"]},"{form["title"]}","{form["description"]}",{form["creator"]},{form["department"]},{form["form_type"]},{form["is_published"]},{form["review_status"]},{form["created_at"]}\n'
            
            data_sections.append(forms_csv)
        
        # Responses data
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT r.id, f.title as form_title, u.name as student_name, 
                       r.score, r.total_marks, r.percentage, r.submitted_at
                FROM responses r
                JOIN forms f ON r.form_id = f.id
                JOIN users u ON r.student_id = u.id
                ORDER BY r.submitted_at DESC
            ''')
            responses = cursor.fetchall()
            
            responses_csv = "\n\nResponses Export\n"
            responses_csv += "ID,Form,Student,Score,Total Marks,Percentage,Submitted At\n"
            for response in responses:
                responses_csv += f'{response["id"]},{response["form_title"]},{response["student_name"]},{response["score"]},{response["total_marks"]},{response["percentage"]},{response["submitted_at"]}\n'
            
            data_sections.append(responses_csv)
        
        connection.close()
        
        # Combine all CSV data
        full_csv = "\n".join(data_sections)
        
        return jsonify({
            'success': True,
            'csv': full_csv,
            'filename': f'system_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        })
        
    except Exception as e:
        print(f"Export data error: {e}")
        return jsonify({'success': False, 'error': str(e)})

# Update logout route
@app.route('/logout')
def logout():
    """Fast logout - no delays"""
    # Save user info before clearing session
    user_email = session.get('email')
    user_name = session.get('name')
    user_id = session.get('user_id')
    
    # Clear session IMMEDIATELY
    session.clear()
    
    # Background tasks (don't wait for these)
    if user_id:
        # Background notification
        def bg_notification():
            try:
                conn = get_db()
                with conn.cursor() as cursor:
                    cursor.execute('''
                        INSERT INTO notifications (user_id, title, message, type) 
                        VALUES (%s, %s, %s, %s)
                    ''', (user_id, 'Logged Out', 'You have been logged out of the system.', 'info'))
                    conn.commit()
                conn.close()
            except Exception as e:
                print(f"Background notification error: {e}")
        
        # Background email
        def bg_email():
            if ENABLE_EMAIL_NOTIFICATIONS and user_email and user_name:
                try:
                    html_content = f'''
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #667eea;">Logout Alert</h2>
                        <p>Hello {user_name},</p>
                        <p>You have been logged out of FormMaster Pro.</p>
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 20px 0;">
                            <p><strong>Logout Details:</strong></p>
                            <p>User: {user_name}</p>
                            <p>Email: {user_email}</p>
                            <p>Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        </div>
                    </div>
                    '''
                    send_email(user_email, 'Logout Alert - FormMaster Pro', html_content)
                except Exception as e:
                    print(f"Background email error: {e}")
        
        # Start background threads
        threading.Thread(target=bg_notification, daemon=True).start()
        threading.Thread(target=bg_email, daemon=True).start()
    
    # Redirect immediately
    return redirect('/login')

# Add error handlers
@app.errorhandler(404)
def page_not_found(e):
    return html_wrapper('404 Not Found', '''
    <div class="row justify-content-center align-items-center" style="min-height: 80vh;">
        <div class="col-md-6 text-center">
            <h1 class="display-1 text-white">404</h1>
            <h2 class="text-white">Page Not Found</h2>
            <p class="text-white-50">The page you are looking for doesn't exist or has been moved.</p>
            <a href="/dashboard" class="btn btn-primary btn-lg">
                <i class="fas fa-home me-2"></i>Go to Dashboard
            </a>
        </div>
    </div>
    ''', get_navbar() if 'user_id' in session else '', ''), 404

@app.errorhandler(500)
def internal_server_error(e):
    return html_wrapper('500 Internal Server Error', f'''
    <div class="row justify-content-center align-items-center" style="min-height: 80vh;">
        <div class="col-md-6 text-center">
            <h1 class="display-1 text-white">500</h1>
            <h2 class="text-white">Internal Server Error</h2>
            <p class="text-white-50">Something went wrong on our end. Please try again later.</p>
            <div class="alert alert-danger">
                <strong>Error Details:</strong><br>
                {str(e)}
            </div>
            <a href="/dashboard" class="btn btn-primary btn-lg">
                <i class="fas fa-home me-2"></i>Go to Dashboard
            </a>
        </div>
    </div>
    ''', get_navbar() if 'user_id' in session else '', ''), 500

# Main application entry point
if __name__ == '__main__':
    print("Initializing database...")
    init_db()
    
    print("Starting FormMaster Pro...")
    print(f"Admin URL: https://formmaster.up.railway.app/login")
    print(f"Admin Email: {ADMIN_EMAIL}")
    print(f"Admin Password: {ADMIN_PASSWORD}")
    print(f"Super Admin Email: {SUPER_ADMIN_EMAIL}")
    print(f"Super Admin Password: {SUPER_ADMIN_PASSWORD}")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
























