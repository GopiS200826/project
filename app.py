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
import mysql.connector  # Changed from pymysql to be consistent
from mysql.connector import Error


app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'


# Database Configuration for Railway
def get_db_connection():
    """Get database connection for Railway"""
    try:
        # Get connection details from Railway environment variables
        db_host = os.environ.get('MYSQLHOST', 'mysql.railway.internal')
        db_port = int(os.environ.get('MYSQLPORT', '3306'))
        db_user = os.environ.get('MYSQLUSER', 'root')
        db_password = os.environ.get('MYSQLPASSWORD', 'tPLXNLpSkMKDwkOmdASGmtXdsJVMyrVf')
        db_name = os.environ.get('MYSQLDATABASE', 'railway')
        
        connection = pymysql.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name,
            port=db_port,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
            connect_timeout=10
        )
        print(f"Connected to database: {db_name} on {db_host}:{db_port}")
        return connection
    except Exception as e:
        print(f"Error connecting to MySQL: {e}")
        print(f"Full error: {traceback.format_exc()}")
        return None

# Alias for compatibility
get_db = get_db_connection

# Remove the old get_db() function completely (lines 76-85)


# Email Configuration
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USER = ''  # Change this to your email
EMAIL_PASSWORD = 'Admin@123'  # Change this to your app password
EMAIL_FROM = ''  # Change this to your email

# Enable/Disable email notifications
ENABLE_EMAIL_NOTIFICATIONS = True  # Set to False to disable emails

# Default Admin Credentials
ADMIN_EMAIL = 'admin@example.com'
ADMIN_PASSWORD = 'admin123'
ADMIN_NAME = 'System Administrator'

# Department options
DEPARTMENTS = ['IT', 'CS', 'ECE', 'EEE', 'MECH', 'CIVIL', 'MBA', 'PHYSICS', 'CHEMISTRY', 'MATHS']

# Email sending function
def send_email(to_email, subject, html_content):
    if not ENABLE_EMAIL_NOTIFICATIONS:
        print(f"Email notifications disabled. Would send to {to_email}: {subject}")
        return True
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = to_email
        
        # Create HTML version
        html_part = MIMEText(html_content, 'html')
        msg.attach(html_part)
        
        # Send email
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)
        
        print(f"Email sent to {to_email}: {subject}")
        return True
    except Exception as e:
        print(f"Error sending email to {to_email}: {e}")
        return False



# Initialize database with proper table creation
def init_db():
    try:
        connection = get_db_connection()
        if not connection:
            print("Failed to connect to database")
            return
        
        with connection.cursor() as cursor:
            # Railway automatically creates the database, just select it
            pass            
            # Rest of your table creation code remains the same...
            
            # Users table
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            email VARCHAR(100) UNIQUE NOT NULL,
                            password VARCHAR(255) NOT NULL,
                            name VARCHAR(100) NOT NULL,
                            role ENUM('student', 'teacher', 'admin') DEFAULT 'student',
                            department VARCHAR(50) DEFAULT 'IT',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            INDEX idx_email (email),
                            INDEX idx_department (department)
                            )''')
            
            # Forms table with all columns
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
                            reviewed_by INT,
                            reviewed_at TIMESTAMP NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
                            FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL,
                            INDEX idx_created_by (created_by),
                            INDEX idx_department_form (department),
                            INDEX idx_form_type (form_type),
                            INDEX idx_student_submission (is_student_submission),
                            INDEX idx_review_status (review_status)
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

# Decorators
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
        if session.get('role') not in ['teacher', 'admin']:
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
        if session.get('role') != 'admin':
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
    if session['role'] == 'admin':
        user_badge = '<span class="badge bg-danger">ADMIN</span>'
    elif session['role'] == 'teacher':
        user_badge = '<span class="badge bg-warning">TEACHER</span>'
    else:
        user_badge = '<span class="badge student-stats-card">STUDENT</span>'
    
    dept_badge = '<span class="badge bg-dark ms-2">' + session.get('department', 'N/A') + '</span>'
    
    nav_links = '''
    <li><a class="dropdown-item" href="/dashboard"><i class="fas fa-home me-2"></i>Dashboard</a></li>
    '''
    
    if session['role'] in ['teacher', 'admin']:
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
    
    if session['role'] == 'admin':
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
                
                # Send login notification email
                if ENABLE_EMAIL_NOTIFICATIONS and email != ADMIN_EMAIL:
                    html_content = f'''
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #667eea;">Login Alert</h2>
                        <p>Hello {user['name']},</p>
                        <p>You have successfully logged into FormMaster Pro.</p>
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 20px 0;">
                            <p><strong>Details:</strong></p>
                            <p>User: {user['name']}</p>
                            <p>Email: {user['email']}</p>
                            <p>Role: {user['role'].title()}</p>
                            <p>Department: {user['department']}</p>
                            <p>Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        </div>
                        <p>If this wasn't you, please contact the system administrator immediately.</p>
                        <hr>
                        <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
                    </div>
                    '''
                    send_email(email, 'Login Alert - FormMaster Pro', html_content)
                
                # Create login notification
                create_notification(
                    user_id=user['id'],
                    title='Login Successful',
                    message=f'You logged in successfully from {request.remote_addr}',
                    type='success',
                    link='/dashboard'
                )
                
                return redirect('/dashboard')
            else:
                content = f'''
                <div class="row justify-content-center align-items-center" style="min-height: 80vh;">
                    <div class="col-md-4">
                        <div class="card glass-effect">
                            <div class="card-body p-4">
                                <h3 class="text-center mb-4 text-dark">Login</h3>
                                <div class="alert alert-danger">Invalid email or password</div>
                                <form method="POST">
                                    <div class="mb-3">
                                        <label class="form-label text-dark">Email</label>
                                        <input type="email" class="form-control" name="email" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label text-dark">Password</label>
                                        <input type="password" class="form-control" name="password" required>
                                    </div>
                                    <button type="submit" class="btn btn-primary w-100">Login</button>
                                </form>
                                <hr class="my-4">
                                <p class="text-center">
                                    <a href="/register" class="text-decoration-none">Create new account</a>
                                </p>
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
                return html_wrapper('Login', content, get_navbar(), '')
        except Exception as e:
            print(f"Login error: {e}")
            traceback.print_exc()
            return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')
    
    content = f'''
    <div class="row justify-content-center align-items-center" style="min-height: 80vh;">
        <div class="col-md-4">
            <div class="card glass-effect">
                <div class="card-body p-4">
                    <h3 class="text-center mb-4 text-dark">Login</h3>
                    <form method="POST">
                        <div class="mb-3">
                            <label class="form-label text-dark">Email</label>
                            <input type="email" class="form-control" name="email" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label text-dark">Password</label>
                            <input type="password" class="form-control" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Login</button>
                    </form>
                    <hr class="my-4">
                    <p class="text-center">
                        <a href="/register" class="text-decoration-none">Create new account</a>
                    </p>
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
    return html_wrapper('Login', content, '', '')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            name = request.form['name']
            email = request.form['email']
            password = request.form['password']
            role = request.form.get('role', 'student')
            department = request.form.get('department', 'IT')
            
            hashed = hash_password(password)
            connection = get_db()
            
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        'INSERT INTO users (name, email, password, role, department) VALUES (%s, %s, %s, %s, %s)',
                        (name, email, hashed, role, department)
                    )
                    connection.commit()
                    
                    cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
                    user = cursor.fetchone()
                
                connection.close()
                
                session['user_id'] = user['id']
                session['email'] = user['email']
                session['name'] = user['name']
                session['role'] = user['role']
                session['department'] = user['department']
                
                # Create welcome notification
                create_notification(
                    user_id=user['id'],
                    title='Welcome to FormMaster Pro!',
                    message=f'Your account has been created successfully as a {role} in the {department} department.',
                    type='success',
                    link='/dashboard'
                )
                
                # Send registration confirmation email
                if ENABLE_EMAIL_NOTIFICATIONS:
                    html_content = f'''
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #667eea;">Welcome to FormMaster Pro!</h2>
                        <p>Hello {name},</p>
                        <p>Your account has been successfully created.</p>
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 20px 0;">
                            <p><strong>Account Details:</strong></p>
                            <p>Name: {name}</p>
                            <p>Email: {email}</p>
                            <p>Role: {role.title()}</p>
                            <p>Department: {department}</p>
                            <p>Registration Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        </div>
                        <p>You can now login to your account and start using FormMaster Pro.</p>
                        <a href="http://localhost:5000/login" style="display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">Login to Your Account</a>
                        <hr>
                        <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
                    </div>
                    '''
                    send_email(email, 'Welcome to FormMaster Pro!', html_content)
                
                return redirect('/dashboard')
            except pymysql.err.IntegrityError:
                connection.close()
                departments_options = ''.join([f'<option value="{dept}">{dept}</option>' for dept in DEPARTMENTS])
                content = f'''
                <div class="row justify-content-center">
                    <div class="col-md-6">
                        <div class="card glass-effect">
                            <div class="card-body">
                                <h3 class="text-center mb-4">Register</h3>
                                <div class="alert alert-danger">Email already exists</div>
                                <form method="POST">
                                    <div class="mb-3">
                                        <label>Full Name</label>
                                        <input type="text" class="form-control" name="name" required>
                                    </div>
                                    <div class="mb-3">
                                        <label>Email</label>
                                        <input type="email" class="form-control" name="email" required>
                                    </div>
                                    <div class="mb-3">
                                        <label>Password</label>
                                        <input type="password" class="form-control" name="password" required>
                                    </div>
                                    <div class="mb-3">
                                        <label>Role</label>
                                        <select class="form-select" name="role">
                                            <option value="student">Student</option>
                                            <option value="teacher">Teacher</option>
                                        </select>
                                    </div>
                                    <div class="mb-3">
                                        <label>Department</label>
                                        <select class="form-select" name="department" required>
                                            {departments_options}
                                        </select>
                                    </div>
                                    <button type="submit" class="btn btn-primary w-100">Register</button>
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
                return html_wrapper('Register', content, get_navbar(), '')
        except Exception as e:
            print(f"Register error: {e}")
            traceback.print_exc()
            return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')
    
    departments_options = ''.join([f'<option value="{dept}">{dept}</option>' for dept in DEPARTMENTS])
    content = f'''
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card glass-effect">
                <div class="card-body">
                    <h3 class="text-center mb-4">Register</h3>
                    <form method="POST">
                        <div class="mb-3">
                            <label>Full Name</label>
                            <input type="text" class="form-control" name="name" required>
                        </div>
                        <div class="mb-3">
                            <label>Email</label>
                            <input type="email" class="form-control" name="email" required>
                        </div>
                        <div class="mb-3">
                            <label>Password</label>
                            <input type="password" class="form-control" name="password" required>
                        </div>
                        <div class="mb-3">
                            <label>Role</label>
                            <select class="form-select" name="role">
                                <option value="student">Student</option>
                                <option value="teacher">Teacher</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label>Department</label>
                            <select class="form-select" name="department" required>
                                {departments_options}
                            </select>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Register</button>
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
            
            if user_role == 'admin':
                if selected_dept:
                    dept_filter = 'AND f.department = %s'
                    params.append(selected_dept)
                else:
                    dept_filter = ''
            elif user_role == 'teacher':
                dept_filter = 'AND f.department = %s'
                params.append(user_dept)
            
            # Get forms based on user role and department
            if user_role == 'admin':
                cursor.execute(f'''
                    SELECT f.*, u.name as creator_name, u.department as creator_department 
                    FROM forms f 
                    JOIN users u ON f.created_by = u.id 
                    WHERE (f.is_student_submission = FALSE OR f.review_status = 'approved')
                    {dept_filter}
                    ORDER BY f.created_at DESC
                ''', params)
                forms = cursor.fetchall()
            elif user_role == 'teacher':
                cursor.execute(f'''
                    SELECT f.*, u.name as creator_name 
                    FROM forms f 
                    JOIN users u ON f.created_by = u.id 
                    WHERE (f.is_student_submission = FALSE OR f.review_status = 'approved')
                    {dept_filter}
                    ORDER BY f.created_at DESC
                ''', params)
                forms = cursor.fetchall()
            else:
                # Students only see forms from their department
                cursor.execute('''
                    SELECT f.*, u.name as creator_name,
                           (SELECT status FROM form_requests WHERE form_id = f.id AND student_id = %s) as request_status,
                           (SELECT 1 FROM assignments WHERE form_id = f.id AND student_id = %s) as is_assigned,
                           (SELECT 1 FROM responses WHERE form_id = f.id AND student_id = %s) as has_submitted
                    FROM forms f 
                    JOIN users u ON f.created_by = u.id 
                    WHERE f.department = %s 
                    AND f.form_type = 'open'
                    AND (f.is_student_submission = FALSE OR f.review_status = 'approved')
                    ORDER BY f.created_at DESC
                ''', (user_id, user_id, user_id, user_dept))
                forms = cursor.fetchall()
            
            # Get assigned forms for students
            assigned_forms = []
            if user_role == 'student':
                cursor.execute('''
                    SELECT f.*, a.due_date, a.is_completed 
                    FROM forms f
                    JOIN assignments a ON f.id = a.form_id
                    WHERE a.student_id = %s AND f.review_status = 'approved'
                ''', (user_id,))
                assigned_forms = cursor.fetchall()
            
            # Get pending requests count for teachers/admin
            pending_requests_count = 0
            if user_role in ['teacher', 'admin']:
                if user_role == 'admin':
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
            if user_role in ['teacher', 'admin']:
                if user_role == 'admin':
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
            
            # Get department statistics for admin
            dept_stats = {}
            if user_role == 'admin':
                cursor.execute('''
                    SELECT department, 
                           COUNT(*) as form_count,
                           SUM(CASE WHEN is_student_submission = TRUE THEN 1 ELSE 0 END) as student_forms,
                           SUM(CASE WHEN review_status = 'approved' THEN 1 ELSE 0 END) as approved_forms
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
                        SUM(CASE WHEN percentage < 70 THEN 1 ELSE 0 END) as failed_forms
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
        
        connection.close()
        
        # Department filter for admin/teacher
        dept_filter_html = ''
        if user_role in ['admin', 'teacher']:
            departments_options = '<option value="">All Departments</option>' if user_role == 'admin' else f'<option value="{user_dept}" selected>{user_dept} (Current)</option>'
            
            if user_role == 'admin':
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
                            {f'Showing forms from: {selected_dept if selected_dept else "All Departments"}' if user_role == 'admin' else f'Showing forms from your department: {user_dept}'}
                        </small>
                    </div>
                </form>
            </div>
            '''
        
        # Department statistics for admin
        dept_stats_html = ''
        if user_role == 'admin' and not selected_dept:
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
                                Student Forms: {stat['student_forms']}<br>
                                Approved: {stat['approved_forms']}
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
            type_badge = 'badge-info' if form['form_type'] == 'open' else 'badge-purple'
            type_text = 'Open' if form['form_type'] == 'open' else 'Confidential'
            
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
            student_actions = ''
            
            if form['created_by'] == user_id or user_role in ['teacher', 'admin']:
                edit_button = f'<a href="/form/{form["id"]}/edit" class="btn btn-sm btn-outline-primary"><i class="fas fa-edit"></i> Edit</a>'
                results_button = f'<a href="/form/{form["id"]}/responses" class="btn btn-sm btn-outline-success"><i class="fas fa-chart-bar"></i> Results</a>'
            
            if user_role in ['teacher', 'admin']:
                assign_button = f'<a href="/form/{form["id"]}/assign" class="btn btn-sm btn-outline-warning"><i class="fas fa-user-plus"></i> Assign</a>'
            
            # Student actions for taking forms
            if user_role == 'student':
                if has_submitted:
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
                    student_actions = f'<button onclick="requestForm({form["id"]})" class="btn btn-sm btn-outline-purple"><i class="fas fa-hand-paper"></i> Request Access</button>'
            
            # For admin, show creator's department
            dept_info = f'<i class="fas fa-building me-1"></i>{form["department"]}'
            if user_role == 'admin' and 'creator_department' in form:
                dept_info = f'<i class="fas fa-building me-1"></i>{form["department"]} (Creator Dept: {form["creator_department"]})'
            
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
                        </div>
                        <span class="badge {status_badge}">{status_text}</span>
                    </div>
                    <div class="form-actions mt-3">
                        {student_actions}
                        {edit_button}
                        {results_button}
                        {assign_button}
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
        
        # Render assigned forms for students
        assigned_html = ''
        if user_role == 'student':
            for form in assigned_forms:
                status_badge = 'badge-success' if form['is_completed'] else 'badge-danger'
                status_text = 'Completed' if form['is_completed'] else 'Pending'
                
                start_button = f'<a href="/form/{form["id"]}/take" class="btn btn-sm btn-primary"><i class="fas fa-play"></i> Start</a>' if not form['is_completed'] else '<span class="text-success"><i class="fas fa-check"></i> Submitted</span>'
                
                assigned_html += f'''
                <div class="card mb-3">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <h5 class="mb-1">{form['title']}</h5>
                                <small class="text-muted">
                                    <i class="fas fa-building me-1"></i>{form['department']}
                                    {f'| Due: {form["due_date"].strftime("%Y-%m-%d") if form["due_date"] else "No due date"}'}
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
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(45deg, #3b82f6, #1d4ed8);">
                        <h5>Average Score</h5>
                        <h2>{student_stats.get('avg_score', 0) or 0:.1f}%</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(45deg, #10b981, #059669);">
                        <h5>Passed Forms</h5>
                        <h2>{student_stats.get('passed_forms', 0) or 0}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(45deg, #8b5cf6, #7c3aed);">
                        <h5>Pending Submissions</h5>
                        <h2>{student_stats.get('pending_submissions', 0) or 0}</h2>
                    </div>
                </div>
            </div>
            '''
        
        # Determine column widths
        col_width = '12'
        assigned_section = ''
        if user_role == 'student':
            col_width = '6'
            assigned_section = f'''
            <div class="col-md-6">
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
        if user_role in ['teacher', 'admin'] and pending_requests_count > 0:
            requests_badge = f'<span class="badge bg-danger request-badge">{pending_requests_count}</span>'
        
        # Pending reviews badge for teachers/admin
        reviews_badge = ''
        if user_role in ['teacher', 'admin'] and pending_reviews_count > 0:
            reviews_badge = f'<span class="badge bg-warning request-badge">{pending_reviews_count}</span>'
        
        # Build dashboard
        content = f'''
        <div class="mb-4">
            <div class="d-flex justify-content-between align-items-center">
                <h2 class="text-white">Welcome, {session["name"]}!</h2>
                <div>
                    <span class="badge bg-light text-dark me-2">{session["department"]}</span>
                    {f'<a href="/create-form" class="btn btn-primary"><i class="fas fa-plus me-2"></i>Create Form</a>' if user_role in ['teacher', 'admin'] else ''}
                    {f'<a href="/create-student-form" class="btn btn-success"><i class="fas fa-plus-circle me-2"></i>Create Form</a>' if user_role == 'student' else ''}
                </div>
            </div>
        </div>

        {dept_filter_html}
        {dept_stats_html}
        {student_stats_html}
        
        <div class="row">
            <div class="col-md-{col_width}">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-list me-2"></i>Available Forms ({len(forms)})
                            {requests_badge}
                            {reviews_badge}
                        </h5>
                    </div>
                    <div class="card-body">
                        {forms_html}
                    </div>
                </div>
            </div>
            {assigned_section}
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
        </script>
        '''
        
        return html_wrapper('Dashboard', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"Dashboard error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/create-form', methods=['GET', 'POST'])
@login_required
def create_form():
    if session['role'] not in ['teacher', 'admin']:
        return redirect('/create-student-form')
    
    if request.method == 'POST':
        try:
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            department = request.form.get('department', session['department'])
            form_type = request.form.get('form_type', 'open')
            
            if not title:
                return html_wrapper('Error', '<div class="alert alert-danger">Title is required</div>', get_navbar(), '')
            
            connection = get_db()
            with connection.cursor() as cursor:
                cursor.execute('''
                    INSERT INTO forms (title, description, created_by, department, form_type, questions) 
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', (title, description, session['user_id'], department, form_type, '[]'))
                form_id = cursor.lastrowid
                connection.commit()
            connection.close()
            
            # Create notification for form creation
            create_notification(
                user_id=session['user_id'],
                title='Form Created Successfully',
                message=f'Your form "{title}" has been created successfully.',
                type='success',
                link=f'/form/{form_id}/edit'
            )
            
            # Send form creation email
            if ENABLE_EMAIL_NOTIFICATIONS:
                html_content = f'''
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #667eea;">New Form Created</h2>
                    <p>Hello {session['name']},</p>
                    <p>You have successfully created a new form.</p>
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 20px 0;">
                        <p><strong>Form Details:</strong></p>
                        <p>Title: {title}</p>
                        <p>Description: {description or 'No description'}</p>
                        <p>Department: {department}</p>
                        <p>Type: {form_type.title()}</p>
                        <p>Created By: {session['name']}</p>
                        <p>Creation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    <p>You can now edit the form to add questions and publish it.</p>
                    <a href="http://localhost:5000/form/{form_id}/edit" style="display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">Edit Form</a>
                    <hr>
                    <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
                </div>
                '''
                send_email(session['email'], 'New Form Created - FormMaster Pro', html_content)
            
            return redirect(f'/form/{form_id}/edit')
            
        except Exception as e:
            print(f"Create form error: {e}")
            traceback.print_exc()
            return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')
    
    # Show all departments for admin, only user's department for teachers
    if session['role'] == 'admin':
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
                                <option value="open">Open - Students can request to take</option>
                                <option value="confidential">Confidential - Students must request access</option>
                            </select>
                            <small class="text-muted">
                                For both types, students need to request access. You'll need to approve their requests.
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
            
            if not title:
                return html_wrapper('Error', '<div class="alert alert-danger">Title is required</div>', get_navbar(), '')
            
            if not reviewer_id:
                return html_wrapper('Error', '<div class="alert alert-danger">Please select a reviewer</div>', get_navbar(), '')
            
            connection = get_db()
            with connection.cursor() as cursor:
                # Get reviewer details
                cursor.execute('SELECT name, email FROM users WHERE id = %s', (reviewer_id,))
                reviewer = cursor.fetchone()
                
                # Create the form as student submission
                cursor.execute('''
                    INSERT INTO forms (title, description, created_by, department, form_type, questions, 
                                      is_student_submission, review_status, reviewed_by) 
                    VALUES (%s, %s, %s, %s, %s, %s, TRUE, 'pending', %s)
                ''', (title, description, session['user_id'], department, form_type, '[]', reviewer_id))
                form_id = cursor.lastrowid
                
                # Also create entry in student_form_reviews table
                cursor.execute('''
                    INSERT INTO student_form_reviews (form_id, student_id, reviewer_id, review_status)
                    VALUES (%s, %s, %s, 'pending')
                ''', (form_id, session['user_id'], reviewer_id))
                
                connection.commit()
            connection.close()
            
            # Create notification for student
            create_notification(
                user_id=session['user_id'],
                title='Student Form Created',
                message=f'Your form "{title}" has been created and submitted for review.',
                type='success',
                link=f'/student-form/{form_id}/edit'
            )
            
            # Create notification for reviewer
            create_notification(
                user_id=reviewer_id,
                title='New Student Form for Review',
                message=f'A new student form "{title}" has been submitted for your review.',
                type='warning',
                link='/review-forms'
            )
            
            # Send form creation email to student
            if ENABLE_EMAIL_NOTIFICATIONS:
                html_content = f'''
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #667eea;">Student Form Created</h2>
                    <p>Hello {session['name']},</p>
                    <p>You have successfully created a new student form for review.</p>
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 20px 0;">
                        <p><strong>Form Details:</strong></p>
                        <p>Title: {title}</p>
                        <p>Description: {description or 'No description'}</p>
                        <p>Department: {department}</p>
                        <p>Type: {form_type.title()}</p>
                        <p>Reviewer: {reviewer['name']} ({reviewer['email']})</p>
                        <p>Status: Pending Review</p>
                    </div>
                    <p>Your form has been submitted for review. The reviewer will notify you once it's approved.</p>
                    <a href="http://localhost:5000/student-form/{form_id}/edit" style="display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">Edit Form</a>
                    <hr>
                    <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
                </div>
                '''
                send_email(session['email'], 'Student Form Created - FormMaster Pro', html_content)
                
                # Send notification email to reviewer
                html_content_reviewer = f'''
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #667eea;">New Student Form for Review</h2>
                    <p>Hello {reviewer['name']},</p>
                    <p>A student has submitted a new form for your review.</p>
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 20px 0;">
                        <p><strong>Form Details:</strong></p>
                        <p>Title: {title}</p>
                        <p>Description: {description or 'No description'}</p>
                        <p>Department: {department}</p>
                        <p>Type: {form_type.title()}</p>
                        <p>Student: {session['name']} ({session['email']})</p>
                        <p>Status: Pending Review</p>
                    </div>
                    <p>Please review this form and approve or reject it.</p>
                    <a href="http://localhost:5000/review-forms" style="display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">Review Forms</a>
                    <hr>
                    <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
                </div>
                '''
                send_email(reviewer['email'], 'New Student Form for Review - FormMaster Pro', html_content_reviewer)
            
            return redirect(f'/student-form/{form_id}/edit')
            
        except Exception as e:
            print(f"Create student form error: {e}")
            traceback.print_exc()
            return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')
    
    # Get available teachers for review
    connection = get_db()
    with connection.cursor() as cursor:
        cursor.execute('''
            SELECT id, name, email, role, department 
            FROM users 
            WHERE role IN ('teacher', 'admin') 
            AND department = %s
            ORDER BY name
        ''', (session['department'],))
        reviewers = cursor.fetchall()
    connection.close()
    
    reviewers_options = '<option value="">Select a reviewer...</option>'
    for reviewer in reviewers:
        role_text = 'Teacher' if reviewer['role'] == 'teacher' else 'Admin'
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
                .then(res => res.json())
                .then(data => {{
                    if (data.success) {{
                        alert('Questions saved successfully!');
                    }} else {{
                        alert('Error saving questions');
                    }}
                }})
                .catch(error => {{
                    alert('Error: ' + error);
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

@app.route('/api/student-form/<int:form_id>', methods=['POST'])
@student_required
def update_student_form(form_id):
    try:
        data = request.json
        questions = data.get('questions', [])
        
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('UPDATE forms SET questions = %s WHERE id = %s', 
                          (json.dumps(questions), form_id))
            connection.commit()
        connection.close()
        
        # Create notification for saving form
        create_notification(
            user_id=session['user_id'],
            title='Form Saved',
            message='Your form questions have been saved successfully.',
            type='success',
            link=f'/student-form/{form_id}/edit'
        )
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Update student form error: {e}")
        return jsonify({'success': False, 'error': str(e)})

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
                <a href="http://localhost:5000/review-forms" style="display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">Review Forms</a>
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
        
        {"""
        <div class="text-center py-5">
            <i class="fas fa-chart-line fa-3x text-muted mb-3"></i>
            <h4>No responses yet</h4>
            <p class="text-muted">You haven't taken any forms yet.</p>
            <a href="/dashboard" class="btn btn-primary">
                <i class="fas fa-list me-2"></i>Browse Available Forms
            </a>
        </div>
        """ if not responses else ''}
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
        
        # Get selected department for admin
        selected_dept = request.args.get('department', '')
        
        with connection.cursor() as cursor:
            if session['role'] == 'admin':
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
            if session['role'] == 'admin':
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
        
        # Department filter for admin
        dept_filter_html = ''
        if session['role'] == 'admin':
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
            
            # Admin can review any form, teachers only from their department
            if session['role'] != 'admin':
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
                    <a href="http://localhost:5000/dashboard" style="display: inline-block; padding: 10px 20px; background: #10b981; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">View Dashboard</a>
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
                    <a href="http://localhost:5000/my-submissions" style="display: inline-block; padding: 10px 20px; background: #ef4444; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">View Submissions</a>
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
        
        # Check permissions - admin can edit any form
        if form['created_by'] != session['user_id'] and session['role'] not in ['teacher', 'admin']:
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
                            <a href="http://localhost:5000/dashboard" style="display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">View Dashboard</a>
                            <hr>
                            <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
                        </div>
                        '''
                        send_email(student['email'], 'New Form Assigned - FormMaster Pro', html_content)
            
            # Return after POST to avoid showing form again
            return redirect('/dashboard')
        
        # GET request - show the form
        with connection.cursor() as cursor:
            # For admin, show students from all departments, for teachers only from form's department
            if session['role'] == 'admin':
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
        if session['role'] == 'admin':
            # Group students by department for admin
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
                <a href="http://localhost:5000/form-requests" style="display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">Review Requests</a>
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
        
        # Get selected department for admin
        selected_dept = request.args.get('department', '')
        
        with connection.cursor() as cursor:
            if session['role'] == 'admin':
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
        
        # Department filter for admin
        dept_filter_html = ''
        if session['role'] == 'admin':
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
            if session['role'] != 'admin':
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
                    <a href="http://localhost:5000/dashboard" style="display: inline-block; padding: 10px 20px; background: #10b981; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">View Dashboard</a>
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
            
            # Admin can access any form
            admin_access = session['role'] == 'admin'
            
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
                <h3>{form['title']}</h3>
                <p>{form['description']}</p>
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
            
            cursor.execute('''
                UPDATE assignments SET is_completed = TRUE 
                WHERE form_id = %s AND student_id = %s
            ''', (form_id, session['user_id']))
            
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
            link='/my-responses'
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
        
        # Send submission notification email
        if ENABLE_EMAIL_NOTIFICATIONS and form_details:
            html_content = f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #667eea;">Form Submission Completed</h2>
                <p>Hello {form_details['creator_name']},</p>
                <p>A student has submitted your form.</p>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 20px 0;">
                    <p><strong>Form Details:</strong></p>
                    <p>Title: {form_details['title']}</p>
                    <p>Student: {form_details['student_name']} ({form_details['student_email']})</p>
                    <p>Score: {score}/{total_marks} ({percentage:.1f}%)</p>
                    <p>Submission Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                <p>You can view all responses from the form results page.</p>
                <a href="http://localhost:5000/form/{form_id}/responses" style="display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">View Results</a>
                <hr>
                <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
            </div>
            '''
            send_email(form_details['creator_email'], 'Form Submission - FormMaster Pro', html_content)
        
        return jsonify({
            'success': True,
            'score': score,
            'total_marks': total_marks,
            'percentage': round(percentage, 2)
        })
    except Exception as e:
        print(f"Submit form error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/form/<int:form_id>/responses')
@login_required
def view_responses(form_id):
    try:
        # Get selected department for admin
        selected_dept = request.args.get('department', '')
        
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            # Admin can view all responses
            if session['role'] != 'admin':
                if not form or (form['created_by'] != session['user_id'] and session['role'] != 'admin'):
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
            
            # Get responses with department filter for admin
            if session['role'] == 'admin' and selected_dept:
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
        
        # Department filter for admin
        dept_filter_html = ''
        if session['role'] == 'admin':
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
            teacher_forms_html += f'''
            <tr onclick="showFormDetails({form['id']})" style="cursor: pointer;">
                <td>{form['title']}</td>
                <td><span class="badge bg-{type_badge}">{form['form_type'].title()}</span></td>
                <td><span class="badge bg-{status_badge}">{'Published' if form['is_published'] else 'Draft'}</span></td>
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

@app.route('/api/notifications/<int:notification_id>/delete', methods=['DELETE'])
@login_required
def delete_notification(notification_id):
    """Delete a specific notification"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('DELETE FROM notifications WHERE id = %s AND user_id = %s', 
                          (notification_id, session['user_id']))
            connection.commit()
        connection.close()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error deleting notification: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/notifications/clear-all', methods=['DELETE'])
@login_required
def clear_all_notifications():
    """Clear all notifications for user"""
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

@app.route('/admin')
@admin_required
def admin_panel():
    try:
        # Get selected department from query parameter
        selected_dept = request.args.get('department', '')
        
        connection = get_db()
        with connection.cursor() as cursor:
            # Get overall statistics
            cursor.execute('''
                SELECT 
                    (SELECT COUNT(*) FROM users) as total_users,
                    (SELECT COUNT(*) FROM users WHERE role = 'student') as students,
                    (SELECT COUNT(*) FROM users WHERE role = 'teacher') as teachers,
                    (SELECT COUNT(*) FROM forms) as forms,
                    (SELECT COUNT(*) FROM responses) as responses,
                    (SELECT COUNT(*) FROM form_requests WHERE status = 'pending') as pending_requests,
                    (SELECT COUNT(*) FROM forms WHERE is_student_submission = TRUE AND review_status = 'pending') as pending_reviews
            ''')
            stats = cursor.fetchone()
            
            # Get department-wise user statistics
            cursor.execute('''
                SELECT department, 
                       COUNT(*) as total_users,
                       SUM(CASE WHEN role = 'student' THEN 1 ELSE 0 END) as students,
                       SUM(CASE WHEN role = 'teacher' THEN 1 ELSE 0 END) as teachers,
                       SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admins
                FROM users 
                GROUP BY department
                ORDER BY department
            ''')
            dept_user_stats = cursor.fetchall()
            
            # Get forms by department with filter
            query = '''
                SELECT department, COUNT(*) as form_count, 
                       SUM(CASE WHEN form_type = 'open' THEN 1 ELSE 0 END) as open_forms,
                       SUM(CASE WHEN form_type = 'confidential' THEN 1 ELSE 0 END) as confidential_forms,
                       SUM(CASE WHEN is_student_submission = TRUE THEN 1 ELSE 0 END) as student_forms,
                       SUM(CASE WHEN review_status = 'approved' THEN 1 ELSE 0 END) as approved_forms
                FROM forms 
            '''
            params = []
            
            if selected_dept:
                query += ' WHERE department = %s'
                params.append(selected_dept)
            
            query += ' GROUP BY department ORDER BY department'
            cursor.execute(query, params)
            form_stats = cursor.fetchall()
            
            # Recent activities with department filter
            query = '''
                SELECT u.name, f.title, fr.status, fr.requested_at, fr.approved_at, f.department
                FROM form_requests fr
                JOIN users u ON fr.student_id = u.id
                JOIN forms f ON fr.form_id = f.id
            '''
            params = []
            
            if selected_dept:
                query += ' WHERE f.department = %s'
                params.append(selected_dept)
            
            query += ' ORDER BY fr.requested_at DESC LIMIT 10'
            cursor.execute(query, params)
            recent_activities = cursor.fetchall()
            
            # Recent forms with department filter
            query = '''
                SELECT f.title, f.department, f.form_type, f.is_student_submission, u.name as creator, f.created_at
                FROM forms f
                JOIN users u ON f.created_by = u.id
            '''
            params = []
            
            if selected_dept:
                query += ' WHERE f.department = %s'
                params.append(selected_dept)
            
            query += ' ORDER BY f.created_at DESC LIMIT 10'
            cursor.execute(query, params)
            recent_forms = cursor.fetchall()
            
        connection.close()
        
        # Department filter for admin
        departments_options = '<option value="">All Departments</option>'
        for dept in DEPARTMENTS:
            selected = 'selected' if dept == selected_dept else ''
            departments_options += f'<option value="{dept}" {selected}>{dept}</option>'
        
        dept_filter_html = f'''
        <div class="dept-filter mb-4">
            <h5 class="mb-3">Department Filter</h5>
            <form method="GET" action="/admin" class="row align-items-center">
                <div class="col-md-4">
                    <select class="form-select" name="department" onchange="this.form.submit()">
                        {departments_options}
                    </select>
                </div>
                <div class="col-md-8">
                    <small class="text-muted">
                        Showing data for: {selected_dept if selected_dept else "All Departments"}
                    </small>
                </div>
            </form>
        </div>
        '''
        
        dept_user_html = ''
        for stat in dept_user_stats:
            dept_user_html += f'''
            <tr>
                <td><a href="/admin/users?department={stat['department']}" class="text-decoration-none">{stat['department']}</a></td>
                <td>{stat['total_users']}</td>
                <td>{stat['students']}</td>
                <td>{stat['teachers']}</td>
                <td>{stat['admins']}</td>
            </tr>
            '''
        
        form_stats_html = ''
        for stat in form_stats:
            form_stats_html += f'''
            <tr>
                <td><a href="/admin/forms?department={stat['department']}" class="text-decoration-none">{stat['department']}</a></td>
                <td>{stat['form_count']}</td>
                <td>{stat['open_forms']}</td>
                <td>{stat['confidential_forms']}</td>
                <td>{stat['student_forms']}</td>
                <td>{stat['approved_forms']}</td>
            </tr>
            '''
        
        recent_activities_html = ''
        for activity in recent_activities:
            status_badge = 'success' if activity['status'] == 'approved' else 'warning' if activity['status'] == 'pending' else 'danger'
            recent_activities_html += f'''
            <tr>
                <td>{activity['name']}</td>
                <td>{activity['title']}</td>
                <td>{activity['department']}</td>
                <td><span class="badge bg-{status_badge}">{activity['status'].upper()}</span></td>
                <td>{activity['requested_at']}</td>
                <td>{activity['approved_at'] or 'N/A'}</td>
            </tr>
            '''
        
        recent_forms_html = ''
        for form in recent_forms:
            type_badge = 'info' if form['form_type'] == 'open' else 'purple'
            student_badge = '<span class="badge student-stats-card">Student</span>' if form['is_student_submission'] else ''
            recent_forms_html += f'''
            <tr>
                <td>{form['title']} {student_badge}</td>
                <td>{form['department']}</td>
                <td><span class="badge bg-{type_badge}">{form['form_type'].title()}</span></td>
                <td>{form['creator']}</td>
                <td>{form['created_at']}</td>
            </tr>
            '''
        
        content = f'''
        <h2 class="mb-4 text-white">Admin Dashboard</h2>
        
        {dept_filter_html}
        
        <div class="row mb-4">
            <div class="col-md-2">
                <a href="/admin/users" class="text-decoration-none">
                    <div class="stat-card" style="background: linear-gradient(45deg, #667eea, #764ba2); cursor: pointer;" 
                         onmouseover="this.style.transform='scale(1.05)'" onmouseout="this.style.transform='scale(1)'">
                        <h5>Users</h5>
                        <h2>{stats['total_users']}</h2>
                    </div>
                </a>
            </div>
            <div class="col-md-2">
                <a href="/admin/users?role=student" class="text-decoration-none">
                    <div class="stat-card" style="background: linear-gradient(45deg, #10b981, #059669); cursor: pointer;"
                         onmouseover="this.style.transform='scale(1.05)'" onmouseout="this.style.transform='scale(1)'">
                        <h5>Students</h5>
                        <h2>{stats['students']}</h2>
                    </div>
                </a>
            </div>
            <div class="col-md-2">
                <a href="/admin/users?role=teacher" class="text-decoration-none">
                    <div class="stat-card" style="background: linear-gradient(45deg, #f59e0b, #d97706); cursor: pointer;"
                         onmouseover="this.style.transform='scale(1.05)'" onmouseout="this.style.transform='scale(1)'">
                        <h5>Teachers</h5>
                        <h2>{stats['teachers']}</h2>
                    </div>
                </a>
            </div>
            <div class="col-md-2">
                <a href="/admin/forms" class="text-decoration-none">
                    <div class="stat-card" style="background: linear-gradient(45deg, #3b82f6, #1d4ed8); cursor: pointer;"
                         onmouseover="this.style.transform='scale(1.05)'" onmouseout="this.style.transform='scale(1)'">
                        <h5>Forms</h5>
                        <h2>{stats['forms']}</h2>
                    </div>
                </a>
            </div>
            <div class="col-md-2">
                <a href="/form-requests" class="text-decoration-none">
                    <div class="stat-card" style="background: linear-gradient(45deg, #8b5cf6, #7c3aed); cursor: pointer;"
                         onmouseover="this.style.transform='scale(1.05)'" onmouseout="this.style.transform='scale(1)'">
                        <h5>Pending Requests</h5>
                        <h2>{stats['pending_requests']}</h2>
                    </div>
                </a>
            </div>
            <div class="col-md-2">
                <a href="/review-forms" class="text-decoration-none">
                    <div class="stat-card" style="background: linear-gradient(45deg, #ef4444, #dc2626); cursor: pointer;"
                         onmouseover="this.style.transform='scale(1.05)'" onmouseout="this.style.transform='scale(1)'">
                        <h5>Pending Reviews</h5>
                        <h2>{stats['pending_reviews']}</h2>
                    </div>
                </a>
            </div>
        </div>
        
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5>Recent Activities</h5>
                        <a href="/form-requests" class="btn btn-sm btn-primary">View All</a>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Student</th>
                                        <th>Form</th>
                                        <th>Dept</th>
                                        <th>Status</th>
                                        <th>Requested</th>
                                        <th>Approved</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {recent_activities_html}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5>Recently Created Forms</h5>
                        <a href="/admin/forms" class="btn btn-sm btn-primary">View All</a>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Title</th>
                                        <th>Department</th>
                                        <th>Type</th>
                                        <th>Creator</th>
                                        <th>Created</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {recent_forms_html}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Department-wise User Statistics</h5>
                    </div>
                    <div class="card-body">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Department</th>
                                    <th>Total Users</th>
                                    <th>Students</th>
                                    <th>Teachers</th>
                                    <th>Admins</th>
                                </tr>
                            </thead>
                            <tbody>
                                {dept_user_html}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Department-wise Form Statistics</h5>
                    </div>
                    <div class="card-body">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Department</th>
                                    <th>Total Forms</th>
                                    <th>Open Forms</th>
                                    <th>Confidential</th>
                                    <th>Student Forms</th>
                                    <th>Approved</th>
                                </tr>
                            </thead>
                            <tbody>
                                {form_stats_html}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        return html_wrapper('Admin Panel', content, get_navbar(), '')
        
    except Exception as e:
        print(f"Admin panel error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/admin/users')
@admin_required
def admin_users():
    try:
        role_filter = request.args.get('role', '')
        department_filter = request.args.get('department', '')
        
        connection = get_db()
        with connection.cursor() as cursor:
            query = 'SELECT * FROM users WHERE 1=1'
            params = []
            
            if role_filter:
                query += ' AND role = %s'
                params.append(role_filter)
            
            if department_filter:
                query += ' AND department = %s'
                params.append(department_filter)
            
            query += ' ORDER BY created_at DESC'
            cursor.execute(query, params)
            users = cursor.fetchall()
        
        connection.close()
        
        # Department filter
        departments_options = '<option value="">All Departments</option>'
        for dept in DEPARTMENTS:
            selected = 'selected' if dept == department_filter else ''
            departments_options += f'<option value="{dept}" {selected}>{dept}</option>'
        
        # Role filter
        roles_options = '<option value="">All Roles</option>'
        roles = ['student', 'teacher', 'admin']
        for role in roles:
            selected = 'selected' if role == role_filter else ''
            roles_options += f'<option value="{role}" {selected}>{role.title()}</option>'
        
        filter_html = f'''
        <div class="dept-filter mb-4">
            <h5 class="mb-3">Filter Users</h5>
            <form method="GET" action="/admin/users" class="row g-3">
                <div class="col-md-4">
                    <select class="form-select" name="department">
                        {departments_options}
                    </select>
                </div>
                <div class="col-md-4">
                    <select class="form-select" name="role">
                        {roles_options}
                    </select>
                </div>
                <div class="col-md-4">
                    <button type="submit" class="btn btn-primary w-100">Apply Filters</button>
                </div>
            </form>
        </div>
        '''
        
        users_html = ''
        for user in users:
            role_badge = 'danger' if user['role'] == 'admin' else 'warning' if user['role'] == 'teacher' else 'info'
            users_html += f'''
            <tr>
                <td>{user['id']}</td>
                <td>{user['name']}</td>
                <td>{user['email']}</td>
                <td><span class="badge bg-{role_badge}">{user['role'].upper()}</span></td>
                <td>{user['department']}</td>
                <td>{user['created_at']}</td>
            </tr>
            '''
        
        content = f'''
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2 class="text-white">Users Management</h2>
            <a href="/admin" class="btn btn-secondary">Back to Admin</a>
        </div>
        
        {filter_html}
        
        <div class="card">
            <div class="card-header">
                <h5>All Users ({len(users)})</h5>
                <p class="mb-0 text-muted">
                    Showing: {role_filter if role_filter else 'All Roles'} | 
                    {department_filter if department_filter else 'All Departments'}
                </p>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Name</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th>Department</th>
                                <th>Created</th>
                            </tr>
                        </thead>
                        <tbody>
                            {users_html}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        '''
        
        return html_wrapper('Users Management', content, get_navbar(), '')
        
    except Exception as e:
        print(f"Admin users error: {e}")
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/admin/forms')
@admin_required
def admin_forms():
    try:
        department_filter = request.args.get('department', '')
        
        connection = get_db()
        with connection.cursor() as cursor:
            query = '''
                SELECT f.*, u.name as creator_name, u.department as creator_department,
                       (SELECT COUNT(*) FROM responses WHERE form_id = f.id) as response_count,
                       u2.name as reviewer_name
                FROM forms f 
                JOIN users u ON f.created_by = u.id 
                LEFT JOIN users u2 ON f.reviewed_by = u2.id
                WHERE 1=1
            '''
            params = []
            
            if department_filter:
                query += ' AND f.department = %s'
                params.append(department_filter)
            
            query += ' ORDER BY f.created_at DESC'
            cursor.execute(query, params)
            forms = cursor.fetchall()
        
        connection.close()
        
        # Department filter
        departments_options = '<option value="">All Departments</option>'
        for dept in DEPARTMENTS:
            selected = 'selected' if dept == department_filter else ''
            departments_options += f'<option value="{dept}" {selected}>{dept}</option>'
        
        filter_html = f'''
        <div class="dept-filter mb-4">
            <h5 class="mb-3">Filter Forms</h5>
            <form method="GET" action="/admin/forms" class="row g-3">
                <div class="col-md-6">
                    <select class="form-select" name="department">
                        {departments_options}
                    </select>
                </div>
                <div class="col-md-6">
                    <button type="submit" class="btn btn-primary w-100">Apply Filter</button>
                </div>
            </form>
        </div>
        '''
        
        forms_html = ''
        for form in forms:
            status_badge = 'success' if form['is_published'] else 'warning'
            type_badge = 'info' if form['form_type'] == 'open' else 'purple'
            student_badge = '<span class="badge student-stats-card">Student</span>' if form['is_student_submission'] else ''
            review_badge = ''
            if form['is_student_submission']:
                if form['review_status'] == 'approved':
                    review_badge = '<span class="badge bg-success">Approved</span>'
                elif form['review_status'] == 'pending':
                    review_badge = '<span class="badge bg-warning">Pending Review</span>'
                elif form['review_status'] == 'rejected':
                    review_badge = '<span class="badge bg-danger">Rejected</span>'
            
            forms_html += f'''
            <tr>
                <td>{form['id']}</td>
                <td>
                    <strong>{form['title']}</strong>
                    {student_badge}
                    <br><small>{form['description'][:50] if form['description'] else 'No description'}...</small>
                </td>
                <td>{form['creator_name']}</td>
                <td>{form['department']}</td>
                <td>
                    <span class="badge bg-{type_badge}">{form['form_type'].title()}</span><br>
                    <span class="badge bg-{status_badge}">{'Published' if form['is_published'] else 'Draft'}</span>
                    {review_badge}
                </td>
                <td>{form['response_count']}</td>
                <td>
                    <div class="btn-group btn-group-sm">
                        <a href="/form/{form['id']}/edit" class="btn btn-outline-primary">Edit</a>
                        <a href="/form/{form['id']}/responses" class="btn btn-outline-success">Results</a>
                        <a href="/form/{form['id']}/assign" class="btn btn-outline-warning">Assign</a>
                    </div>
                </td>
            </tr>
            '''
        
        content = f'''
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2 class="text-white">Forms Management</h2>
            <a href="/admin" class="btn btn-secondary">Back to Admin</a>
        </div>
        
        {filter_html}
        
        <div class="card">
            <div class="card-header">
                <h5>All Forms ({len(forms)})</h5>
                <p class="mb-0 text-muted">
                    Showing forms from: {department_filter if department_filter else 'All Departments'}
                </p>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Form Details</th>
                                <th>Creator</th>
                                <th>Department</th>
                                <th>Type & Status</th>
                                <th>Responses</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {forms_html}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        '''
        
        return html_wrapper('Forms Management', content, get_navbar(), '')
        
    except Exception as e:
        print(f"Admin forms error: {e}")
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/admin/test')
@admin_required
def admin_test():
    """Admin testing page to verify system functionality"""
    try:
        connection = get_db()
        
        # Test database connectivity
        db_status = "✅ Connected"
        try:
            with connection.cursor() as cursor:
                cursor.execute('SELECT 1')
                db_test = cursor.fetchone()
        except Exception as e:
            db_status = f"❌ Error: {str(e)}"
        
        # Test email functionality
        email_status = "✅ Ready"
        if not ENABLE_EMAIL_NOTIFICATIONS:
            email_status = "⚠️ Disabled (ENABLE_EMAIL_NOTIFICATIONS = False)"
        else:
            try:
                # Test email configuration
                with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
                    server.starttls()
                    server.login(EMAIL_USER, EMAIL_PASSWORD)
                    email_status = "✅ Configured correctly"
            except Exception as e:
                email_status = f"❌ Error: {str(e)}"
        
        # Test system tables
        tables_status = "✅ All tables exist"
        missing_tables = []
        required_tables = ['users', 'forms', 'form_requests', 'assignments', 'responses', 'student_form_reviews', 'notifications']
        
        with connection.cursor() as cursor:
            for table in required_tables:
                cursor.execute(f"SHOW TABLES LIKE '{table}'")
                if not cursor.fetchone():
                    missing_tables.append(table)
        
        if missing_tables:
            tables_status = f"❌ Missing tables: {', '.join(missing_tables)}"
        
        # Get system statistics
        stats = {}
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) as count FROM users')
            stats['users'] = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM forms')
            stats['forms'] = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM responses')
            stats['responses'] = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM notifications')
            stats['notifications'] = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(DISTINCT department) as count FROM users')
            stats['departments'] = cursor.fetchone()['count']
        
        connection.close()
        
        content = f'''
        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h3 class="mb-0">System Test & Diagnostics</h3>
                    </div>
                    <div class="card-body">
                        <h4>System Status</h4>
                        <table class="table table-bordered">
                            <tr>
                                <th width="30%">Database Connection</th>
                                <td>{db_status}</td>
                            </tr>
                            <tr>
                                <th>Email System</th>
                                <td>{email_status}</td>
                            </tr>
                            <tr>
                                <th>Database Tables</th>
                                <td>{tables_status}</td>
                            </tr>
                            <tr>
                                <th>Notifications System</th>
                                <td>✅ Integrated with all user actions</td>
                            </tr>
                        </table>
                        
                        <h4 class="mt-4">System Statistics</h4>
                        <div class="row">
                            <div class="col-md-2">
                                <div class="stat-card" style="background: linear-gradient(45deg, #667eea, #764ba2);">
                                    <h5>Total Users</h5>
                                    <h2>{stats['users']}</h2>
                                </div>
                            </div>
                            <div class="col-md-2">
                                <div class="stat-card" style="background: linear-gradient(45deg, #10b981, #059669);">
                                    <h5>Total Forms</h5>
                                    <h2>{stats['forms']}</h2>
                                </div>
                            </div>
                            <div class="col-md-2">
                                <div class="stat-card" style="background: linear-gradient(45deg, #3b82f6, #1d4ed8);">
                                    <h5>Total Responses</h5>
                                    <h2>{stats['responses']}</h2>
                                </div>
                            </div>
                            <div class="col-md-2">
                                <div class="stat-card" style="background: linear-gradient(45deg, #f59e0b, #d97706);">
                                    <h5>Notifications</h5>
                                    <h2>{stats['notifications']}</h2>
                                </div>
                            </div>
                            <div class="col-md-2">
                                <div class="stat-card" style="background: linear-gradient(45deg, #8b5cf6, #7c3aed);">
                                    <h5>Departments</h5>
                                    <h2>{stats['departments']}</h2>
                                </div>
                            </div>
                        </div>
                        
                        <h4 class="mt-4">Test Actions</h4>
                        <div class="row">
                            <div class="col-md-4">
                                <div class="card">
                                    <div class="card-body">
                                        <h5>Test Email System</h5>
                                        <p>Send a test email to verify email configuration.</p>
                                        <button onclick="sendTestEmail()" class="btn btn-primary">
                                            <i class="fas fa-envelope me-2"></i>Send Test Email
                                        </button>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="card">
                                    <div class="card-body">
                                        <h5>Test Notifications</h5>
                                        <p>Send a test notification to yourself.</p>
                                        <button onclick="sendTestNotification()" class="btn btn-warning">
                                            <i class="fas fa-bell me-2"></i>Test Notification
                                        </button>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="card">
                                    <div class="card-body">
                                        <h5>Database Repair</h5>
                                        <p>Reinitialize database tables if needed.</p>
                                        <button onclick="repairDatabase()" class="btn btn-danger">
                                            <i class="fas fa-database me-2"></i>Repair Database
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="mt-4">
                            <a href="/admin" class="btn btn-secondary">Back to Admin Panel</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        '''
        
        scripts = '''
        <script>
            function sendTestEmail() {
                fetch('/api/test-email', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'}
                })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        alert('Test email sent successfully! Check your inbox.');
                    } else {
                        alert('Error: ' + data.error);
                    }
                });
            }
            
            function sendTestNotification() {
                fetch('/api/test-notification', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'}
                })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        alert('Test notification sent successfully! Check your notification bell.');
                    } else {
                        alert('Error: ' + data.error);
                    }
                });
            }
            
            function repairDatabase() {
                if (confirm('This will recreate all database tables. Continue?')) {
                    fetch('/api/repair-database', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            alert('Database repaired successfully!');
                            window.location.reload();
                        } else {
                            alert('Error: ' + data.error);
                        }
                    });
                }
            }
        </script>
        '''
        
        return html_wrapper('System Test', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"Admin test error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

@app.route('/api/test-email', methods=['POST'])
@admin_required
def test_email():
    """Send a test email to verify email configuration"""
    try:
        html_content = f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #667eea;">Test Email from FormMaster Pro</h2>
            <p>Hello {session['name']},</p>
            <p>This is a test email to verify that the email notification system is working correctly.</p>
            <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 20px 0;">
                <p><strong>Test Details:</strong></p>
                <p>Recipient: {session['email']}</p>
                <p>Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>System: FormMaster Pro</p>
            </div>
            <p>If you received this email, the email notification system is configured correctly.</p>
            <hr>
            <p style="color: #666; font-size: 12px;">This is an automated test message from FormMaster Pro.</p>
        </div>
        '''
        
        success = send_email(session['email'], 'Test Email - FormMaster Pro', html_content)
        
        if success:
            return jsonify({'success': True, 'message': 'Test email sent successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to send test email'})
    except Exception as e:
        print(f"Test email error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/test-notification', methods=['POST'])
@admin_required
def test_notification():
    """Send a test notification"""
    try:
        success = create_notification(
            user_id=session['user_id'],
            title='Test Notification',
            message='This is a test notification to verify the notification system is working correctly.',
            type='info',
            link='/notifications'
        )
        
        if success:
            return jsonify({'success': True, 'message': 'Test notification sent successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to send test notification'})
    except Exception as e:
        print(f"Test notification error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/repair-database', methods=['POST'])
@admin_required
def repair_database():
    """Reinitialize database tables"""
    try:
        init_db()
        return jsonify({'success': True, 'message': 'Database repaired successfully'})
    except Exception as e:
        print(f"Repair database error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return html_wrapper('404', '<div class="alert alert-warning">Page not found</div>', get_navbar(), ''), 404

@app.errorhandler(500)
def server_error(e):
    return html_wrapper('500', '<div class="alert alert-danger">Server error</div>', get_navbar(), ''), 500

if __name__ == '__main__':
    # Initialize database
    print("=" * 60)
    print("FORM SYSTEM - Railway Deployment")
    print("=" * 60)
    
    # Get Railway environment
    railway_env = os.environ.get('RAILWAY_ENVIRONMENT', 'production')
    print(f"Environment: {railway_env}")
    
    # Test database connection
    conn = get_db_connection()
    if conn:
        print("✓ Database connection: SUCCESS")
        
        # Initialize tables
        init_db()
        conn.close()
    else:
        print("✗ Database connection: FAILED")
        print("Please check your Railway MySQL service is running")
    
    # Email configuration status
    if ENABLE_EMAIL_NOTIFICATIONS:
        if EMAIL_USER and EMAIL_PASSWORD:
            print(f"✓ Email Notifications: ENABLED")
            print(f"  Using: {EMAIL_USER}")
        else:
            print(f"⚠ Email Notifications: CONFIGURED but credentials missing")
            print(f"  Set EMAIL_USER and EMAIL_PASSWORD in Railway variables")
    else:
        print(f"✗ Email Notifications: DISABLED")
    
    
    
    if ENABLE_EMAIL_NOTIFICATIONS:
        print(f"✓ Email Notifications: ENABLED")
        print(f"  Email: {EMAIL_USER}")
    else:
        print(f"✗ Email Notifications: DISABLED (set ENABLE_EMAIL_NOTIFICATIONS = True to enable)")
    
    print("\n✓ Key Features Implemented:")
    print("  1. Department-based form segregation")
    print("  2. Dropdown department filters for admin/teacher")
    print("  3. Teacher-only access to their department forms")
    print("  4. Teacher analytics dashboard")
    print("  5. Student access limited to their department")
    print("  6. Department-wise statistics in all views")
    print("  7. Email notifications for all major transactions")
    print("  8. Real-time notifications system with bell icon")
    print("  9. Notification center with mark as read/delete")
    print(" 10. Automated notifications for all user actions")
    
    print("\n✓ Notification Triggers:")
    print("  - Login/Logout")
    print("  - Form creation/editing")
    print("  - Form submission/review")
    print("  - Request approval/rejection")
    print("  - Form assignment")
    print("  - Student form submission")
    print("  - Form approval/rejection by teachers")
    
    print("\n✓ Access Levels:")
    print("  - Admin: Full system access, all departments")
    print("  - Teacher: Limited to their department, full functionality")
    print("  - Student: Limited to their department, can request/respond to forms")
    
    print("\nStarting server...")
    print("Access at: http://localhost:5000")
    print("Admin Test: http://localhost:5000/admin/test")
    print("Teacher Analytics: http://localhost:5000/teacher-analytics")
    print("Notifications: http://localhost:5000/notifications")
    print("=" * 60)


    print("\nApplication ready!")
    print("=" * 60)
    
    # Get port from Railway environment
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)






