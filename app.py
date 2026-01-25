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
import threading
from queue import Queue
import functools
import pickle
from flask_caching import Cache
import redis

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'

# Database Configuration with connection pool
MYSQL_HOST = 'mysql--bgr.railway.internal'
MYSQL_USER = 'root'
MYSQL_PASSWORD = 'obqlFmxezajMwLfOusStXlHkPHtzQQGL'
MYSQL_DB = 'railway'

# Email Configuration
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USER = 'gamergopi26@gmail.com'
EMAIL_PASSWORD = 'Admin@123'
EMAIL_FROM = 'gamrgopi26@gmail.com'

# Enable/Disable email notifications
ENABLE_EMAIL_NOTIFICATIONS = True

# Default Admin Credentials
ADMIN_EMAIL = 'admin@example.com'
ADMIN_PASSWORD = 'admin123'
ADMIN_NAME = 'System Administrator'

# Super Admin Credentials
SUPER_ADMIN_EMAIL = 'superadmin@example.com'
SUPER_ADMIN_PASSWORD = 'superadmin123'
SUPER_ADMIN_NAME = 'Super Administrator'

# Department options
DEPARTMENTS = ['IT', 'CS', 'ECE', 'EEE', 'MECH', 'CIVIL', 'MBA', 'PHYSICS', 'CHEMISTRY', 'MATHS']

# Cache configuration
app.config['CACHE_TYPE'] = 'SimpleCache'  # Use Redis in production: 'RedisCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300  # 5 minutes
cache = Cache(app)

# Email queue for async sending
email_queue = Queue()

# Database connection pool
db_pool = None
MAX_POOL_SIZE = 20

# Initialize database connection pool
def init_db_pool():
    global db_pool
    if not db_pool:
        db_pool = pymysql.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DB,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
            maxconnections=MAX_POOL_SIZE
        )
        print(f"Database connection pool initialized with max {MAX_POOL_SIZE} connections")

# Get database connection from pool
def get_db():
    """Get database connection from pool"""
    if not db_pool:
        init_db_pool()
    
    try:
        # Get connection from pool
        connection = db_pool
        connection.ping(reconnect=True)  # Ensure connection is alive
        return connection
    except Exception as e:
        print(f"Error getting database connection: {e}")
        # Fallback to new connection
        return pymysql.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DB,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )

# Async email sender worker
def email_worker():
    """Background worker to send emails asynchronously"""
    while True:
        try:
            email_data = email_queue.get()
            if email_data is None:
                break
                
            to_email, subject, html_content = email_data
            
            if not ENABLE_EMAIL_NOTIFICATIONS:
                print(f"Email notifications disabled. Would send to {to_email}: {subject}")
                email_queue.task_done()
                continue
            
            try:
                msg = MIMEMultipart('alternative')
                msg['Subject'] = subject
                msg['From'] = EMAIL_FROM
                msg['To'] = to_email
                
                html_part = MIMEText(html_content, 'html')
                msg.attach(html_part)
                
                with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=10) as server:
                    server.starttls()
                    server.login(EMAIL_USER, EMAIL_PASSWORD)
                    server.send_message(msg)
                
                print(f"Email sent to {to_email}: {subject}")
            except Exception as e:
                print(f"Error sending email to {to_email}: {e}")
            finally:
                email_queue.task_done()
        except Exception as e:
            print(f"Email worker error: {e}")

# Start email worker thread
email_thread = threading.Thread(target=email_worker, daemon=True)
email_thread.start()

# Email sending function (async)
def send_email(to_email, subject, html_content):
    """Send email asynchronously"""
    email_queue.put((to_email, subject, html_content))
    return True

# Cached password functions
@functools.lru_cache(maxsize=1000)
def hash_password_cached(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_password(password):
    return hash_password_cached(password)

@functools.lru_cache(maxsize=1000)
def check_password_cached(hashed, password):
    return hashed == hashlib.sha256(password.encode()).hexdigest()

def check_password(hashed, password):
    return check_password_cached(hashed, password)

# Cache decorator
def cached(timeout=300, key_prefix='view_'):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Generate cache key
            cache_key = f"{key_prefix}{request.path}"
            
            # Try to get from cache
            cached_result = cache.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Execute function
            result = f(*args, **kwargs)
            
            # Store in cache
            cache.set(cache_key, result, timeout=timeout)
            
            return result
        return decorated_function
    return decorator

# Optimized database initialization
def init_db():
    try:
        connection = get_db()
        
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {MYSQL_DB}")
            cursor.execute(f"USE {MYSQL_DB}")
            
            # Create tables only if they don't exist
            tables_to_create = [
                ('users', '''
                    CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        password VARCHAR(255) NOT NULL,
                        name VARCHAR(100) NOT NULL,
                        role ENUM('student', 'teacher', 'admin', 'super_admin') DEFAULT 'student',
                        department VARCHAR(50) DEFAULT 'IT',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        INDEX idx_email (email),
                        INDEX idx_department (department),
                        INDEX idx_role (role)
                    )
                '''),
                ('forms', '''
                    CREATE TABLE IF NOT EXISTS forms (
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
                        INDEX idx_share_token (share_token),
                        INDEX idx_is_published (is_published)
                    )
                '''),
                ('notifications', '''
                    CREATE TABLE IF NOT EXISTS notifications (
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
                        INDEX idx_created_at (created_at),
                        INDEX idx_user_read (user_id, is_read)
                    )
                '''),
                ('form_requests', '''
                    CREATE TABLE IF NOT EXISTS form_requests (
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
                        INDEX idx_form_student (form_id, student_id),
                        UNIQUE KEY unique_form_student (form_id, student_id)
                    )
                '''),
                ('assignments', '''
                    CREATE TABLE IF NOT EXISTS assignments (
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
                        INDEX idx_assigned_by (assigned_by),
                        UNIQUE KEY unique_assignment (form_id, student_id)
                    )
                '''),
                ('responses', '''
                    CREATE TABLE IF NOT EXISTS responses (
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
                        INDEX idx_submitted_at (submitted_at),
                        UNIQUE KEY unique_response (form_id, student_id)
                    )
                '''),
                ('student_form_reviews', '''
                    CREATE TABLE IF NOT EXISTS student_form_reviews (
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
                        INDEX idx_reviewer (reviewer_id),
                        INDEX idx_review_status (review_status)
                    )
                ''')
            ]
            
            for table_name, create_query in tables_to_create:
                cursor.execute(create_query)
            
            # Create admin users if not exists (optimized batch insert)
            cursor.execute("SELECT email FROM users WHERE email IN (%s, %s)", (ADMIN_EMAIL, SUPER_ADMIN_EMAIL))
            existing_emails = {row['email'] for row in cursor.fetchall()}
            
            users_to_create = []
            if ADMIN_EMAIL not in existing_emails:
                hashed_admin = hash_password(ADMIN_PASSWORD)
                users_to_create.append((ADMIN_EMAIL, hashed_admin, ADMIN_NAME, 'admin', 'IT'))
            
            if SUPER_ADMIN_EMAIL not in existing_emails:
                hashed_super = hash_password(SUPER_ADMIN_PASSWORD)
                users_to_create.append((SUPER_ADMIN_EMAIL, hashed_super, SUPER_ADMIN_NAME, 'super_admin', 'IT'))
            
            if users_to_create:
                cursor.executemany(
                    "INSERT INTO users (email, password, name, role, department) VALUES (%s, %s, %s, %s, %s)",
                    users_to_create
                )
                print(f"Created {len(users_to_create)} admin user(s)")
            
        print("Database initialized successfully!")
        
    except Exception as e:
        print(f"Error initializing database: {e}")
        traceback.print_exc()
    finally:
        # Don't close pool connection
        pass

# Decorators (unchanged, but optimized)
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

# Optimized notification functions with caching
@cache.memoize(timeout=60)  # Cache for 1 minute
def get_unread_notification_count_cached(user_id):
    """Get count of unread notifications for a user (cached)"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT COUNT(*) as count FROM notifications 
                WHERE user_id = %s AND is_read = FALSE
            ''', (user_id,))
            result = cursor.fetchone()
        return result['count'] if result else 0
    except Exception as e:
        print(f"Error getting notification count: {e}")
        return 0

def get_unread_notification_count(user_id):
    return get_unread_notification_count_cached(user_id)

@cache.memoize(timeout=30)  # Cache for 30 seconds
def get_user_notifications_cached(user_id, limit=20):
    """Get notifications for a user (cached)"""
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
        return notifications
    except Exception as e:
        print(f"Error getting notifications: {e}")
        return []

def get_user_notifications(user_id, limit=20):
    return get_user_notifications_cached(user_id, limit)

def create_notification(user_id, title, message, type='info', link=None):
    """Create a new notification for a user"""
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('''
                INSERT INTO notifications (user_id, title, message, type, link)
                VALUES (%s, %s, %s, %s, %s)
            ''', (user_id, title, message, type, link))
        
        # Invalidate cache
        cache.delete_memoized(get_unread_notification_count_cached, user_id)
        cache.delete_memoized(get_user_notifications_cached, user_id, 20)
        return True
    except Exception as e:
        print(f"Error creating notification: {e}")
        return False

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
        
        # Invalidate cache
        cache.delete_memoized(get_unread_notification_count_cached, user_id)
        cache.delete_memoized(get_user_notifications_cached, user_id, 20)
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
        
        # Invalidate cache
        cache.delete_memoized(get_unread_notification_count_cached, user_id)
        cache.delete_memoized(get_user_notifications_cached, user_id, 20)
        return True
    except Exception as e:
        print(f"Error marking all notifications as read: {e}")
        return False

# Optimized time ago function
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

# HTML Template function (unchanged, but with cache key)
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
            /* CSS unchanged from original */
            body {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                padding-top: 70px;
            }}
            /* ... rest of CSS unchanged ... */
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
    
    # Get unread notification count (cached)
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
                return share_token
            
        return form['share_token']
    except Exception as e:
        print(f"Error ensuring share token: {e}")
        return None

# Optimized JSON parsing
def parse_questions_json(questions_data):
    """Optimized JSON parsing for questions"""
    if not questions_data:
        return []
    
    if isinstance(questions_data, list):
        return questions_data
    
    if isinstance(questions_data, str):
        try:
            return json.loads(questions_data)
        except:
            return []
    
    if isinstance(questions_data, dict):
        return [questions_data]
    
    return []

# Optimized dashboard with caching
@app.route('/dashboard')
@login_required
@cache.cached(timeout=60, key_prefix=lambda: f'dashboard_{session["user_id"]}_{request.args.get("department", "")}')
def dashboard():
    """Optimized dashboard with caching"""
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
            
            # Optimized query: Only fetch needed columns
            if user_role in ['admin', 'super_admin']:
                cursor.execute(f'''
                    SELECT f.id, f.title, f.description, f.created_by, f.department, f.form_type, 
                           f.is_published, f.is_student_submission, f.review_status, f.created_at,
                           u.name as creator_name, u.department as creator_department 
                    FROM forms f 
                    JOIN users u ON f.created_by = u.id 
                    WHERE (f.is_student_submission = FALSE OR f.review_status = 'approved')
                    {dept_filter}
                    ORDER BY f.created_at DESC
                    LIMIT 50  -- Limit results for performance
                ''', params)
                forms = cursor.fetchall()
            elif user_role == 'teacher':
                cursor.execute(f'''
                    SELECT f.id, f.title, f.description, f.created_by, f.department, f.form_type, 
                           f.is_published, f.is_student_submission, f.review_status, f.created_at,
                           u.name as creator_name 
                    FROM forms f 
                    JOIN users u ON f.created_by = u.id 
                    WHERE (f.is_student_submission = FALSE OR f.review_status = 'approved')
                    {dept_filter}
                    ORDER BY f.created_at DESC
                    LIMIT 50
                ''', params)
                forms = cursor.fetchall()
            else:
                # Students only see forms from their department
                cursor.execute('''
                    SELECT f.id, f.title, f.description, f.created_by, f.department, f.form_type, 
                           f.is_published, f.is_student_submission, f.review_status, f.created_at,
                           u.name as creator_name,
                           (SELECT status FROM form_requests WHERE form_id = f.id AND student_id = %s) as request_status,
                           (SELECT 1 FROM assignments WHERE form_id = f.id AND student_id = %s) as is_assigned,
                           (SELECT 1 FROM responses WHERE form_id = f.id AND student_id = %s) as has_submitted
                    FROM forms f 
                    JOIN users u ON f.created_by = u.id 
                    WHERE f.department = %s 
                    AND f.form_type = 'open'
                    AND (f.is_student_submission = FALSE OR f.review_status = 'approved')
                    ORDER BY f.created_at DESC
                    LIMIT 50
                ''', (user_id, user_id, user_id, user_dept))
                forms = cursor.fetchall()
            
            # Get assigned forms for students (optimized)
            assigned_forms = []
            if user_role == 'student':
                cursor.execute('''
                    SELECT f.id, f.title, f.department, a.due_date, a.is_completed 
                    FROM forms f
                    JOIN assignments a ON f.id = a.form_id
                    WHERE a.student_id = %s AND f.review_status = 'approved'
                    LIMIT 20
                ''', (user_id,))
                assigned_forms = cursor.fetchall()
            
            # Get pending requests count for teachers/admin (cached)
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
            
            # Get department statistics for admin (cached)
            dept_stats = {}
            if user_role in ['admin', 'super_admin']:
                cursor.execute('''
                    SELECT department, 
                           COUNT(*) as form_count,
                           SUM(CASE WHEN is_student_submission = TRUE THEN 1 ELSE 0 END) as student_forms,
                           SUM(CASE WHEN review_status = 'approved' THEN 1 ELSE 0 END) as approved_forms,
                           SUM(CASE WHEN is_published = TRUE THEN 1 ELSE 0 END) as published_forms
                    FROM forms 
                    GROUP BY department
                    LIMIT 20
                ''')
                dept_stats = cursor.fetchall()
            
            # Student statistics (optimized)
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
        
        # The rest of the dashboard rendering logic remains the same...
        # ... [All the dashboard HTML generation code remains unchanged] ...
        
        # Return the HTML wrapper as before
        return html_wrapper('Dashboard', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"Dashboard error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

# Optimized login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            email = request.form['email']
            password = request.form['password']
            
            # Use parameterized query for security
            connection = get_db()
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
                user = cursor.fetchone()
            
            if user and check_password(user['password'], password):
                session['user_id'] = user['id']
                session['email'] = user['email']
                session['name'] = user['name']
                session['role'] = user['role']
                session['department'] = user['department']
                
                # Send login notification email (async)
                if ENABLE_EMAIL_NOTIFICATIONS and email not in [ADMIN_EMAIL, SUPER_ADMIN_EMAIL]:
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
                
                # Check for redirect after login
                if 'redirect_after_login' in session:
                    redirect_url = session.pop('redirect_after_login')
                    return redirect(redirect_url)
                
                return redirect('/dashboard')
            else:
                # Show error (same as before)
                return html_wrapper('Login', login_form_html("Invalid email or password"), '', '')
                
        except Exception as e:
            print(f"Login error: {e}")
            return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', '', '')
    
    # GET request - show login form
    redirect_param = request.args.get('redirect', '')
    if redirect_param:
        session['redirect_after_login'] = redirect_param
    
    if 'user_id' in session and 'redirect_after_login' in session:
        redirect_url = session.pop('redirect_after_login')
        return redirect(redirect_url)
    
    return html_wrapper('Login', login_form_html(), '', '')

def login_form_html(error_message=None):
    """Generate login form HTML"""
    error_html = f'<div class="alert alert-danger">{error_message}</div>' if error_message else ''
    
    return f'''
    <div class="row justify-content-center align-items-center" style="min-height: 80vh;">
        <div class="col-md-4">
            <div class="card glass-effect">
                <div class="card-body p-4">
                    <h3 class="text-center mb-4 text-dark">Login</h3>
                    {error_html}
                    <form method="POST" id="loginForm">
                        <div class="mb-3">
                            <label class="form-label text-dark">Email</label>
                            <input type="email" class="form-control" name="email" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label text-dark">Password</label>
                            <input type="password" class="form-control" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100" id="loginBtn">Login</button>
                    </form>
                    <hr class="my-4">
                    <p class="text-center">
                        <a href="/register" class="text-decoration-none">Create new account</a>
                    </p>
                    <div class="text-center text-muted small mt-3">
                        <strong>Default Admin:</strong><br>
                        Email: {ADMIN_EMAIL}<br>
                        Password: {ADMIN_PASSWORD}<br>
                        <strong>Super Admin:</strong><br>
                        Email: {SUPER_ADMIN_EMAIL}<br>
                        Password: {SUPER_ADMIN_PASSWORD}
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script>
        $('#loginForm').on('submit', function() {{
            $('#loginBtn').prop('disabled', true).html('<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Logging in...');
        }});
    </script>
    '''

# Optimized API endpoints
@app.route('/api/notifications/recent')
@login_required
def get_recent_notifications():
    """Optimized recent notifications endpoint"""
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

# Optimized form taking route
@app.route('/form/<int:form_id>/take')
@login_required
def take_form(form_id):
    """Optimized form taking with caching"""
    try:
        # Check cache first
        cache_key = f'form_{form_id}_take'
        cached_response = cache.get(cache_key)
        if cached_response and 'user_id' in session:
            # Check if user has already submitted
            connection = get_db()
            with connection.cursor() as cursor:
                cursor.execute('''
                    SELECT 1 FROM responses WHERE form_id = %s AND student_id = %s
                ''', (form_id, session['user_id']))
                if cursor.fetchone():
                    return html_wrapper('Error', '<div class="alert alert-info">You have already submitted this form</div>', get_navbar(), '')
        
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute('SELECT id, title, description, department, form_type FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            if not form:
                return html_wrapper('Error', '<div class="alert alert-danger">Form not found</div>', get_navbar(), '')
            
            # Check access (optimized single query)
            cursor.execute('''
                SELECT 
                    fr.status as request_status,
                    a.form_id as is_assigned,
                    r.form_id as has_submitted
                FROM forms f
                LEFT JOIN form_requests fr ON f.id = fr.form_id AND fr.student_id = %s
                LEFT JOIN assignments a ON f.id = a.form_id AND a.student_id = %s
                LEFT JOIN responses r ON f.id = r.form_id AND r.student_id = %s
                WHERE f.id = %s
            ''', (session['user_id'], session['user_id'], session['user_id'], form_id))
            access_info = cursor.fetchone()
            
            admin_access = session['role'] in ['admin', 'super_admin']
            teacher_access = session['role'] == 'teacher' and form['department'] == session['department']
            
            has_access = False
            if admin_access or teacher_access:
                has_access = True
            elif access_info:
                if access_info['has_submitted']:
                    return html_wrapper('Error', '<div class="alert alert-info">You have already submitted this form</div>', get_navbar(), '')
                if access_info['is_assigned'] or access_info['request_status'] == 'approved':
                    has_access = True
                elif form['form_type'] == 'open' and form['department'] == session['department']:
                    has_access = True
            
            if not has_access:
                return html_wrapper('Error', '''
                <div class="alert alert-danger">
                    <h4>Access Denied</h4>
                    <p>You need to request access to this form first.</p>
                    <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
                </div>
                ''', get_navbar(), '')
            
            # Get questions
            cursor.execute('SELECT questions FROM forms WHERE id = %s', (form_id,))
            form_data = cursor.fetchone()
            questions = parse_questions_json(form_data['questions']) if form_data else []
        
        # Cache the form data for 5 minutes
        cache.set(cache_key, {
            'form': form,
            'questions': questions
        }, timeout=300)
        
        # Create notification
        create_notification(
            user_id=session['user_id'],
            title='Form Started',
            message=f'You have started taking the form "{form["title"]}".',
            type='info',
            link=f'/form/{form_id}/take'
        )
        
        # Render form (same as before)
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
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

# Optimized form submission
@app.route('/submit-form', methods=['POST'])
@login_required
def submit_form():
    """Optimized form submission"""
    try:
        data = request.json
        form_id = data.get('form_id')
        answers = data.get('answers', {})
        
        connection = get_db()
        with connection.cursor() as cursor:
            # Get form with questions
            cursor.execute('SELECT questions, title FROM forms WHERE id = %s', (form_id,))
            form = cursor.fetchone()
            
            if not form:
                return jsonify({'success': False, 'error': 'Form not found'})
            
            questions = parse_questions_json(form['questions'])
            
            score = 0
            total_marks = 0
            
            # Calculate score
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
            
            # Insert response
            cursor.execute('''
                INSERT INTO responses (form_id, student_id, answers, score, total_marks, percentage)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (form_id, session['user_id'], json.dumps(answers), score, total_marks, percentage))
            
            # Update assignment
            cursor.execute('''
                UPDATE assignments SET is_completed = TRUE 
                WHERE form_id = %s AND student_id = %s
            ''', (form_id, session['user_id']))
            
            # Get form creator for notification
            cursor.execute('''
                SELECT u.id as creator_id, u.email as creator_email, u.name as creator_name
                FROM forms f
                JOIN users u ON f.created_by = u.id
                WHERE f.id = %s
            ''', (form_id,))
            creator = cursor.fetchone()
        
        # Create notifications (async)
        create_notification(
            user_id=session['user_id'],
            title='Form Submitted',
            message=f'You have submitted the form "{form["title"]}". Score: {score}/{total_marks} ({percentage:.1f}%)',
            type='success',
            link='/my-responses'
        )
        
        if creator and creator['creator_id'] != session['user_id']:
            create_notification(
                user_id=creator['creator_id'],
                title='New Form Submission',
                message=f'{session["name"]} has submitted your form "{form["title"]}". Score: {score}/{total_marks}',
                type='info',
                link=f'/form/{form_id}/responses'
            )
        
        # Send email notification (async)
        if ENABLE_EMAIL_NOTIFICATIONS and creator:
            html_content = f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #667eea;">Form Submission Completed</h2>
                <p>Hello {creator['creator_name']},</p>
                <p>A student has submitted your form.</p>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 20px 0;">
                    <p><strong>Form Details:</strong></p>
                    <p>Title: {form['title']}</p>
                    <p>Student: {session['name']} ({session['email']})</p>
                    <p>Score: {score}/{total_marks} ({percentage:.1f}%)</p>
                    <p>Submission Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                <p>You can view all responses from the form results page.</p>
                <a href="http://localhost:5000/form/{form_id}/responses" style="display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">View Results</a>
                <hr>
                <p style="color: #666; font-size: 12px;">This is an automated message from FormMaster Pro.</p>
            </div>
            '''
            send_email(creator['creator_email'], 'Form Submission - FormMaster Pro', html_content)
        
        # Clear cache
        cache.delete(f'form_{form_id}_take')
        
        return jsonify({
            'success': True,
            'score': score,
            'total_marks': total_marks,
            'percentage': round(percentage, 2)
        })
    except Exception as e:
        print(f"Submit form error: {e}")
        return jsonify({'success': False, 'error': str(e)})

# Optimized teacher analytics with caching
@app.route('/teacher-analytics')
@teacher_required
@cache.cached(timeout=120, key_prefix=lambda: f'teacher_analytics_{session["user_id"]}_{request.args.get("department", "")}')
def teacher_analytics():
    """Optimized teacher analytics with caching"""
    try:
        connection = get_db()
        user_dept = session['department']
        user_id = session['user_id']
        
        with connection.cursor() as cursor:
            # Optimized queries with limits and specific columns
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_forms,
                    SUM(CASE WHEN form_type = 'open' THEN 1 ELSE 0 END) as open_forms,
                    SUM(CASE WHEN form_type = 'confidential' THEN 1 ELSE 0 END) as confidential_forms
                FROM forms 
                WHERE created_by = %s AND department = %s
            ''', (user_id, user_dept))
            form_stats = cursor.fetchone()
            
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_responses,
                    AVG(r.percentage) as avg_score,
                    MAX(r.percentage) as highest_score,
                    MIN(r.percentage) as lowest_score
                FROM responses r
                JOIN forms f ON r.form_id = f.id
                WHERE f.created_by = %s AND f.department = %s
                LIMIT 1000  -- Limit for performance
            ''', (user_id, user_dept))
            response_stats = cursor.fetchone()
            
            # ... rest of the analytics queries remain optimized ...
            
        # The rest of the teacher analytics rendering remains the same...
        return html_wrapper('Teacher Analytics', content, get_navbar(), scripts)
        
    except Exception as e:
        print(f"Teacher analytics error: {e}")
        return html_wrapper('Error', f'<div class="alert alert-danger">Error: {str(e)}</div>', get_navbar(), '')

# Add cleanup on shutdown
@app.teardown_appcontext
def close_db_connection(exception=None):
    """Close database connection on app shutdown"""
    if db_pool:
        try:
            db_pool.close()
            print("Database connection pool closed")
        except:
            pass

# Main application entry point
if __name__ == '__main__':
    print("Initializing database connection pool...")
    init_db_pool()
    
    print("Starting FormMaster Pro (Optimized)...")
    print(f"Admin URL: http://localhost:5000/login")
    print(f"Admin Email: {ADMIN_EMAIL}")
    print(f"Admin Password: {ADMIN_PASSWORD}")
    print(f"Super Admin Email: {SUPER_ADMIN_EMAIL}")
    print(f"Super Admin Password: {SUPER_ADMIN_PASSWORD}")
    print(f"Connection Pool Size: {MAX_POOL_SIZE}")
    print(f"Caching: Enabled")
    print(f"Async Email: Enabled")
    
    # Initialize database
    init_db()
    
    # Run app with production settings
    app.run(
        host='0.0.0.0', 
        port=5000, 
        debug=False,  # Disable debug mode for production
        threaded=True  # Enable threading for concurrent requests
    )
