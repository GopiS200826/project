from flask import Flask, request, jsonify, redirect, flash, session
import json
import sqlite3
import os
import hashlib
from functools import wraps
import traceback

app = Flask(__name__)
app.secret_key = 'super-secret-key-12345-change-this-in-production'

# Initialize database
def init_db():
    conn = sqlite3.connect('forms.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 email TEXT UNIQUE NOT NULL,
                 password TEXT NOT NULL,
                 name TEXT NOT NULL,
                 role TEXT DEFAULT 'student',
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Forms table
    c.execute('''CREATE TABLE IF NOT EXISTS forms (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 title TEXT NOT NULL,
                 description TEXT,
                 created_by INTEGER NOT NULL,
                 questions TEXT DEFAULT '[]',
                 is_published BOOLEAN DEFAULT 0,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Assignments table
    c.execute('''CREATE TABLE IF NOT EXISTS assignments (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 form_id INTEGER NOT NULL,
                 student_id INTEGER NOT NULL,
                 assigned_by INTEGER NOT NULL,
                 assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 due_date TEXT,
                 is_completed BOOLEAN DEFAULT 0)''')
    
    # Responses table
    c.execute('''CREATE TABLE IF NOT EXISTS responses (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 form_id INTEGER NOT NULL,
                 student_id INTEGER NOT NULL,
                 answers TEXT NOT NULL,
                 score REAL DEFAULT 0,
                 total_marks REAL DEFAULT 0,
                 percentage REAL DEFAULT 0,
                 submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 time_taken INTEGER)''')
    
    # Create admin user
    c.execute("SELECT * FROM users WHERE email = 'admin@form.com'")
    if not c.fetchone():
        hashed = hashlib.sha256('admin123'.encode()).hexdigest()
        c.execute("INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, 'admin')",
                  ('admin@form.com', hashed, 'Admin User'))
    
    conn.commit()
    conn.close()

# Database connection
def get_db():
    conn = sqlite3.connect('forms.db')
    conn.row_factory = sqlite3.Row
    return conn

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
            return '<script>alert("Teacher access required"); window.location.href = "/dashboard";</script>'
        return f(*args, **kwargs)
    return decorated_function

# HTML Templates
def html_wrapper(title, content):
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>{title} - Form System</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            body {{ background: #f8f9fa; font-family: Arial, sans-serif; }}
            .navbar {{ background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,.1); }}
            .card {{ border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,.1); margin-bottom: 20px; }}
            .btn-primary {{ background: #4a6bff; border: none; }}
            .btn-primary:hover {{ background: #3a5bef; }}
            .question-card {{ border-left: 4px solid #4a6bff; }}
            .badge-success {{ background: #28a745; }}
            .badge-warning {{ background: #ffc107; }}
            .badge-danger {{ background: #dc3545; }}
        </style>
    </head>
    <body>
        {content}
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    '''

def navbar():
    if 'user_id' in session:
        return f'''
        <nav class="navbar navbar-expand-lg navbar-light">
            <div class="container">
                <a class="navbar-brand text-primary fw-bold" href="/dashboard">
                    <i class="fas fa-poll me-2"></i>FormMaster
                </a>
                <div class="dropdown">
                    <button class="btn btn-outline-primary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                        <i class="fas fa-user me-2"></i>{session['name']}
                        <span class="badge bg-primary ms-2">{session['role']}</span>
                    </button>
                    <ul class="dropdown-menu">
                        <li><a class="dropdown-item" href="/dashboard">Dashboard</a></li>
                        <li><a class="dropdown-item text-danger" href="/logout">Logout</a></li>
                    </ul>
                </div>
            </div>
        </nav>
        '''
    else:
        return '''
        <nav class="navbar navbar-light">
            <div class="container">
                <a class="navbar-brand text-primary fw-bold" href="/">
                    <i class="fas fa-poll me-2"></i>FormMaster
                </a>
            </div>
        </nav>
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
            
            conn = get_db()
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            conn.close()
            
            if user and check_password(user['password'], password):
                session['user_id'] = user['id']
                session['email'] = user['email']
                session['name'] = user['name']
                session['role'] = user['role']
                return redirect('/dashboard')
            else:
                return html_wrapper('Login', navbar() + '''
                <div class="container mt-5">
                    <div class="row justify-content-center">
                        <div class="col-md-4">
                            <div class="card shadow">
                                <div class="card-body">
                                    <h3 class="text-center mb-4">Login</h3>
                                    <div class="alert alert-danger">Invalid email or password</div>
                                    <form method="POST">
                                        <div class="mb-3">
                                            <label>Email</label>
                                            <input type="email" class="form-control" name="email" required>
                                        </div>
                                        <div class="mb-3">
                                            <label>Password</label>
                                            <input type="password" class="form-control" name="password" required>
                                        </div>
                                        <button type="submit" class="btn btn-primary w-100">Login</button>
                                    </form>
                                    <hr>
                                    <p class="text-center">
                                        <a href="/register">Create new account</a>
                                    </p>
                                    <div class="text-center text-muted small">
                                        Admin: admin@form.com / admin123
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                ''')
        except Exception as e:
            print(f"Login error: {e}")
            traceback.print_exc()
            return html_wrapper('Error', f'<div class="container mt-5"><div class="alert alert-danger">Error: {str(e)}</div></div>')
    
    return html_wrapper('Login', navbar() + '''
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-4">
                <div class="card shadow">
                    <div class="card-body">
                        <h3 class="text-center mb-4">Login</h3>
                        <form method="POST">
                            <div class="mb-3">
                                <label>Email</label>
                                <input type="email" class="form-control" name="email" required>
                            </div>
                            <div class="mb-3">
                                <label>Password</label>
                                <input type="password" class="form-control" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Login</button>
                        </form>
                        <hr>
                        <p class="text-center">
                            <a href="/register">Create new account</a>
                        </p>
                        <div class="text-center text-muted small">
                            Admin: admin@form.com / admin123
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    ''')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            name = request.form['name']
            email = request.form['email']
            password = request.form['password']
            role = request.form.get('role', 'student')
            
            hashed = hash_password(password)
            conn = get_db()
            
            try:
                conn.execute('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
                            (name, email, hashed, role))
                conn.commit()
                
                user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
                conn.close()
                
                session['user_id'] = user['id']
                session['email'] = user['email']
                session['name'] = user['name']
                session['role'] = user['role']
                
                return redirect('/dashboard')
            except sqlite3.IntegrityError:
                conn.close()
                return html_wrapper('Register', navbar() + '''
                <div class="container mt-5">
                    <div class="row justify-content-center">
                        <div class="col-md-4">
                            <div class="card shadow">
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
                </div>
                ''')
        except Exception as e:
            print(f"Register error: {e}")
            traceback.print_exc()
            return html_wrapper('Error', f'<div class="container mt-5"><div class="alert alert-danger">Error: {str(e)}</div></div>')
    
    return html_wrapper('Register', navbar() + '''
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-4">
                <div class="card shadow">
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
    </div>
    ''')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        conn = get_db()
        
        # Get user's forms
        if session['role'] in ['teacher', 'admin']:
            forms = conn.execute('SELECT * FROM forms WHERE created_by = ? ORDER BY created_at DESC', 
                               (session['user_id'],)).fetchall()
        else:
            forms = conn.execute('SELECT * FROM forms WHERE created_by = ? ORDER BY created_at DESC', 
                               (session['user_id'],)).fetchall()
        
        # Get assigned forms for students
        assigned_forms = []
        if session['role'] == 'student':
            assigned_forms = conn.execute('''
                SELECT f.*, a.due_date, a.is_completed 
                FROM forms f
                JOIN assignments a ON f.id = a.form_id
                WHERE a.student_id = ?
            ''', (session['user_id'],)).fetchall()
        
        conn.close()
        
        # Render forms
        forms_html = '<div class="list-group">'
        for form in forms:
            status = 'Published' if form['is_published'] else 'Draft'
            badge_class = 'badge-success' if form['is_published'] else 'badge-warning'
            
            forms_html += f'''
            <div class="list-group-item">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h6 class="mb-1">{form['title']}</h6>
                        <p class="mb-1 text-muted small">{form['description'][:50] if form['description'] else 'No description'}...</p>
                    </div>
                    <span class="badge {badge_class}">{status}</span>
                </div>
                <div class="mt-2">
                    <a href="/form/{form['id']}/edit" class="btn btn-sm btn-outline-primary">
                        <i class="fas fa-edit"></i> Edit
                    </a>
                    <a href="/form/{form['id']}/responses" class="btn btn-sm btn-outline-success">
                        <i class="fas fa-chart-bar"></i> Results
                    </a>
            '''
            
            if session.get('role') in ['teacher', 'admin']:
                forms_html += f'''
                    <a href="/form/{form['id']}/assign" class="btn btn-sm btn-outline-warning">
                        <i class="fas fa-user-plus"></i> Assign
                    </a>
                '''
            
            forms_html += '''
                </div>
            </div>
            '''
        forms_html += '</div>'
        
        if not forms:
            forms_html = '<p class="text-muted">No forms created yet.</p>'
        
        # Render assigned forms
        assigned_html = '<div class="list-group">'
        for form in assigned_forms:
            status = 'Completed' if form['is_completed'] else 'Pending'
            badge_class = 'badge-success' if form['is_completed'] else 'badge-danger'
            
            assigned_html += f'''
            <div class="list-group-item">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h6 class="mb-1">{form['title']}</h6>
                    </div>
                    <span class="badge {badge_class}">{status}</span>
                </div>
                <div class="mt-2">
            '''
            
            if not form['is_completed']:
                assigned_html += f'''
                    <a href="/form/{form['id']}/take" class="btn btn-sm btn-primary">
                        <i class="fas fa-play"></i> Start
                    </a>
                '''
            else:
                assigned_html += '<span class="text-success"><i class="fas fa-check"></i> Submitted</span>'
            
            assigned_html += '''
                </div>
            </div>
            '''
        assigned_html += '</div>'
        
        if not assigned_forms:
            assigned_html = '<p class="text-muted">No assigned forms.</p>'
        
        # Build dashboard
        assigned_section = ''
        col_width = '12'
        if session['role'] == 'student':
            col_width = '6'
            assigned_section = f'''
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5 class="mb-0">Assigned Forms ({len(assigned_forms)})</h5>
                    </div>
                    <div class="card-body">
                        {assigned_html}
                    </div>
                </div>
            </div>
            '''
        
        dashboard_content = navbar() + f'''
        <div class="container mt-4">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2>Welcome, {session['name']}!</h2>
                <a href="/create-form" class="btn btn-primary">
                    <i class="fas fa-plus me-2"></i>Create Form
                </a>
            </div>

            <div class="row">
                <div class="col-md-{col_width}">
                    <div class="card mb-4">
                        <div class="card-header">
                            <h5 class="mb-0">My Forms ({len(forms)})</h5>
                        </div>
                        <div class="card-body">
                            {forms_html}
                        </div>
                    </div>
                </div>
                {assigned_section}
            </div>
        </div>
        '''
        
        return html_wrapper('Dashboard', dashboard_content)
        
    except Exception as e:
        print(f"Dashboard error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="container mt-5"><div class="alert alert-danger">Error: {str(e)}</div></div>')

@app.route('/create-form', methods=['GET', 'POST'])
@login_required
def create_form():
    if request.method == 'POST':
        try:
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            
            if not title:
                return html_wrapper('Create Form', navbar() + '''
                <div class="container mt-5">
                    <div class="alert alert-danger">Title is required</div>
                    <a href="/create-form" class="btn btn-secondary">Go Back</a>
                </div>
                ''')
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO forms (title, description, created_by, questions) 
                VALUES (?, ?, ?, ?)
            ''', (title, description, session['user_id'], '[]'))
            form_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return redirect(f'/form/{form_id}/edit')
            
        except Exception as e:
            print(f"Create form error: {e}")
            traceback.print_exc()
            return html_wrapper('Error', f'<div class="container mt-5"><div class="alert alert-danger">Error: {str(e)}</div></div>')
    
    return html_wrapper('Create Form', navbar() + '''
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card shadow">
                    <div class="card-body">
                        <h3 class="text-center mb-4">Create New Form</h3>
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
                            <div class="d-flex gap-2">
                                <a href="/dashboard" class="btn btn-secondary">Cancel</a>
                                <button type="submit" class="btn btn-primary">Create Form</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    ''')

@app.route('/form/<int:form_id>/edit')
@login_required
def edit_form(form_id):
    try:
        conn = get_db()
        form = conn.execute('SELECT * FROM forms WHERE id = ?', (form_id,)).fetchone()
        conn.close()
        
        if not form:
            return redirect('/dashboard')
        
        if form['created_by'] != session['user_id'] and session['role'] not in ['teacher', 'admin']:
            return html_wrapper('Error', navbar() + '''
            <div class="container mt-5">
                <div class="alert alert-danger">Access denied</div>
                <a href="/dashboard" class="btn btn-secondary">Go Back</a>
            </div>
            ''')
        
        questions = form['questions'] if form['questions'] else '[]'
        
        content = navbar() + f'''
        <div class="container mt-4">
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
                            <h4 class="mb-0">Editing: {form['title']}</h4>
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
        </div>
        
        <script>
            let questions = {questions};
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
        
        return html_wrapper('Edit Form', content)
        
    except Exception as e:
        print(f"Edit form error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="container mt-5"><div class="alert alert-danger">Error: {str(e)}</div></div>')

@app.route('/api/form/<int:form_id>', methods=['POST'])
@login_required
def update_form(form_id):
    try:
        data = request.json
        questions = data.get('questions', [])
        
        conn = get_db()
        conn.execute('UPDATE forms SET questions = ? WHERE id = ?', 
                    (json.dumps(questions), form_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Update form error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/form/<int:form_id>/assign', methods=['GET', 'POST'])
@teacher_required
def assign_form(form_id):
    try:
        conn = get_db()
        
        if request.method == 'POST':
            student_id = request.form.get('student_id')
            due_date = request.form.get('due_date')
            
            if student_id:
                conn.execute('''
                    INSERT INTO assignments (form_id, student_id, assigned_by, due_date)
                    VALUES (?, ?, ?, ?)
                ''', (form_id, student_id, session['user_id'], due_date))
                conn.commit()
        
        form = conn.execute('SELECT * FROM forms WHERE id = ?', (form_id,)).fetchone()
        students = conn.execute('SELECT * FROM users WHERE role = "student"').fetchall()
        conn.close()
        
        if not form:
            return redirect('/dashboard')
        
        students_options = ''.join([
            f'<option value="{s["id"]}">{s["name"]} ({s["email"]})</option>' 
            for s in students
        ])
        
        content = navbar() + f'''
        <div class="container mt-5">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card shadow">
                        <div class="card-body">
                            <h3 class="text-center mb-4">Assign Form: {form['title']}</h3>
                            <form method="POST">
                                <div class="mb-3">
                                    <label class="form-label">Select Student</label>
                                    <select class="form-select" name="student_id" required>
                                        <option value="">Choose student...</option>
                                        {students_options}
                                    </select>
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
        </div>
        '''
        
        return html_wrapper('Assign Form', content)
        
    except Exception as e:
        print(f"Assign form error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="container mt-5"><div class="alert alert-danger">Error: {str(e)}</div></div>')

@app.route('/form/<int:form_id>/take')
@login_required
def take_form(form_id):
    try:
        conn = get_db()
        
        # Check if student is assigned
        if session['role'] == 'student':
            assignment = conn.execute('''
                SELECT 1 FROM assignments WHERE form_id = ? AND student_id = ?
            ''', (form_id, session['user_id'])).fetchone()
            
            if not assignment:
                return html_wrapper('Error', navbar() + '''
                <div class="container mt-5">
                    <div class="alert alert-danger">Form not assigned to you</div>
                    <a href="/dashboard" class="btn btn-secondary">Go Back</a>
                </div>
                ''')
        
        # Check if already submitted
        response = conn.execute('''
            SELECT * FROM responses WHERE form_id = ? AND student_id = ?
        ''', (form_id, session['user_id'])).fetchone()
        
        if response:
            return html_wrapper('Error', navbar() + '''
            <div class="container mt-5">
                <div class="alert alert-info">You have already submitted this form</div>
                <a href="/dashboard" class="btn btn-secondary">Go Back</a>
            </div>
            ''')
        
        form = conn.execute('SELECT * FROM forms WHERE id = ?', (form_id,)).fetchone()
        conn.close()
        
        if not form:
            return redirect('/dashboard')
        
        questions = json.loads(form['questions'])
        
        questions_html = ''
        for i, q in enumerate(questions):
            options_html = ''
            if q.get('type') == 'mcq':
                for j, opt in enumerate(q.get('options', [])):
                    options_html += f'''
                    <div class="form-check mb-2">
                        <input class="form-check-input" type="radio" name="q_{q['id']}" value="{j}" id="q{q['id']}_{j}" {"required" if q.get('required') else ""}>
                        <label class="form-check-label" for="q{q['id']}_{j}">{opt}</label>
                    </div>
                    '''
            elif q.get('type') == 'true_false':
                options_html = f'''
                <div class="form-check form-check-inline">
                    <input class="form-check-input" type="radio" name="q_{q['id']}" value="true" id="q{q['id']}_true" {"required" if q.get('required') else ""}>
                    <label class="form-check-label" for="q{q['id']}_true">True</label>
                </div>
                <div class="form-check form-check-inline">
                    <input class="form-check-input" type="radio" name="q_{q['id']}" value="false" id="q{q['id']}_false">
                    <label class="form-check-label" for="q{q['id']}_false">False</label>
                </div>
                '''
            elif q.get('type') == 'short_answer':
                options_html = f'''
                <input type="text" class="form-control" name="q_{q['id']}" {"required" if q.get('required') else ""}>
                '''
            
            required_star = '<span class="text-danger">*</span>' if q.get('required') else ''
            questions_html += f'''
            <div class="card mb-3">
                <div class="card-body">
                    <h5>Q{i+1}: {q.get('question', '')} {required_star}</h5>
                    {options_html}
                </div>
            </div>
            '''
        
        content = navbar() + f'''
        <div class="container mt-4">
            <div class="card">
                <div class="card-header bg-primary text-white">
                    <h3 class="mb-0">{form['title']}</h3>
                    <p class="mb-0">{form['description'] or ''}</p>
                </div>
                <div class="card-body">
                    <form id="responseForm">
                        {questions_html}
                    </form>
                </div>
                <div class="card-footer">
                    <button onclick="submitForm()" class="btn btn-success btn-lg w-100">
                        <i class="fas fa-paper-plane me-2"></i>Submit
                    </button>
                </div>
            </div>
        </div>
        
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
                    const qId = key.replace('q_', '');
                    answers[qId] = value;
                }}
                
                fetch('/submit-form', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{
                        form_id: {form_id},
                        answers: answers
                    }})
                }})
                .then(res => res.json())
                .then(data => {{
                    if (data.success) {{
                        document.body.innerHTML = `
                            <div class="container mt-5">
                                <div class="card text-center">
                                    <div class="card-body py-5">
                                        <i class="fas fa-check-circle fa-5x text-success mb-4"></i>
                                        <h2>Form Submitted!</h2>
                                        <div class="display-1 text-primary my-4">
                                            ${{data.score}}/${{data.total_marks}}
                                        </div>
                                        <p>Score: <strong>${{data.percentage}}%</strong></p>
                                        <a href="/dashboard" class="btn btn-primary mt-3">
                                            Back to Dashboard
                                        </a>
                                    </div>
                                </div>
                            </div>
                        `;
                    }} else {{
                        alert('Error submitting form: ' + (data.error || 'Unknown error'));
                    }}
                }})
                .catch(error => {{
                    alert('Error: ' + error);
                }});
            }}
        </script>
        '''
        
        return html_wrapper('Take Form', content)
        
    except Exception as e:
        print(f"Take form error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="container mt-5"><div class="alert alert-danger">Error: {str(e)}</div></div>')

@app.route('/submit-form', methods=['POST'])
@login_required
def submit_form():
    try:
        data = request.json
        form_id = data.get('form_id')
        answers = data.get('answers', {})
        
        conn = get_db()
        form = conn.execute('SELECT * FROM forms WHERE id = ?', (form_id,)).fetchone()
        
        if not form:
            return jsonify({'error': 'Form not found'}), 404
        
        questions = json.loads(form['questions'])
        
        # Calculate score
        score = 0
        total_marks = 0
        
        for q in questions:
            q_id = str(q.get('id'))
            marks = q.get('marks', 1)
            total_marks += marks
            
            if q_id in answers:
                user_answer = answers[q_id]
                
                if q.get('type') == 'mcq':
                    correct = q.get('correct_answer', 0)
                    if str(user_answer) == str(correct):
                        score += marks
                
                elif q.get('type') == 'true_false':
                    correct = q.get('correct_answer', 'true')
                    if str(user_answer).lower() == str(correct).lower():
                        score += marks
        
        percentage = (score / total_marks * 100) if total_marks > 0 else 0
        
        # Save response
        conn.execute('''
            INSERT INTO responses (form_id, student_id, answers, score, total_marks, percentage, time_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (form_id, session['user_id'], json.dumps(answers), score, total_marks, percentage, 0))
        
        # Mark assignment as completed
        conn.execute('''
            UPDATE assignments SET is_completed = 1 
            WHERE form_id = ? AND student_id = ?
        ''', (form_id, session['user_id']))
        
        conn.commit()
        conn.close()
        
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
        conn = get_db()
        
        form = conn.execute('SELECT * FROM forms WHERE id = ?', (form_id,)).fetchone()
        if not form or (form['created_by'] != session['user_id'] and session['role'] not in ['teacher', 'admin']):
            conn.close()
            return html_wrapper('Error', navbar() + '''
            <div class="container mt-5">
                <div class="alert alert-danger">Access denied</div>
                <a href="/dashboard" class="btn btn-secondary">Go Back</a>
            </div>
            ''')
        
        responses = conn.execute('''
            SELECT r.*, u.name, u.email 
            FROM responses r 
            JOIN users u ON r.student_id = u.id 
            WHERE r.form_id = ?
        ''', (form_id,)).fetchall()
        conn.close()
        
        responses_html = ''
        for r in responses:
            responses_html += f'''
            <tr>
                <td>{r['name']}</td>
                <td>{r['email']}</td>
                <td>{r['score']}/{r['total_marks']}</td>
                <td>{r['percentage']}%</td>
                <td>{r['submitted_at']}</td>
            </tr>
            '''
        
        if not responses_html:
            responses_html = '''
            <tr>
                <td colspan="5" class="text-center">No responses yet</td>
            </tr>
            '''
        
        content = navbar() + f'''
        <div class="container mt-4">
            <div class="card">
                <div class="card-header">
                    <h4 class="mb-0">Responses for: {form['title']}</h4>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Student</th>
                                    <th>Email</th>
                                    <th>Score</th>
                                    <th>Percentage</th>
                                    <th>Submitted At</th>
                                </tr>
                            </thead>
                            <tbody>
                                {responses_html}
                            </tbody>
                        </table>
                    </div>
                    <a href="/dashboard" class="btn btn-secondary">Back to Dashboard</a>
                </div>
            </div>
        </div>
        '''
        
        return html_wrapper('Responses', content)
        
    except Exception as e:
        print(f"View responses error: {e}")
        traceback.print_exc()
        return html_wrapper('Error', f'<div class="container mt-5"><div class="alert alert-danger">Error: {str(e)}</div></div>')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    print("=" * 50)
    print("Form System Started!")
    print("Access at: http://localhost:5000")
    print("Admin login: admin@form.com / admin123")
    print("=" * 50)
    
    # Fix for Flask version compatibility
    import flask
    from flask.sessions import SecureCookieSessionInterface
    
    class PatchedSessionInterface(SecureCookieSessionInterface):
        def save_session(self, *args, **kwargs):
            # Remove partitioned parameter if it exists
            if 'partitioned' in kwargs:
                kwargs.pop('partitioned')
            return super().save_session(*args, **kwargs)
    
    app.session_interface = PatchedSessionInterface()
    
    app.run(debug=True, host='0.0.0.0', port=5000)