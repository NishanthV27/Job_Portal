from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
bcrypt = Bcrypt(app)

# Database initialization with automatic table creation
def init_db():
    db_exists = os.path.exists('jobs.db')
    
    conn = sqlite3.connect('jobs.db')
    cursor = conn.cursor()
    cursor.execute('PRAGMA foreign_keys = ON')
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            user_type TEXT NOT NULL,
            company_name TEXT,
            full_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            company TEXT NOT NULL,
            location TEXT NOT NULL,
            salary TEXT,
            employer_id INTEGER NOT NULL,
            posted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employer_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER NOT NULL,
            seeker_id INTEGER NOT NULL,
            employer_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (job_id) REFERENCES jobs (id) ON DELETE CASCADE,
            FOREIGN KEY (seeker_id) REFERENCES users (id),
            FOREIGN KEY (employer_id) REFERENCES users (id)
        )
    ''')
    
    # Create admin user if new database
    if not db_exists:
        admin_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
        try:
            cursor.execute(
                'INSERT INTO users (username, email, password, user_type, full_name) '
                'VALUES (?, ?, ?, ?, ?)',
                ('admin', 'admin@jobportal.com', admin_password, 'admin', 'Admin User')
            )
            print("Admin user created successfully")
        except sqlite3.IntegrityError as e:
            print(f"Error creating admin user: {e}")
    
    conn.commit()
    conn.close()

# Initialize database before first request
with app.app_context():
    init_db()

def get_db_connection():
    conn = sqlite3.connect('jobs.db')
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def format_date(date_str):
    try:
        return datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S').strftime('%b %d, %Y')
    except:
        return date_str

app.jinja_env.filters['format_date'] = format_date

# Routes
@app.route('/')
def index():
    conn = get_db_connection()
    jobs = conn.execute('''
        SELECT jobs.*, users.company_name 
        FROM jobs 
        JOIN users ON jobs.employer_id = users.id 
        ORDER BY posted_at DESC LIMIT 6
    ''').fetchall()
    conn.close()
    return render_template('index.html', jobs=jobs)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    location = request.args.get('location', '')
    
    conn = get_db_connection()
    sql = '''
        SELECT jobs.*, users.company_name, COUNT(applications.id) as application_count 
        FROM jobs 
        JOIN users ON jobs.employer_id = users.id
        LEFT JOIN applications ON jobs.id = applications.job_id
        WHERE (jobs.title LIKE ? OR jobs.description LIKE ? OR jobs.company LIKE ?)
    '''
    params = [f'%{query}%', f'%{query}%', f'%{query}%']
    
    if location:
        sql += ' AND jobs.location LIKE ?'
        params.append(f'%{location}%')
    
    sql += ' GROUP BY jobs.id ORDER BY jobs.posted_at DESC'
    
    jobs = conn.execute(sql, params).fetchall()
    conn.close()
    return render_template('browse_jobs.html', 
                         jobs=jobs, 
                         search_query=query,
                         location_query=location)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['user_type'] = user['user_type']
            
            if user['user_type'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['user_type'] == 'employer':
                return redirect(url_for('employer_dashboard'))
            else:
                return redirect(url_for('seeker_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user_type = request.form['user_type']
        full_name = request.form.get('full_name', '')
        company_name = request.form.get('company_name', '')
        
        try:
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO users (username, email, password, user_type, full_name, company_name) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (username, email, password, user_type, full_name, company_name)
            )
            conn.commit()
            conn.close()
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'danger')
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Admin Dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['user_type'] != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    jobs = conn.execute('SELECT jobs.*, users.username FROM jobs JOIN users ON jobs.employer_id = users.id ORDER BY posted_at DESC').fetchall()
    applications = conn.execute('''
        SELECT applications.*, jobs.title, users.username 
        FROM applications 
        JOIN jobs ON applications.job_id = jobs.id 
        JOIN users ON applications.seeker_id = users.id
        ORDER BY applied_at DESC
    ''').fetchall()
    conn.close()
    
    return render_template('dashboard_admin.html', 
                         users=users, 
                         jobs=jobs, 
                         applications=applications)

# Employer Routes
@app.route('/employer/dashboard')
def employer_dashboard():
    if 'user_id' not in session or session['user_type'] != 'employer':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    jobs = conn.execute('''
        SELECT jobs.*, COUNT(applications.id) as application_count 
        FROM jobs 
        LEFT JOIN applications ON jobs.id = applications.job_id 
        WHERE jobs.employer_id = ? 
        GROUP BY jobs.id
        ORDER BY jobs.posted_at DESC
    ''', (session['user_id'],)).fetchall()
    
    applications = conn.execute('''
        SELECT applications.*, jobs.title, users.full_name 
        FROM applications 
        JOIN jobs ON applications.job_id = jobs.id 
        JOIN users ON applications.seeker_id = users.id 
        WHERE applications.employer_id = ?
        ORDER BY applications.applied_at DESC
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    return render_template('dashboard_employer.html', 
                         jobs=jobs, 
                         applications=applications)

@app.route('/employer/post-job', methods=['GET', 'POST'])
def post_job():
    if 'user_id' not in session or session['user_type'] != 'employer':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        company = request.form['company']
        location = request.form['location']
        salary = request.form['salary']
        
        conn = get_db_connection()
        user = conn.execute('SELECT company_name FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        company_name = user['company_name'] if user and user['company_name'] else company
        
        conn.execute(
            'INSERT INTO jobs (title, description, company, location, salary, employer_id) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (title, description, company_name, location, salary, session['user_id'])
        )
        conn.commit()
        conn.close()
        flash('Job posted successfully!', 'success')
        return redirect(url_for('employer_dashboard'))
    
    return render_template('post_job.html')

@app.route('/employer/manage-jobs')
def manage_jobs():
    if 'user_id' not in session or session['user_type'] != 'employer':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    jobs = conn.execute('''
        SELECT jobs.*, COUNT(applications.id) as application_count 
        FROM jobs 
        LEFT JOIN applications ON jobs.id = applications.job_id 
        WHERE jobs.employer_id = ? 
        GROUP BY jobs.id
        ORDER BY jobs.posted_at DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    return render_template('manage_jobs.html', jobs=jobs)

@app.route('/employer/delete-job/<int:job_id>')
def delete_job(job_id):
    if 'user_id' not in session or session['user_type'] != 'employer':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    job = conn.execute('SELECT * FROM jobs WHERE id = ? AND employer_id = ?', (job_id, session['user_id'])).fetchone()
    
    if job:
        conn.execute('DELETE FROM jobs WHERE id = ?', (job_id,))
        conn.commit()
        flash('Job deleted successfully', 'success')
    else:
        flash('Job not found or unauthorized', 'danger')
    
    conn.close()
    return redirect(url_for('manage_jobs'))

# Job Seeker Routes
@app.route('/seeker/dashboard')
def seeker_dashboard():
    if 'user_id' not in session or session['user_type'] != 'seeker':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    applications = conn.execute('''
        SELECT applications.*, jobs.title, jobs.company, jobs.location 
        FROM applications 
        JOIN jobs ON applications.job_id = jobs.id 
        WHERE applications.seeker_id = ?
        ORDER BY applications.applied_at DESC
    ''', (session['user_id'],)).fetchall()
    
    recommended_jobs = conn.execute('''
        SELECT jobs.*, users.company_name 
        FROM jobs 
        JOIN users ON jobs.employer_id = users.id 
        WHERE jobs.id NOT IN (
            SELECT job_id FROM applications WHERE seeker_id = ?
        )
        ORDER BY jobs.posted_at DESC 
        LIMIT 3
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    return render_template('dashboard_seeker.html', 
                         applications=applications, 
                         jobs=recommended_jobs)

@app.route('/browse-jobs')
def browse_jobs():
    conn = get_db_connection()
    jobs = conn.execute('''
        SELECT jobs.*, users.company_name, COUNT(applications.id) as application_count 
        FROM jobs 
        JOIN users ON jobs.employer_id = users.id
        LEFT JOIN applications ON jobs.id = applications.job_id
        GROUP BY jobs.id 
        ORDER BY jobs.posted_at DESC
    ''').fetchall()
    conn.close()
    return render_template('browse_jobs.html', jobs=jobs)

@app.route('/apply-job/<int:job_id>')
def apply_job(job_id):
    if 'user_id' not in session or session['user_type'] != 'seeker':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Check if already applied
    existing = conn.execute(
        'SELECT * FROM applications WHERE job_id = ? AND seeker_id = ?', 
        (job_id, session['user_id'])
    ).fetchone()
    
    if existing:
        flash('You have already applied for this job', 'warning')
    else:
        # Get employer_id for the job
        job = conn.execute(
            'SELECT employer_id FROM jobs WHERE id = ?', 
            (job_id,)
        ).fetchone()
        
        if job:
            conn.execute(
                'INSERT INTO applications (job_id, seeker_id, employer_id) '
                'VALUES (?, ?, ?)',
                (job_id, session['user_id'], job['employer_id'])
            )
            conn.commit()
            flash('Application submitted successfully!', 'success')
        else:
            flash('Job not found', 'danger')
    
    conn.close()
    return redirect(url_for('browse_jobs'))

@app.route('/seeker/withdraw-application/<int:app_id>')
def withdraw_application(app_id):
    if 'user_id' not in session or session['user_type'] != 'seeker':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute(
        'DELETE FROM applications WHERE id = ? AND seeker_id = ?', 
        (app_id, session['user_id'])
    )
    conn.commit()
    conn.close()
    flash('Application withdrawn', 'success')
    return redirect(url_for('seeker_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)