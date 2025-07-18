from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'secret-key'

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )''')
    # Reports table
    c.execute('''CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user TEXT,
                    crime_type TEXT,
                    description TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Username already exists!"
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == 'admin':
            return "Admins must use the <a href='/admin_login'>Admin Login</a> page."

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE username=?', (username,))
        result = c.fetchone()
        conn.close()

        if result and check_password_hash(result[0], password):
            session['user'] = username
            return redirect(url_for('report'))
        else:
            return "Invalid Credentials!"
    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # You can hardcode the admin password or fetch from DB if you want
        admin_username = 'admin'
        admin_password = 'admin123'  # Change this to a secure password
        if username == admin_username and password == admin_password:
            session['user'] = 'admin'
            return redirect(url_for('admin'))
        else:
            return "Invalid Admin Credentials!"
    return render_template('admin_login.html')

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        crime_type = request.form['crime_type']
        description = request.form['description']
        user = session['user']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('INSERT INTO reports (user, crime_type, description) VALUES (?, ?, ?)', (user, crime_type, description))
        conn.commit()
        conn.close()
        return "Report Submitted Successfully!"
    return render_template('report.html')

@app.route('/admin')
def admin():
    if 'user' in session and session['user'] == 'admin':
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM reports ORDER BY timestamp DESC')
        reports = c.fetchall()
        conn.close()
        return render_template('admin.html', reports=reports)
    return "Access Denied"

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
