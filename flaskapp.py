from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'dummy_secret_key'  # Set a secret key for session management

# Get the base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'users2.db')

# SQLite setup
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (username TEXT UNIQUE, password TEXT, firstname TEXT, lastname TEXT, email TEXT, filename TEXT)''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('auth.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    firstname = request.form['first_name']
    lastname = request.form['last_name']
    email = request.form['email']
    limerick_file = request.files['limerick_file']  # Handle file upload

    # Validate registration details
    if not validate_registration(username, password, email):
        return redirect(url_for('index'))

    # Save the uploaded file
    if limerick_file and limerick_file.filename.endswith('.txt'):
        filename = limerick_file.filename
        limerick_file.save(os.path.join(BASE_DIR, filename))  # Save the file to the server
    else:
        flash('Invalid file type. Please upload a .txt file.')
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password, firstname, lastname, email, filename) VALUES (?, ?, ?, ?, ?, ?) ",
                  (username, password, firstname, lastname, email, filename))
        conn.commit()
        conn.close()

        return redirect(url_for('profile', username=username))
    except sqlite3.IntegrityError:
        flash('Username already exists. Please choose another one.')
        return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form['login_username']
    password = request.form['login_password']

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    user = c.fetchone()
    conn.close()

    if user:
        return redirect(url_for('profile', username=username))
    else:
        flash('Invalid username or password. Please try again.')
        return redirect(url_for('index'))

@app.route('/profile/<username>', methods=['GET', 'POST'])
def profile(username):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()

    if user:
        # Handle file upload if it's a POST request
        if request.method == 'POST':
            file = request.files['file']  # File input name should match
            if file and file.filename.endswith('.txt'):
                # Save the uploaded file
                file_path = os.path.join(BASE_DIR, file.filename)
                file.save(file_path)

                # Update the filename in the database
                conn = sqlite3.connect(DATABASE)
                c = conn.cursor()
                c.execute("UPDATE users SET filename=? WHERE username=?", (file.filename, username))
                conn.commit()
                conn.close()
                flash('File uploaded successfully.')
                return redirect(url_for('profile', username=username))  # Redirect to the profile page to show updates
            else:
                flash('Invalid file type. Please upload a .txt file.')

        # Get the word count of the uploaded file
        file_path = os.path.join(BASE_DIR, user[5])  # user[5] is the filename
        word_count = 0
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                content = file.read()
                word_count = len(content.split())

        return render_template('profile.html', user=user, word_count=word_count)
    else:
        flash('User not found.')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(BASE_DIR, filename, as_attachment=True)

def validate_registration(username, password, email):
    if len(password) < 6 or not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password):
        flash('Password must be at least 6 characters long and contain at least one uppercase letter, one lowercase letter, and one number.')
        return False
    if not valid_email(email):
        flash('Invalid email format. Please try again.')
        return False
    return True

def valid_email(email):
    return '@' in email and '.' in email

if __name__ == '__main__':
    init_db()  # Initialize the database
    app.run(debug=True)
