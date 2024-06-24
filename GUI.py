from tkinter import *
import os
import hashlib
import sqlite3
import setup
import subprocess
import sys

try:
    from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
    from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
    from flask_bcrypt import Bcrypt
    import pyperclip
    import pyotp
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", 'flask'])
    subprocess.check_call([sys.executable, "-m", "pip", "install", 'flask_login'])
    subprocess.check_call([sys.executable, "-m", "pip", "install", 'flask_bcrypt'])
    subprocess.check_call([sys.executable, "-m", "pip", "install", 'pyperclip'])
    subprocess.check_call([sys.executable, "-m", "pip", "install", 'pyotp'])

finally:
    from flask import Flask, render_template, request, redirect, url_for, flash
    from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
    from flask_bcrypt import Bcrypt
    import pyperclip
    import pyotp


# SHA_256 hash function
def SHA_256(hash_string):
    sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1], user[2], user[3])
    return None


# defines User class / Constructor for User 
class User(UserMixin):
    def __init__(self, id, username, password, otp_secret):
        self.id = id
        self.username = username
        self.password = password
        self.otp_secret = otp_secret

# initialise the database - passwords.db local database file
def init_db():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        otp_secret TEXT NOT NULL
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        app_name TEXT NOT NULL,
        password TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
@login_required
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    username_exists = False  
    missing_fields = False

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            missing_fields = True
        else:
            # hash the master password
            hashed_password = bcrypt.generate_password_hash(SHA_256(password)).decode('utf-8')
            otp_secret = pyotp.random_base32()

            conn = sqlite3.connect('passwords.db')
            cursor = conn.cursor()
            try:
                cursor.execute('INSERT INTO users (username, password, otp_secret) VALUES (?, ?, ?)', (username, hashed_password, otp_secret))
                conn.commit()
                flash('Registration successful! Please scan the QR code with your 2FA app.', 'success')
                return redirect(url_for('show_2fa', username=username))
            except sqlite3.IntegrityError:
                username_exists = True  # Set to True if the username already exists in database
                conn.rollback() 
            finally:
                conn.close()

    return render_template('register.html', username_exists=username_exists, missing_fields=missing_fields) 

@app.route('/show_2fa/<username>')
def show_2fa(username):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT otp_secret FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        otp_secret = user[0]
        otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=username, issuer_name="YourAppName")
        return render_template('show_2fa.html', otp_uri=otp_uri)
    else:
        flash('User not found', 'error')
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        otp_token = request.form['otp_token']

        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[2], SHA_256(password)):
            totp = pyotp.TOTP(user[3])

            # Verify 2FA token is correct
            if totp.verify(otp_token):
                user_obj = User(user[0], user[1], user[2], user[3])
                login_user(user_obj)
                session['iv'], session['key'] = setup.generateValues(password)
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid 2FA token', 'error')
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    session.pop('iv', None)
    session.pop('key', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/add', methods=['POST'])
@login_required
def add_password():

    # Ensure the app name is not case sensitive since addition of app name
    # is subjective to users
    app_name = request.form['app_name'].capitalize()
    password = request.form['password']

    if not (app_name and password):
        flash('Please enter both app name and password', 'error')
        return redirect(url_for('home'))

    iv = session['iv']
    key = session['key'] 

    # Encrypt the app name and password using AES-256 Encryption
    enc_app_name = setup.encrypt_to_str(app_name, key, iv)
    enc_password = setup.encrypt_to_str(password, key, iv)

    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM passwords WHERE app_name = ? AND user_id = ?', (enc_app_name, current_user.id))
    existing_password = cursor.fetchone()

    # Update the password if it exist, else, add them into the passwords.db file database
    if existing_password:
        cursor.execute('UPDATE passwords SET password = ? WHERE app_name = ? AND user_id = ?', (enc_password, enc_app_name, current_user.id))
        flash('Password updated successfully', 'success')
    else:
        cursor.execute('INSERT INTO passwords (user_id, app_name, password) VALUES (?, ?, ?)', (current_user.id, enc_app_name, enc_password))
        flash('Password added successfully', 'success')

    conn.commit()
    conn.close()
    return redirect(url_for('home'))

@app.route('/get', methods=['POST'])
@login_required
def get_password():

    # Ensure the app name is not case sensitive since addition of app name
    # is subjective to users
    app_name = request.form['app_name'].capitalize()

    iv = session['iv']
    key = session['key']

    enc_app_name = setup.encrypt_to_str(app_name, key, iv)

    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM passwords WHERE app_name = ? AND user_id = ?', (enc_app_name, current_user.id))
    result = cursor.fetchone()

    # Check if password exist in the password.db file, else, return no password found error
    if result:
        dec_password = setup.decrypt_from_str(result[0], key, iv)
        pyperclip.copy(dec_password)
        flash(f'Password for {app_name} is {dec_password}, and copied into your clipboard', 'info')
    else:
        flash(f'No password found for {app_name}', 'error')

    conn.close()
    return redirect(url_for('home'))

@app.route('/list', methods=['GET', 'POST'])
@login_required
def list_passwords():
    iv = session['iv']
    key = session['key']
    
    search_query = request.args.get('q', '').capitalize()

    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()

    # Check if the given password is in the list of passwords
    if search_query:
        enc_search_query = setup.encrypt_to_str(search_query, key, iv)
        cursor.execute('SELECT app_name, password FROM passwords WHERE user_id = ? AND app_name LIKE ?', (current_user.id, f'%{enc_search_query}%'))
    else:
        cursor.execute('SELECT app_name, password FROM passwords WHERE user_id = ?', (current_user.id,))
        
    records = cursor.fetchall()
    conn.close()

    # Sort the passwords according to the alphabetical order of app names
    sorted_records = sorted(records, key=lambda x: setup.decrypt_from_str(x[0], key, iv))

    passwords = {setup.decrypt_from_str(app, key, iv): setup.decrypt_from_str(pwd, key, iv) for app, pwd in sorted_records}

    if not passwords and search_query:
        flash(f'No passwords found for {search_query}', 'error')

    return render_template('list.html', passwords=passwords, search_query=search_query)

@app.route('/delete', methods=['POST'])
@login_required
def delete_password():

    # Ensure the app name is not case sensitive since addition of app name
    # is subjective to users, thus, deleting should also be not case sensitive
    app_name = request.form['app_name'].capitalize()

    iv = session['iv']
    key = session['key']

    enc_app_name = setup.encrypt_to_str(app_name, key, iv)

    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM passwords WHERE app_name = ? AND user_id = ?', (enc_app_name, current_user.id))
    result = cursor.fetchone()

    # Check if password exist in system. If yes, then delete successfully.
    if result:
        cursor.execute('DELETE FROM passwords WHERE app_name = ? AND user_id = ?', (enc_app_name, current_user.id))
        flash(f'Password for {app_name} deleted', 'success')
    else:
        flash(f'No password found for {app_name}', 'error')

    conn.commit()
    conn.close()
    return redirect(url_for('home'))

# Initialise it as debug = True for the app
if __name__ == '__main__':
    init_db()
    app.run(debug=True)