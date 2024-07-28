import hashlib
import random
import mysql.connector
import setup
import subprocess
import sys

try:
    from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
    from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
    from flask_bcrypt import Bcrypt
    import pyotp
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", 'flask'])
    subprocess.check_call([sys.executable, "-m", "pip", "install", 'flask_login'])
    subprocess.check_call([sys.executable, "-m", "pip", "install", 'flask_bcrypt'])
    subprocess.check_call([sys.executable, "-m", "pip", "install", 'clipboard'])
    subprocess.check_call([sys.executable, "-m", "pip", "install", 'pyotp'])
    subprocess.check_call([sys.executable, "-m", "pip", "install", 'mysql-connector-python'])

finally:
    from flask import Flask, render_template, request, redirect, url_for, flash
    from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
    from flask_bcrypt import Bcrypt
    import pyotp

def SHA_256(hash_string):
    sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# New connection to the online MySQL database for PythonAnywhere deployment
def get_db_connection():
    return mysql.connector.connect(
        host='cyrolite.mysql.pythonanywhere-services.com',
        user='cyrolite',
        password='Y02030405y!',
        database='cyrolite$default'
    )

# Previous connection to MySQL database using localhost 
''' def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='iamanoob44',
        password='Chinch0ng24042002!',
        database='mypasswords'
    )'''



@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1], user[2], user[3], user[4], user[5])
    return None

class User(UserMixin):
    def __init__(self, id, username, password, otp_secret, security_question, security_answer):
        self.id = id
        self.username = username
        self.password = password
        self.otp_secret = otp_secret
        self.security_question = security_question
        self.security_answer_hashed_ver = security_answer

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) BINARY COLLATE utf8_bin NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        otp_secret VARCHAR(255) NOT NULL,
        security_question TEXT NOT NULL,
        security_answer VARCHAR(255) NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS passwords (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        app_name TEXT NOT NULL,
        password TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()


@app.route('/')
@login_required
def home():
    return render_template('index.html')


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    user_pw_not_found = False
    invalid_otp = False
    username = ''
    otp_token = ''
    old_master_password = ''
    new_password = ''

    if request.method == 'POST':
        username = request.form['username']
        otp_token = request.form['otp_token']
        old_master_password = request.form['old_password']
        new_password = request.form['new_password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE BINARY username = %s', (username,))
        user = cursor.fetchone()

        if user:
            totp = pyotp.TOTP(user[3])
            # Verify old master password first before verifying the 2FA
            if user[2] == SHA_256(old_master_password):
                # Verify 2FA
                if totp.verify(otp_token):
                    # Decrypt all passwords with the old master password
                    old_iv, old_key = setup.generateValues(user[2])
                    cursor.execute('SELECT id, app_name, password FROM passwords WHERE user_id = %s', (user[0],))
                    passwords = cursor.fetchall()

                    decrypted_passwords = []
                    for pw in passwords:
                        app_name = setup.decrypt_from_str(pw[1], old_key, old_iv)
                        password = setup.decrypt_from_str(pw[2], old_key, old_iv)
                        decrypted_passwords.append((pw[0], app_name, password))

                    # Encrypt passwords with the new master password
                    new_iv, new_key = setup.generateValues(SHA_256(new_password))
                    encrypted_passwords = []
                    for pw in decrypted_passwords:
                        enc_app_name = setup.encrypt_to_str(pw[1], new_key, new_iv)
                        enc_password = setup.encrypt_to_str(pw[2], new_key, new_iv)
                        encrypted_passwords.append((enc_app_name, enc_password, pw[0]))

                    # Update passwords in the database
                    for enc_app_name, enc_password, pw_id in encrypted_passwords:
                        cursor.execute('UPDATE passwords SET app_name = %s, password = %s WHERE id = %s', (enc_app_name, enc_password, pw_id))

                    # Update the master password in the database
                    hashed_password = SHA_256(new_password)
                    cursor.execute('UPDATE users SET password = %s WHERE username = %s', (hashed_password, username))

                    conn.commit()
                    flash('Password changed! Please log in to access the page', 'success')
                    return redirect(url_for('login'))
                else:
                    invalid_otp = True 
            else:
                user_pw_not_found = True
        else:
            user_pw_not_found = True

        conn.close()

    return render_template('change_password.html', 
                           user_pw_not_found=user_pw_not_found, 
                           invalid_otp=invalid_otp, 
                           username=username, 
                           otp_token=otp_token, 
                           old_password=old_master_password, 
                           new_password=new_password)


@app.route('/forget_password', methods=['GET', 'POST'])
def forget_password():
    username_not_found = False
    invalid_otp = False
    invalid_answer = False
    display_question = False
    security_question = ""

    if request.method == 'POST':
        if 'username' in request.form:
            username = request.form['username']

            conn = get_db_connection()
            cursor = conn.cursor()

            # Check if the username exists
            cursor.execute('SELECT * FROM users WHERE BINARY username = %s', (username,))
            user = cursor.fetchone()

            if user:
                security_question = user[4]  # Security Question is user[4]
                display_question = True
                session['username'] = username  # Store username in session
            else:
                username_not_found = True

            conn.close()

        elif 'security_answer' in request.form and 'otp_token' in request.form and 'new_password' in request.form:
            if 'username' in session:
                username = session['username']
            else:
                return redirect(url_for('forget_password'))


            security_answer = request.form['security_answer'].capitalize()
            hashed_security_answer = SHA_256(security_answer)
            otp_token = request.form['otp_token']
            new_password = request.form['new_password']

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE BINARY username = %s', (username,))
            user = cursor.fetchone()

            if user:
                if user[5] == hashed_security_answer:  # Security answer is user[5]
                    totp = pyotp.TOTP(user[3])  # 2FA token is user[3]
                    if totp.verify(otp_token):
                        old_hashed_password = user[2]  # old hashed password

                        # Generate IV and keys from old hashed password
                        old_iv, old_key = setup.generateValues(old_hashed_password)

                        # Decrypt all passwords
                        cursor.execute('SELECT id, app_name, password FROM passwords WHERE user_id = %s', (user[0],))
                        passwords = cursor.fetchall()

                        # Temporary dictionary to hold decrypted passwords
                        temp_passwords = {}
                        for pwd in passwords:
                            app_name = setup.decrypt_from_str(pwd[1], old_key, old_iv)
                            password = setup.decrypt_from_str(pwd[2], old_key, old_iv)
                            temp_passwords[app_name] = password

                        # Update master password
                        new_hashed_password = SHA_256(new_password)
                        cursor.execute('UPDATE users SET password = %s WHERE id = %s', (new_hashed_password, user[0]))

                        # Generate IV and keys from new password
                        new_iv, new_key = setup.generateValues(new_hashed_password)

                        # Re-encrypt passwords with new master password
                        for app_name, password in temp_passwords.items():
                            enc_app_name = setup.encrypt_to_str(app_name, new_key, new_iv)
                            enc_password = setup.encrypt_to_str(password, new_key, new_iv)
                            cursor.execute('UPDATE passwords SET app_name = %s, password = %s WHERE user_id = %s AND app_name = %s', 
                                           (enc_app_name, enc_password, user[0], setup.encrypt_to_str(app_name, old_key, old_iv)))

                        conn.commit()
                        flash('Login password updated successfully!', 'success')
                        return redirect(url_for('login'))
                    else:
                        invalid_otp = True
                else:
                    invalid_answer = True
            else:
                username_not_found = True

            conn.close()

    return render_template('forget_password.html', 
                           username_not_found=username_not_found, 
                           invalid_otp=invalid_otp, 
                           invalid_answer=invalid_answer, 
                           display_question=display_question, 
                           security_question=security_question)


@app.route('/register', methods=['GET', 'POST'])
def register():
    username_exists = False
    missing_fields = False
    passwords_not_match = False
    username_spacing_error = False  # New flag for username spacing error

    # Variables to store the values entered by a user
    entered_username = ''
    entered_security_question = ''
    entered_security_answer = ''

    if request.method == 'POST':
        entered_username = request.form['username']
        master_password = request.form['password']
        confirm_master_password = request.form['confirm_password']
        entered_security_question = request.form['security_question']
        entered_security_answer = request.form['security_answer'].capitalize()

        if ' ' in entered_username:  # Check for spaces in the username
            username_spacing_error = True
        elif not entered_username or not master_password or not confirm_master_password or not entered_security_question or not entered_security_answer:
            missing_fields = True
        elif master_password != confirm_master_password:
            passwords_not_match = True
        else:
            hashed_password = SHA_256(master_password)
            hashed_security_answer = SHA_256(entered_security_answer)
            otp_secret = pyotp.random_base32()

            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                # Check if that specific username already exists in a case-insensitive manner (refer to README - register feature for more details)
                cursor.execute('SELECT COUNT(*) FROM users WHERE BINARY UPPER(username) = UPPER(%s)', (entered_username,))
                if cursor.fetchone()[0] > 0:
                    username_exists = True
                else:
                    cursor.execute('INSERT INTO users (username, password, otp_secret, security_question, security_answer) VALUES (%s, %s, %s, %s, %s)',
                                   (entered_username, hashed_password, otp_secret, entered_security_question, hashed_security_answer))
                    conn.commit()
                    flash('Registration successful!', 'success')
                    return redirect(url_for('show_2fa', username=entered_username))
            except mysql.connector.Error as error:
                username_exists = True  # Set the flag to True if the username already exists
                conn.rollback()
            finally:
                conn.close()

    return render_template('register.html', username_exists=username_exists, missing_fields=missing_fields, passwords_not_match=passwords_not_match,
                           username_spacing_error=username_spacing_error, entered_username=entered_username, entered_security_question=entered_security_question, 
                           entered_security_answer=entered_security_answer)






@app.route('/show_2fa/<username>')
def show_2fa(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT otp_secret FROM users WHERE BINARY username = %s', (username,))
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

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE BINARY username = %s', (username,))
        user = cursor.fetchone()
        conn.close()

        if user and user[2] == SHA_256(password):
            totp = pyotp.TOTP(user[3])
            if totp.verify(otp_token):
                user_obj = User(user[0], user[1], user[2], user[3], user[4], user[5])
                login_user(user_obj)
                hashed_password = SHA_256(password)
                session['iv'], session['key'] = setup.generateValues(hashed_password)
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid 2FA token', 'error')
        else:
            flash('Invalid username or password', 'error')

        return render_template('login.html', username=username, password=password, otp_token=otp_token)
    
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
    app_name = request.form['app_name'].capitalize()
    password = request.form['password']

    if not (app_name and password):
        flash('Please enter both app name and password', 'error')
        return redirect(url_for('home'))

    iv = session['iv']
    key = session['key'] 

    enc_app_name = setup.encrypt_to_str(app_name, key, iv)
    enc_password = setup.encrypt_to_str(password, key, iv)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM passwords WHERE app_name = %s AND user_id = %s', (enc_app_name, current_user.id))
    existing_password = cursor.fetchone()

    if existing_password:
        cursor.execute('UPDATE passwords SET password = %s WHERE app_name = %s AND user_id = %s', (enc_password, enc_app_name, current_user.id))
        flash('Password updated successfully', 'success')
    else:
        cursor.execute('INSERT INTO passwords (user_id, app_name, password) VALUES (%s, %s, %s)', (current_user.id, enc_app_name, enc_password))
        flash('Password added successfully', 'success')

    conn.commit()
    conn.close()
    return redirect(url_for('home'))



@app.route('/get', methods=['POST'])
@login_required
def get_password():
    app_name = request.form['app_name'].capitalize()

    iv = session['iv']
    key = session['key']

    enc_app_name = setup.encrypt_to_str(app_name, key, iv)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM passwords WHERE app_name = %s AND user_id = %s', (enc_app_name, current_user.id))
    result = cursor.fetchone()

    if result:
        dec_password = setup.decrypt_from_str(result[0], key, iv)
        return render_template('show_password.html', app_name=app_name, password=dec_password)
    else:
        flash(f'No password found for {app_name}', 'error')

    conn.close()
    return redirect(url_for('home'))


@app.route('/list', methods=['GET', 'POST'])
@login_required
def list_passwords():
    iv = session['iv']
    key = session['key']
    
    if request.method == 'POST':
        app_name = request.form['app_name']
        new_password = request.form['new_password']
        
        encrypted_app_name = setup.encrypt_to_str(app_name, key, iv)
        encrypted_new_password = setup.encrypt_to_str(new_password, key, iv)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE passwords SET password = %s WHERE user_id = %s AND app_name = %s', (encrypted_new_password, current_user.id, encrypted_app_name))
        conn.commit()
        conn.close()

        flash('Password updated successfully.', 'success')
        return redirect(url_for('list_passwords'))

    search_query = request.args.get('q', '').capitalize()

    conn = get_db_connection()
    cursor = conn.cursor()

    if search_query:
        enc_search_query = setup.encrypt_to_str(search_query, key, iv)
        cursor.execute('SELECT app_name, password FROM passwords WHERE user_id = %s AND app_name LIKE %s', (current_user.id, f'%{enc_search_query}%'))
    else:
        cursor.execute('SELECT app_name, password FROM passwords WHERE user_id = %s', (current_user.id,))
        
    records = cursor.fetchall()
    conn.close()

    sorted_records = sorted(records, key=lambda x: setup.decrypt_from_str(x[0], key, iv))

    passwords = {setup.decrypt_from_str(app, key, iv): setup.decrypt_from_str(pwd, key, iv) for app, pwd in sorted_records}

    return render_template('list.html', passwords=passwords, search_query=search_query)


@app.route('/delete_password_from_list', methods=['POST'])
@login_required
def delete_password_from_list():
    app_name = request.form['app_name']
    iv = session['iv']
    key = session['key']
    
    encrypted_app_name = setup.encrypt_to_str(app_name, key, iv)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM passwords WHERE user_id = %s AND app_name = %s', (current_user.id, encrypted_app_name))
    conn.commit()
    conn.close()
    
    return redirect(url_for('list_passwords'))


@app.route('/update_password_from_list', methods=['POST'])
@login_required
def update_password_from_list():
    app_name = request.form['app_name']
    new_password = request.form['new_password']
    iv = session['iv']
    key = session['key']

    encrypted_app_name = setup.encrypt_to_str(app_name, key, iv)
    encrypted_new_password = setup.encrypt_to_str(new_password, key, iv)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE passwords SET password = %s WHERE user_id = %s AND app_name = %s', 
                   (encrypted_new_password, current_user.id, encrypted_app_name))
    conn.commit()
    conn.close()
    
    return redirect(url_for('list_passwords'))



@app.route('/delete', methods=['POST'])
@login_required
def delete_password():
    app_name = request.form['app_name'].capitalize()

    iv = session['iv']
    key = session['key']

    enc_app_name = setup.encrypt_to_str(app_name, key, iv)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM passwords WHERE app_name = %s AND user_id = %s', (enc_app_name, current_user.id))
    result = cursor.fetchone()

    if result:
        cursor.execute('DELETE FROM passwords WHERE app_name = %s AND user_id = %s', (enc_app_name, current_user.id))
        flash(f'Password for {app_name} deleted', 'success')
    else:
        flash(f'No password found for {app_name}', 'error')

    conn.commit()
    conn.close()
    return redirect(url_for('home'))



@app.route('/generate_password', methods=['POST'])
@login_required
def generate_password():
    length = int(request.form.get('pw_length',12))
    if length < 12:
        return redirect(url_for('home'))
    else:
        random_pw = random_password_generator(length)
        return render_template('generated_password.html', random_pw=random_pw)
    

def random_password_generator(default_safe_length):
    alphabetical_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    numerical_characters = "1234567890"
    special_char = "`!@#$%^&*()_+\{|}:'\<\>?/;[~]"
    characters = alphabetical_characters + numerical_characters + special_char
    password = "".join(random.choice(characters) for _ in range(default_safe_length))
    return password


if __name__ == '__main__':
    init_db()
    app.run(debug=True)