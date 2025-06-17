# app.py
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import json
from werkzeug.utils import secure_filename
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
app.secret_key = 'supersecretkey'

login_manager = LoginManager()
login_manager.init_app(app)

# Thư mục
UPLOAD_FOLDER = 'uploads'
MESSAGE_FOLDER = 'messages'
USERS_FILE = 'users.json'
KEY_FOLDER = 'keys'

for folder in [UPLOAD_FOLDER, MESSAGE_FOLDER, KEY_FOLDER]:
    os.makedirs(folder, exist_ok=True)

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

def generate_keys(username):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    with open(f'{KEY_FOLDER}/{username}_private.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(f'{KEY_FOLDER}/{username}_public.pem', 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def sign_data(username, data):
    with open(f'{KEY_FOLDER}/{username}_private.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()

def verify_signature(sender, data, signature_hex):
    try:
        with open(f'{KEY_FOLDER}/{sender}_public.pem', 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
        public_key.verify(
            bytes.fromhex(signature_hex),
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, FileNotFoundError):
        return False

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    users = load_users()
    if user_id in users:
        return User(user_id)
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username']
        password = request.form['password']
        if username in users:
            return 'Tài khoản đã tồn tại!'
        users[username] = password
        save_users(users)
        generate_keys(username)
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            user = User(username)
            login_user(user)
            return redirect('/dashboard')
        return 'Sai thông tin đăng nhập!'
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.route('/dashboard')
@login_required
def dashboard():
    users = list(load_users().keys())
    users.remove(current_user.id)
    return render_template('dashboard.html', users=users)

@app.route('/send', methods=['POST'])
@login_required
def send():
    receiver = request.form['receiver']
    message = request.form['message']
    file = request.files['file']
    filename = ''
    file_signature = ''
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        with open(filepath, 'rb') as f:
            file_data = f.read()
        file_signature = sign_data(current_user.id, file_data)

    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    msg = {
        'sender': current_user.id,
        'message': message,
        'file': filename,
        'signature': file_signature
    }
    inbox_file = os.path.join(MESSAGE_FOLDER, f'{receiver}.json')
    inbox = []
    if os.path.exists(inbox_file):
        with open(inbox_file, 'r') as f:
            inbox = json.load(f)
    inbox.append(msg)
    with open(inbox_file, 'w') as f:
        json.dump(inbox, f)
    return redirect('/dashboard')

@app.route('/inbox')
@login_required
def inbox():
    inbox_file = os.path.join(MESSAGE_FOLDER, f'{current_user.id}.json')
    messages = []
    if os.path.exists(inbox_file):
        with open(inbox_file, 'r') as f:
            messages = json.load(f)
        for msg in messages:
            signature = msg.get('signature', '')
            file_path = os.path.join(UPLOAD_FOLDER, msg['file']) if msg['file'] else None
            if msg['file'] and os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                msg['valid'] = verify_signature(msg['sender'], file_data, signature)
            else:
                msg['valid'] = False
    return render_template('inbox.html', messages=messages)

@app.route('/download/<filename>')
@login_required
def download(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
