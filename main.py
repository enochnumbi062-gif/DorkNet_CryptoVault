import os
import io
import csv
from dotenv import load_dotenv
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Chargement des variables d'environnement
load_dotenv()

app = Flask(__name__)

# --- CONFIGURATION ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dorknet-xchange-default-secret')

# Configuration PostgreSQL avec correction pour Render
db_url = os.getenv('DATABASE_URL', 'sqlite:///cryptovault.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

# Initialisation
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'

# --- SÉCURITÉ : CLÉ AES ---
aes_key_hex = os.getenv('AES_KEY')
if not aes_key_hex:
    aes_key_hex = get_random_bytes(32).hex()
ENCRYPTION_KEY = bytes.fromhex(aes_key_hex)

# --- MODÈLES DE DONNÉES ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.String(500))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

@app.route('/')
def index():
    db.create_all() 
    files = []
    logs = []
    if current_user.is_authenticated:
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        files = os.listdir(app.config['UPLOAD_FOLDER'])
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    return render_template('index.html', files=files, logs=logs)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        login_user(user)
        log = AuditLog(username=username, action="CONNEXION", details="Accès réussi au coffre")
        db.session.add(log); db.session.commit()
    else:
        flash('Identifiants incorrects.')
    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    if User.query.filter_by(username=username).first():
        flash('Pseudo déjà utilisé.')
    else:
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        log = AuditLog(username=username, action="INSCRIPTION", details="Nouveau compte DorkNet créé")
        db.session.add(log); db.session.commit()
        flash('Compte créé !')
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    if file and file.filename != '':
        try:
            cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(file.read())
            filename = file.filename + '.enc'
            path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(path, 'wb') as f:
                [f.write(x) for x in (nonce, tag, ciphertext)]
            log = AuditLog(username=current_user.username, action="CHIFFREMENT", details=f"Fichier sécurisé : {file.filename}")
            db.session.add(log); db.session.commit()
            flash(f'Fichier sécurisé.')
        except Exception as e:
            flash(f'Erreur : {str(e)}')
    return redirect(url_for('index'))

@app.route('/download/<filename>')
@login_required
def download(filename):
    try:
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(path, 'rb') as f:
            nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        log = AuditLog(username=current_user.username, action="DÉCHIFFREMENT", details=f"Accès au fichier : {filename}")
        db.session.add(log); db.session.commit()
        return send_file(io.BytesIO(data), as_attachment=True, download_name=filename.replace('.enc', ''))
    except Exception:
        flash('Échec du déchiffrement.')
        return redirect(url_for('index'))

@app.route('/export_logs')
@login_required
def export_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    proxy = io.StringIO()
    writer = csv.writer(proxy)
    writer.writerow(['Date', 'Utilisateur', 'Action', 'Details'])
    for log in logs:
        writer.writerow([log.timestamp, log.username, log.action, log.details])
    mem = io.BytesIO()
    mem.write(proxy.getvalue().encode('utf-8'))
    mem.seek(0)
    proxy.close()
    return send_file(mem, as_attachment=True, download_name=f"DorkNet_Audit_{current_user.username}.csv", mimetype='text/csv')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
