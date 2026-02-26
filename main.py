import os
import io
import csv
import cloudinary
import cloudinary.uploader
import cloudinary.api
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

# --- CONFIGURATION GÉNÉRALE ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dorknet-xchange-88')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

# Configuration Base de données (PostgreSQL pour Render ou SQLite local)
db_url = os.getenv('DATABASE_URL', 'sqlite:///cryptovault.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'

# --- CONFIGURATION CLOUDINARY ---
cloudinary.config(
  cloud_name = os.getenv('CLOUDINARY_CLOUD_NAME'),
  api_key = os.getenv('CLOUDINARY_API_KEY'),
  api_secret = os.getenv('CLOUDINARY_API_SECRET')
)

# --- SÉCURITÉ : CLÉ AES-256 ---
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

# --- ROUTES PRINCIPALES (DASHBOARD) ---

@app.route('/')
def index():
    db.create_all()
    logs = []
    cloud_files = []
    if current_user.is_authenticated:
        # 1. Récupérer les 10 derniers logs d'audit
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
        # 2. Récupérer les fichiers Cloudinary pour l'affichage immédiat
        try:
            resources = cloudinary.api.resources(resource_type="raw", type="upload", max_results=15)
            for res in resources.get('resources', []):
                cloud_files.append({
                    'public_id': res['public_id'],
                    'url': res['secure_url'],
                    'size': f"{res['bytes'] / 1024:.1f} KB",
                    'created_at': res['created_at']
                })
        except Exception as e:
            print(f"Erreur Cloudinary : {e}")
            
    return render_template('index.html', logs=logs, files=cloud_files)

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
    return send_file(mem, as_attachment=True, download_name=f"Audit_DorkNet_{current_user.username}.csv", mimetype='text/csv')

# --- GESTION DES FICHIERS CLOUD ---

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    if file and file.filename != '':
        try:
            # Chiffrement AES
            cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(file.read())
            
            enc_filename = file.filename + '.enc'
            with open(enc_filename, 'wb') as f:
                [f.write(x) for x in (nonce, tag, ciphertext)]
            
            # Upload vers Cloudinary
            upload_result = cloudinary.uploader.upload(enc_filename, resource_type="raw")
            
            # Nettoyage
            if os.path.exists(enc_filename):
                os.remove(enc_filename)
            
            log = AuditLog(username=current_user.username, action="CLOUD_UPLOAD", details=f"Fichier chiffré : {file.filename}")
            db.session.add(log); db.session.commit()
            flash(f'Succès : {file.filename} est sécurisé dans le Cloud !')
        except Exception as e:
            flash(f'Erreur : {str(e)}')
    return redirect(url_for('index'))

@app.route('/delete_cloud/<path:public_id>')
@login_required
def delete_cloud(public_id):
    try:
        cloudinary.uploader.destroy(public_id, resource_type="raw")
        log = AuditLog(username=current_user.username, action="CLOUD_DELETE", details=f"Suppression : {public_id}")
        db.session.add(log); db.session.commit()
        flash(f"Fichier supprimé définitivement du Cloud.")
    except Exception as e:
        flash(f"Erreur suppression : {str(e)}")
    return redirect(url_for('index'))

# --- AUTHENTIFICATION ---

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        login_user(user)
        log = AuditLog(username=username, action="CONNEXION", details="Accès au système")
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
        log = AuditLog(username=username, action="INSCRIPTION", details="Nouveau compte créé")
        db.session.add(log); db.session.commit()
        flash('Compte créé ! Connectez-vous.')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
