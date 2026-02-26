import os
import io
import csv
import requests
import cloudinary
import cloudinary.uploader
import cloudinary.api
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_apscheduler import APScheduler
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- CHARGEMENT DES VARIABLES D'ENVIRONNEMENT ---
load_dotenv()

app = Flask(__name__)

# --- CONFIGURATION GÉNÉRALE ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dorknet-cryptovault-secure-key')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

# Configuration Base de données (PostgreSQL pour Render ou SQLite local)
db_url = os.getenv('DATABASE_URL', 'sqlite:///cryptovault.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'

# --- CONFIGURATION CLOUDINARY ---
cloudinary.config(
  cloud_name = os.getenv('CLOUDINARY_CLOUD_NAME'),
  api_key = os.getenv('CLOUDINARY_API_KEY'),
  api_secret = os.getenv('CLOUDINARY_API_SECRET')
)

# --- CONFIGURATION EMAIL & SCHEDULER ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASS')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USER')

mail = Mail(app)
scheduler = APScheduler()

# --- SÉCURITÉ : CLÉ AES-256 ---
aes_key_hex = os.getenv('AES_KEY')
if not aes_key_hex:
    # Génération d'une clé temporaire si absente (Attention: non persistant)
    aes_key_hex = get_random_bytes(32).hex()
ENCRYPTION_KEY = bytes.fromhex(aes_key_hex)

# --- MODÈLES DE DONNÉES ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    pin_code = db.Column(db.String(200), nullable=True)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.String(500))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- FONCTIONS AUTOMATIQUES (RAPPORTS) ---
def send_audit_report():
    with app.app_context():
        try:
            logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
            proxy = io.StringIO()
            writer = csv.writer(proxy)
            writer.writerow(['Date', 'Utilisateur', 'Action', 'Details'])
            for log in logs:
                writer.writerow([log.timestamp, log.username, log.action, log.details])
            
            msg = Message(f"Rapport d'Audit DorkNet_CryptoVault - {datetime.now().strftime('%d/%m/%Y')}",
                          recipients=[os.getenv('MAIL_USER')])
            msg.body = "Veuillez trouver ci-joint le rapport d'audit complet de DorkNet_CryptoVault."
            msg.attach(f"Audit_DorkNet_{datetime.now().strftime('%Y%m%d')}.csv", "text/csv", proxy.getvalue())
            mail.send(msg)
            print("Rapport d'audit périodique envoyé.")
        except Exception as e:
            print(f"Erreur Scheduler : {e}")

# Planification : Toutes les 48 heures
if not scheduler.running:
    scheduler.add_job(id='audit_report_job', func=send_audit_report, trigger='interval', hours=48)
    scheduler.start()

# --- ROUTES DE NAVIGATION ---

@app.route('/')
def index():
    logs, cloud_files = [], []
    if current_user.is_authenticated:
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
        try:
            resources = cloudinary.api.resources(resource_type="raw", type="upload", max_results=15)
            for res in resources.get('resources', []):
                cloud_files.append({
                    'public_id': res['public_id'],
                    'size': f"{res['bytes'] / 1024:.1f} KB"
                })
        except: pass
    return render_template('index.html', logs=logs, files=cloud_files)

@app.route('/setup_db')
def setup_db():
    """Route de secours pour forcer la création des tables sur Render"""
    try:
        db.create_all()
        return "✅ Base de données DorkNet_CryptoVault configurée avec succès !"
    except Exception as e:
        return f"❌ Erreur configuration : {str(e)}"

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_user_id' not in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        pin = request.form.get('pin')
        user = User.query.get(session['pending_user_id'])
        if user and check_password_hash(user.pin_code, pin):
            login_user(user)
            session.pop('pending_user_id')
            db.session.add(AuditLog(username=user.username, action="2FA_SUCCESS", details="Connexion validée"))
            db.session.commit()
            return redirect(url_for('index'))
        else:
            flash("Code PIN invalide.", "danger")
    return render_template('2fa.html')

# --- GESTION DES FICHIERS & SÉCURITÉ ---

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    if file:
        try:
            cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(file.read())
            enc_filename = file.filename + '.enc'
            
            with open(enc_filename, 'wb') as f:
                [f.write(x) for x in (nonce, tag, ciphertext)]
            
            cloudinary.uploader.upload(enc_filename, resource_type="raw")
            os.remove(enc_filename)
            
            db.session.add(AuditLog(username=current_user.username, action="UPLOAD", details=f"Fichier : {file.filename}"))
            db.session.commit()
            flash(f'Succès : {file.filename} est sécurisé !', "success")
        except Exception as e: flash(f'Erreur : {str(e)}', "danger")
    return redirect(url_for('index'))

@app.route('/download_cloud/<path:public_id>')
@login_required
def download_cloud(public_id):
    try:
        res = cloudinary.api.resource(public_id, resource_type="raw")
        response = requests.get(res['secure_url'])
        enc_data = response.content
        nonce, tag, ciphertext = enc_data[:16], enc_data[16:32], enc_data[32:]
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return send_file(io.BytesIO(decrypted_data), as_attachment=True, download_name=public_id.replace('.enc', ''))
    except Exception as e: flash(f"Erreur : {str(e)}", "danger"); return redirect(url_for('index'))

# --- AUTHENTIFICATION ---

@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(username=request.form.get('username')).first()
    if user and check_password_hash(user.password, request.form.get('password')):
        session['pending_user_id'] = user.id
        return redirect(url_for('verify_2fa'))
    flash('Identifiants incorrects.', "danger")
    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    pin = request.form.get('pin')
    
    if User.query.filter_by(username=username).first():
        flash('Pseudo utilisé.', "danger")
    else:
        new_user = User(
            username=username, 
            password=generate_password_hash(password, method='pbkdf2:sha256'),
            pin_code=generate_password_hash(pin, method='pbkdf2:sha256')
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Compte créé ! Connectez-vous.', "success")
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))

# --- LANCEMENT ET INITIALISATION ---

# Cette partie assure la création des tables au lancement sur Render
with app.app_context():
    try:
        db.create_all()
        print("✅ Base de données DorkNet_CryptoVault initialisée avec succès.")
    except Exception as e:
        print(f"❌ Erreur lors de l'initialisation de la DB : {e}")

if __name__ == '__main__':
    # Configuration pour Render (port dynamique)
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
