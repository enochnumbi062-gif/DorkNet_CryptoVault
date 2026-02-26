import os
import io
import csv
import requests
import cloudinary
import cloudinary.uploader
import cloudinary.api
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_apscheduler import APScheduler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- CHARGEMENT DES VARIABLES D'ENVIRONNEMENT ---
load_dotenv()

app = Flask(__name__)

# --- CONFIGURATION ANTI-BRUTE FORCE ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# --- CONFIGURATION GÉNÉRALE & BASE DE DONNÉES ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dorknet-cryptovault-secure-key')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

db_url = os.getenv('DATABASE_URL', 'sqlite:///cryptovault.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'

# --- ÉTAT DU SYSTÈME (KILL SWITCH) ---
SYSTEM_ACTIVE = True 

# --- CONFIGURATION CLOUDINARY ---
cloudinary.config(
  cloud_name = os.getenv('CLOUDINARY_CLOUD_NAME'),
  api_key = os.getenv('CLOUDINARY_API_KEY'),
  api_secret = os.getenv('CLOUDINARY_API_SECRET')
)

# --- CONFIGURATION EMAIL & SCHEDULER ---
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv('MAIL_USER'),
    MAIL_PASSWORD=os.getenv('MAIL_PASS'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_USER')
)

mail = Mail(app)
scheduler = APScheduler()

# --- SÉCURITÉ : CLÉ AES-256 (SERVEUR) ---
aes_key_hex = os.getenv('AES_KEY')
if not aes_key_hex:
    aes_key_hex = get_random_bytes(32).hex()
ENCRYPTION_KEY = bytes.fromhex(aes_key_hex)

# --- MODÈLES DE DONNÉES ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False) 
    pin_code = db.Column(db.Text, nullable=True)  

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.String(500))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- DÉCORATEURS ET MIDDLEWARES ---

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.username != "Enoch_dorknet":
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def check_kill_switch():
    if not SYSTEM_ACTIVE and request.endpoint not in ['index', 'static', 'login', 'logout']:
        return "<h1>⚠️ ACCÈS NEUTRALISÉ</h1><p>Le bastion DorkNet CryptoVault est en mode confinement de sécurité par le Dr Enoch Numbi.</p>", 503

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# --- ALERTES & AUDIT ---

def send_critical_alert(action, details):
    with app.app_context():
        try:
            msg = Message(
                subject=f"🚨 [DORKNET CRYPTOVAULT] VIOLATION DÉTECTÉE : {action}",
                recipients=[os.getenv('MAIL_USER')],
                extra_headers={'X-Priority': '1', 'Importance': 'high'}
            )
            msg.html = f"""
            <div style="font-family: sans-serif; border: 2px solid #d9534f; border-radius: 8px; max-width: 600px;">
                <div style="background-color: #d9534f; color: white; padding: 20px; text-align: center;"><h1>ALERTE SÉCURITÉ CRITIQUE</h1></div>
                <div style="padding: 25px;">
                    <p>Attention <strong>Dr Enoch Numbi</strong>, anomalie détectée :</p>
                    <p><b>Action:</b> {action}<br><b>Détails:</b> {details}</p>
                </div>
            </div>
            """
            mail.send(msg)
        except Exception as e: print(f"❌ Erreur mail : {e}")

# --- ROUTES AUTHENTIFICATION ---

@app.route('/login', methods=['POST'])
@limiter.limit("10 per hour")
def login():
    user = User.query.filter_by(username=request.form.get('username')).first()
    if user and check_password_hash(user.password, request.form.get('password')):
        session['pending_user_id'] = user.id
        return redirect(url_for('verify_2fa'))
    flash('Identifiants invalides.', "danger")
    return redirect(url_for('index'))

@app.route('/verify_2fa', methods=['GET', 'POST'])
@limiter.limit("5 per 15 minutes")
def verify_2fa():
    if 'pending_user_id' not in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        pin = request.form.get('pin')
        user = User.query.get(session['pending_user_id'])
        if user and check_password_hash(user.pin_code, pin):
            login_user(user)
            session.pop('pending_user_id')
            db.session.add(AuditLog(username=user.username, action="LOGIN_SUCCESS", details="Accès bastion validé."))
            db.session.commit()
            return redirect(url_for('index'))
        flash("Code PIN incorrect.", "danger")
    return render_template('2fa.html')

# --- GESTION FICHIERS & HONEYTOKEN ---

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    if file:
        try:
            # Le fichier arrive déjà chiffré par le JS (Client-Side)
            # On applique une seconde couche de sécurité Serveur (Double Barrière)
            cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(file.read())
            
            enc_filename = file.filename # Le nom contient déjà .enc
            buffer = io.BytesIO()
            [buffer.write(x) for x in (nonce, tag, ciphertext)]
            buffer.seek(0)
            
            cloudinary.uploader.upload(buffer, resource_type="raw", public_id=enc_filename)
            
            db.session.add(AuditLog(username=current_user.username, action="UPLOAD", details=file.filename))
            db.session.commit()
            flash('Fichier sécurisé et envoyé !', "success")
        except Exception as e: flash(str(e), "danger")
    return redirect(url_for('index'))

@app.route('/download_cloud/<path:public_id>')
@login_required
def download_cloud(public_id):
    # --- PIÈGE HONEYTOKEN ---
    if "passwords_importants" in public_id.lower():
        error_msg = f"⚠️ INTRUSION : Tentative d'accès au fichier piège par @{current_user.username}."
        db.session.add(AuditLog(username=current_user.username, action="HONEYTOKEN_TRIGGER", details=error_msg))
        db.session.commit()
        send_critical_alert("HONEYTOKEN_TRIGGERED", error_msg)
        flash("🚫 Erreur critique de sécurité.", "danger")
        return redirect(url_for('index'))

    try:
        res = cloudinary.api.resource(public_id, resource_type="raw")
        response = requests.get(res['secure_url'])
        enc_data = response.content
        
        # Déchiffrement de la couche Serveur
        nonce, tag, ciphertext = enc_data[:16], enc_data[16:32], enc_data[32:]
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX, nonce=nonce)
        decrypted_layer = cipher.decrypt_and_verify(ciphertext, tag)
        
        db.session.add(AuditLog(username=current_user.username, action="DOWNLOAD_SUCCESS", details=public_id))
        db.session.commit()
        # On envoie le fichier (toujours chiffré par la clé client JS)
        return send_file(io.BytesIO(decrypted_layer), as_attachment=True, download_name=public_id)
    except Exception as e:
        send_critical_alert("SECURITY_BREACH", f"Échec intégrité sur {public_id}")
        flash("🚫 Intégrité compromise.", "danger")
        return redirect(url_for('index'))

# --- ROUTES ADMIN ---

@app.route('/admin/logs')
@login_required
@admin_required
def admin_logs():
    all_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('admin_logs.html', logs=all_logs)

@app.route('/admin/killswitch', methods=['POST'])
@login_required
@admin_required
def trigger_kill_switch():
    global SYSTEM_ACTIVE
    SYSTEM_ACTIVE = False
    send_critical_alert("KILL_SWITCH_ACTIVATED", "Confinement manuel activé.")
    db.session.add(AuditLog(username=current_user.username, action="SYS_LOCKDOWN", details="Mode Silence Radio activé."))
    db.session.commit()
    flash("🚨 BASTION VERROUILLÉ.", "danger")
    return redirect(url_for('admin_logs'))

@app.route('/')
def index():
    cloud_files = []
    logs = []
    if current_user.is_authenticated:
        try:
            res = cloudinary.api.resources(resource_type="raw", type="upload", max_results=15)
            for r in res.get('resources', []):
                cloud_files.append({'public_id': r['public_id'], 'size': f"{r['bytes']/1024:.1f} KB"})
            logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
        except: pass
    return render_template('index.html', files=cloud_files, logs=logs)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
