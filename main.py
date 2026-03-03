import os
import io
import csv
import time
import magic
import ctypes
import hashlib
import requests
import threading
import cloudinary
import cloudinary.uploader
import cloudinary.api
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import text

# --- CHARGEMENT DES VARIABLES D'ENVIRONNEMENT ---
load_dotenv()

app = Flask(__name__)

# --- STYLE TERMINAL RESTAURÉ (IMAGE 1) ---
DORKNET_STYLE = """
<style>
    :root { 
        --primary: #00ff41; 
        --bg: #0d1117; 
        --card: #161b22; 
        --text: #c9d1d9; 
        --border: #30363d; 
        --danger: #ff3e3e;
    }
    body { 
        background-color: var(--bg) !important; 
        color: var(--text); 
        font-family: 'Courier New', monospace; 
        margin: 0; padding: 20px;
    }
    .container { 
        background: var(--card); 
        border: 2px solid var(--primary); 
        box-shadow: 0 0 20px rgba(0, 255, 65, 0.2); 
        border-radius: 10px;
        padding: 25px;
        max-width: 800px;
        margin: auto;
    }
    .header-box {
        border: 2px solid var(--primary);
        padding: 15px;
        text-align: center;
        margin-bottom: 30px;
        position: relative;
    }
    .header-box h1 { color: var(--primary); text-transform: uppercase; letter-spacing: 5px; margin: 0; }
    .status-line { color: var(--primary); font-size: 0.8em; margin-top: 10px; }
    
    input, select {
        background: #000 !important;
        border: 1px solid var(--primary) !important;
        color: var(--primary) !important;
        padding: 10px;
        width: 100%;
        margin-bottom: 15px;
        border-radius: 5px;
    }
    .btn-terminal {
        background: var(--primary) !important;
        color: #000 !important;
        font-weight: bold;
        text-transform: uppercase;
        border: none;
        padding: 12px;
        width: 100%;
        cursor: pointer;
        box-shadow: 0 0 15px var(--primary);
        transition: 0.3s;
        margin-top: 10px;
    }
    .btn-terminal:hover { opacity: 0.8; box-shadow: 0 0 25px var(--primary); }
    .logout-link { color: var(--danger); text-decoration: none; font-weight: bold; }
    .operator-tag { color: var(--primary); font-weight: bold; }
    .file-item { border-bottom: 1px solid var(--border); padding: 10px 0; color: #8b949e; display: flex; justify-content: space-between; }
    .alert { padding: 10px; border: 1px solid var(--primary); margin-bottom: 20px; background: rgba(0,255,65,0.1); }
</style>
"""

# --- SÉCURITÉ & PROTECTION ---
csrf = CSRFProtect(app)
# CSP assoupli pour permettre le style inline du DORKNET_STYLE
talisman = Talisman(
    app,
    content_security_policy=None, 
    force_https=True,
    session_cookie_secure=True,
    session_cookie_http_only=True
)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# --- CONFIGURATION GÉNÉRALE ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dorknet-cryptovault-secure-key')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'enc'}

db_url = os.getenv('DATABASE_URL', 'sqlite:///cryptovault.db')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'

SYSTEM_ACTIVE = True 

# --- CLOUDINARY ---
cloudinary.config(
  cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME', '').strip(),
  api_key = os.environ.get('CLOUDINARY_API_KEY', '').strip(),
  api_secret = os.environ.get('CLOUDINARY_API_SECRET', '').strip()
)

# --- CONFIGURATION EMAIL ---
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv('MAIL_USER'),
    MAIL_PASSWORD=os.getenv('MAIL_PASS'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_USER')
)
mail = Mail(app)

# --- MODÈLES DE DONNÉES ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False) 
    pin_code = db.Column(db.Text, nullable=True)
    failed_attempts = db.Column(db.Integer, default=0) 
    lockout_until = db.Column(db.DateTime, nullable=True) 

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.String(500))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- DÉCORATEURS ET UTILITAIRES ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.username != "Enoch_dorknet":
            abort(404) 
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def check_kill_switch():
    if not SYSTEM_ACTIVE and request.endpoint not in ['index', 'static', 'login', 'logout', 'register']:
        return "<h1>⚠️ ACCÈS NEUTRALISÉ - DORKNET BASTION</h1>", 503

def send_critical_alert(action, details):
    with app.app_context():
        try:
            msg = Message(subject=f"🚨 [DORKNET] ALERTE : {action}", recipients=[os.getenv('MAIL_USER')])
            msg.html = f"<b>Action:</b> {action}<br><b>Détails:</b> {details}"
            mail.send(msg)
        except Exception as e: print(f"❌ Erreur mail : {e}")

# --- ROUTES AUTHENTIFICATION ---
@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = generate_password_hash(request.form.get('password'))
    pin = generate_password_hash(request.form.get('pin'))
    if User.query.filter_by(username=username).first():
        flash("Utilisateur déjà existant", "danger")
        return redirect(url_for('index'))
    new_user = User(username=username, password=password, pin_code=pin)
    db.session.add(new_user)
    db.session.commit()
    flash("Accès généré avec succès !", "success")
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    username_input = request.form.get('username')
    password_input = request.form.get('password')
    user = User.query.filter_by(username=username_input).first()

    if not user:
        time.sleep(1.0)
        flash('Identifiants invalides.', "danger")
        return redirect(url_for('index'))

    if user.lockout_until and user.lockout_until > datetime.now():
        return f"<h1>COMPTE SCELLÉ - Réessayez après {user.lockout_until}</h1>", 403

    if check_password_hash(user.password, password_input):
        user.failed_attempts = 0
        user.lockout_until = None
        db.session.commit()
        session['pending_user_id'] = user.id
        return redirect(url_for('verify_2fa'))
    else:
        user.failed_attempts += 1
        if user.failed_attempts >= 5:
            user.lockout_until = datetime.now() + timedelta(minutes=30)
            send_critical_alert("COMPTE_VERROUILLÉ", username_input)
        db.session.commit()
        time.sleep(0.5)
        flash('Identifiants invalides.', "danger")
        return redirect(url_for('index'))

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_user_id' not in session: return redirect(url_for('index'))
    if request.method == 'POST':
        pin = request.form.get('pin')
        user = User.query.get(session['pending_user_id'])
        if user and check_password_hash(user.pin_code, pin):
            login_user(user)
            session.pop('pending_user_id')
            db.session.add(AuditLog(username=user.username, action="LOGIN_SUCCESS", details="Accès validé."))
            db.session.commit()
            return redirect(url_for('index'))
        flash("Code PIN incorrect.", "danger")
    return render_template('2fa.html', style=DORKNET_STYLE)

@app.route('/logout')
@login_required
def logout():
    db.session.add(AuditLog(username=current_user.username, action="LOGOUT", details="Session terminée."))
    db.session.commit()
    logout_user()
    session.clear()
    return redirect(url_for('index'))

# --- GESTION FICHIERS ---
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    if not file or file.filename == '': return redirect(url_for('index'))
    filename = secure_filename(file.filename)
    
    # Vérification extension et type MIME profond
    if ('.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS):
        try:
            file_content = file.read()
            file_type = magic.from_buffer(file_content, mime=True)
            if any(x in file_type for x in ["python", "executable", "shell"]):
                db.session.add(AuditLog(username=current_user.username, action="MALWARE_DETECTED", details=filename))
                db.session.commit()
                return "🚨 ALERTE : Contenu malveillant détecté.", 403

            cloudinary.uploader.upload(file_content, resource_type="raw", public_id=filename, folder="DorkNet_Vault")
            db.session.add(AuditLog(username=current_user.username, action="UPLOAD", details=filename))
            db.session.commit()
            flash('Fichier sécurisé envoyé !', "success")
        except Exception as e: flash(f"Erreur : {str(e)}", "danger")
    return redirect(url_for('index'))

@app.route('/download/<path:public_id>')
@login_required
def download_file(public_id):
    try:
        res = cloudinary.api.resource(public_id, resource_type="raw")
        response = requests.get(res['secure_url'])
        return send_file(io.BytesIO(response.content), as_attachment=True, download_name=public_id.split('/')[-1])
    except Exception as e: return redirect(url_for('index'))

# --- ADMINISTRATION ---
@app.route('/admin/logs')
@login_required
@admin_required
def admin_logs():
    all_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('admin_logs.html', logs=all_logs, style=DORKNET_STYLE)

@app.route('/admin/killswitch', methods=['POST'])
@login_required
@admin_required
def trigger_kill_switch():
    global SYSTEM_ACTIVE
    SYSTEM_ACTIVE = False
    send_critical_alert("KILL_SWITCH_ACTIVATED", f"Par {current_user.username}")
    return redirect(url_for('admin_logs'))

# --- ROUTE PRINCIPALE ---
@app.route('/')
def index():
    cloud_files = []
    if current_user.is_authenticated:
        try:
            res = cloudinary.api.resources(resource_type="raw", prefix="DorkNet_Vault/")
            if 'resources' in res:
                cloud_files = [{'public_id': r['public_id'], 'size': f"{r['bytes']/1024:.1f} KB"} for r in res['resources']]
        except: pass
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(5).all() if current_user.is_authenticated else []
    return render_template('index.html', files=cloud_files, logs=logs, style=DORKNET_STYLE)

# --- DÉMARRAGE ET RÉPARATION DB ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Correction automatique de l'erreur 500 (colonnes manquantes)
        try:
            db.session.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS failed_attempts INTEGER DEFAULT 0'))
            db.session.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS lockout_until TIMESTAMP'))
            db.session.commit()
            print("🛡️ DorkNet : Schéma DB validé et sécurisé.")
        except Exception as e:
            db.session.rollback()
            print(f"ℹ️ Migration DB : {e}")

    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
