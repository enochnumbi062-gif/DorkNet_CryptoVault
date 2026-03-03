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

# --- CHARGEMENT DES VARIABLES D'ENVIRONNEMENT ---
load_dotenv()

app = Flask(__name__)

# --- PROTECTION CSRF & BOUCLIER HTTP ---
csrf = CSRFProtect(app)
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://cdn.jsdelivr.net'],
    'style-src': ['\'self\'', 'https://cdn.jsdelivr.net']
}
talisman = Talisman(
    app,
    content_security_policy=csp,
    force_https=True,
    session_cookie_secure=True,
    session_cookie_http_only=True
)

# --- CONFIGURATION ANTI-BRUTE FORCE ---
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

# --- CONFIGURATION CLOUDINARY & MAIL ---
cloudinary.config(
  cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME', '').strip(),
  api_key = os.environ.get('CLOUDINARY_API_KEY', '').strip(),
  api_secret = os.environ.get('CLOUDINARY_API_SECRET', '').strip()
)

app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv('MAIL_USER'),
    MAIL_PASSWORD=os.getenv('MAIL_PASS'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_USER')
)
mail = Mail(app)

# --- MODÈLES DE DONNÉES SÉCURISÉS ---
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

# --- OUTILS DE SÉCURITÉ BAS-NIVEAU ---

def wipe_memory(variable):
    if not isinstance(variable, (str, bytes, bytearray)): return False
    location, size = id(variable), sys.getsizeof(variable)
    try:
        offset = 32 if isinstance(variable, str) else 20
        ctypes.memset(location + offset, 0, size - offset)
        return True
    except: return False

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- DÉCORATEURS & MIDDLEWARE ---

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.username != "Enoch_dorknet":
            session['admin_violation'] = session.get('admin_violation', 0) + 1
            if session['admin_violation'] >= 3:
                db.session.add(AuditLog(username="INTRUS", action="BOMBE", details=f"IP: {get_remote_address()}"))
                db.session.commit()
                logout_user()
                session.clear()
                return redirect(url_for('index'))
            abort(404) 
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def check_kill_switch():
    if not SYSTEM_ACTIVE and request.endpoint not in ['index', 'static', 'login', 'logout', 'register']:
        return "<h1>⚠️ ACCÈS NEUTRALISÉ</h1>", 503

def send_critical_alert(action, details):
    with app.app_context():
        try:
            msg = Message(subject=f"🚨 [DORKNET] {action}", recipients=[os.getenv('MAIL_USER')])
            msg.html = f"<b>Action:</b> {action}<br><b>Détails:</b> {details}"
            mail.send(msg)
        except: pass

# --- ROUTES AUTHENTIFICATION (ANTI-EXTRACTION & LOCKOUT) ---

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    username_input = request.form.get('username')
    password_input = request.form.get('password')
    user = User.query.filter_by(username=username_input).first()

    if not user:
        time.sleep(1.0)
        return abort(401)

    if user.lockout_until and user.lockout_until > datetime.now():
        db.session.add(AuditLog(username=username_input, action="LOCKOUT_HIT", details="Compte scellé."))
        db.session.commit()
        return "<h1>COMPTE SCELLÉ</h1>", 403

    if check_password_hash(user.password, password_input):
        user.failed_attempts = 0
        user.lockout_until = None
        db.session.commit()
        # Sécurité session
        old_pending = session.get('pending_user_id')
        session.clear() 
        session['pending_user_id'] = user.id
        return redirect(url_for('verify_2fa'))
    else:
        user.failed_attempts += 1
        if user.failed_attempts >= 5:
            user.lockout_until = datetime.now() + timedelta(minutes=30)
            send_critical_alert("COMPTE_VERROUILLÉ", username_input)
        db.session.commit()
        time.sleep(0.5)
        flash('Accès refusé.', "danger")
        return redirect(url_for('index'))

@app.route('/verify_2fa', methods=['GET', 'POST'])
@limiter.limit("5 per 15 minutes")
def verify_2fa():
    if 'pending_user_id' not in session: return redirect(url_for('index'))
    if request.method == 'POST':
        pin = request.form.get('pin')
        user = User.query.get(session['pending_user_id'])
        if user and check_password_hash(user.pin_code, pin):
            login_user(user)
            session.pop('pending_user_id')
            db.session.add(AuditLog(username=user.username, action="LOGIN_SUCCESS", details="2FA Validé"))
            db.session.commit()
            wipe_memory(pin) # Nettoyage RAM
            return redirect(url_for('index'))
        flash("Code PIN incorrect.", "danger")
    return render_template('2fa.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    if User.query.filter_by(username=username).first(): return redirect(url_for('index'))
    new_user = User(
        username=username, 
        password=generate_password_hash(request.form.get('password')),
        pin_code=generate_password_hash(request.form.get('pin'))
    )
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('index'))

# --- ROUTES FICHIERS (DEEP INSPECTION & HONEYPOT) ---

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    if not file or file.filename == '': return redirect(url_for('index'))
    
    filename = secure_filename(file.filename)
    if allowed_file(filename):
        file_content = file.read()
        # Analyse MIME réelle
        file_type = magic.from_buffer(file_content, mime=True)
        if any(x in file_type for x in ["python", "executable", "shell"]):
            db.session.add(AuditLog(username=current_user.username, action="MALWARE_DETECTED", details=filename))
            db.session.commit()
            return "🚨 ALERTE : Contenu interdit.", 403

        try:
            cloudinary.uploader.upload(file_content, resource_type="raw", public_id=filename, folder="DorkNet_Vault")
            db.session.add(AuditLog(username=current_user.username, action="UPLOAD", details=filename))
            db.session.commit()
            flash('Fichier sécurisé !', "success")
        except Exception as e: flash(f"Erreur : {str(e)}", "danger")
    return redirect(url_for('index'))

@app.route('/admin/config_backup')
def honeypot_trap():
    send_critical_alert("HONEYPOT_CRITIQUE", f"IP: {get_remote_address()}")
    return abort(404)

# --- INTEGRITY SENTINEL (S'exécute en tâche de fond) ---

def start_integrity_sentinel():
    critical_files = ['main.py', '.env']
    ref_hash = hashlib.sha256()
    for f in critical_files:
        if os.path.exists(f):
            with open(f, "rb") as file: ref_hash.update(file.read())
    reference = ref_hash.hexdigest()
    
    while True:
        time.sleep(60)
        check = hashlib.sha256()
        for f in critical_files:
            if os.path.exists(f):
                with open(f, "rb") as file: check.update(file.read())
        if check.hexdigest() != reference:
            print("🚨 VIOLATION D'INTÉGRITÉ !")
            # Déclencher ici une alerte mail ou arrêt

# --- ROUTES ADMIN & INDEX (CONSERVÉES) ---

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin/logs')
@admin_required
def admin_logs():
    all_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('admin_logs.html', logs=all_logs)

@app.route('/admin/killswitch', methods=['POST'])
@admin_required
def trigger_kill_switch():
    global SYSTEM_ACTIVE
    SYSTEM_ACTIVE = False
    return redirect(url_for('admin_logs'))

@app.route('/')
def index():
    cloud_files = []
    if current_user.is_authenticated:
        try:
            res = cloudinary.api.resources(resource_type="raw")
            if 'resources' in res:
                cloud_files = [{'public_id': r['public_id'], 'size': f"{r['bytes']/1024:.1f} KB"} for r in res['resources']]
        except: pass
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all() if current_user.is_authenticated else []
    return render_template('index.html', files=cloud_files, logs=logs)

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    # Lancement de la sentinelle dans un thread séparé
    threading.Thread(target=start_integrity_sentinel, daemon=True).start()
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
