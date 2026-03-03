import os
import io
import csv
import time
import magic
import ctypes
import sys
import requests
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

# --- CONFIGURATION DU BOUCLIER HTTP (TALISMAN) ---
csp = {
    'default-src': '\'self\'',
    'script-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net'
    ],
    'style-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net',
        '\'unsafe-inline\'' 
    ]
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    force_https=True,
    session_cookie_secure=True,
    session_cookie_http_only=True
)

# --- PROTECTION CSRF (FLASK-WTF) ---
csrf = CSRFProtect(app)

# --- CONFIGURATION ANTI-BRUTE FORCE ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# --- CONFIGURATION GÉNÉRALE & BDD ---
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

# --- CONFIGURATION CLOUDINARY ---
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

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.String(500))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- MÉMOIRE VIVE : PROTOCOLE D'EFFACEMENT ---
def wipe_memory(variable):
    if not isinstance(variable, (str, bytes, bytearray)):
        return False
    location = id(variable)
    size = sys.getsizeof(variable)
    try:
        offset = 32 if isinstance(variable, str) else 20
        ctypes.memset(location + offset, 0, size - offset)
        return True
    except Exception as e:
        print(f"⚠️ Erreur de Wiper : {e}")
        return False

# --- DÉCORATEURS ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.username != "Enoch_dorknet":
            if 'admin_violation_count' not in session:
                session['admin_violation_count'] = 0
            session['admin_violation_count'] += 1
            if session['admin_violation_count'] >= 3:
                db.session.add(AuditLog(
                    username=current_user.username if current_user.is_authenticated else "INTRUS_ANONYME",
                    action="BOMBE_DECONNEXION",
                    details=f"Violation répétée. IP: {get_remote_address()}"
                ))
                db.session.commit()
                logout_user()
                session.clear()
                flash("🚨 ALERTE SÉCURITÉ : Session neutralisée.", "danger")
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
    flash("Accès généré !", "success")
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    username_input = request.form.get('username')
    password_input = request.form.get('password')
    time.sleep(0.5) # Anti-Timing Attack
    user = User.query.filter_by(username=username_input).first()
    if user and check_password_hash(user.password, password_input):
        session['pending_user_id'] = user.id
        return redirect(url_for('verify_2fa'))
    db.session.add(AuditLog(username=username_input or "INCONNU", action="LOGIN_FAILED", details="Tentative rejetée."))
    db.session.commit()
    flash('Accès refusé par le protocole.', "danger")
    wipe_memory(password_input)
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
            db.session.add(AuditLog(username=user.username, action="LOGIN_SUCCESS", details="Bastion validé."))
            db.session.commit()
            wipe_memory(pin)
            return redirect(url_for('index'))
        flash("Code PIN incorrect.", "danger")
    return render_template('2fa.html')

@app.route('/logout')
@login_required
def logout():
    db.session.add(AuditLog(username=current_user.username, action="LOGOUT", details="Session terminée."))
    db.session.commit()
    logout_user()
    session.clear()
    return redirect(url_for('index'))

# --- GESTION FICHIERS (DPI & ANTI-MALWARE) ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files: return redirect(url_for('index'))
    file = request.files['file']
    if file.filename == '': return redirect(url_for('index'))
    filename = secure_filename(file.filename)
    if file and allowed_file(filename):
        file_content = file.read()
        file_type = magic.from_buffer(file_content, mime=True)
        if any(x in file_type for x in ["python", "executable", "shell"]):
            db.session.add(AuditLog(username=current_user.username, action="MALWARE_DETECTED", details=f"Fichier bloqué : {filename}"))
            db.session.commit()
            return "🚨 ALERTE : Contenu malveillant détecté.", 403
        try:
            cloudinary.uploader.upload(file_content, resource_type="raw", public_id=filename, folder="DorkNet_Vault", invalidate=True)
            db.session.add(AuditLog(username=current_user.username, action="UPLOAD", details=filename))
            db.session.commit()
            flash('Fichier analysé et sécurisé !', "success")
        except Exception as e: flash(f"Erreur Cloud : {str(e)}", "danger")
        finally: wipe_memory(file_content)
    return redirect(url_for('index'))

@app.route('/download_cloud/<path:public_id>')
@login_required
def download_cloud(public_id):
    try:
        res = cloudinary.api.resource(public_id, resource_type="raw")
        response = requests.get(res['secure_url'])
        return send_file(io.BytesIO(response.content), as_attachment=True, download_name=public_id)
    except Exception as e: return redirect(url_for('index'))

# --- ADMINISTRATION ---
@app.route('/admin/logs')
@limiter.limit("3 per day")
@login_required
@admin_required
def admin_logs():
    all_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('admin_logs.html', logs=all_logs)

@app.route('/admin/export_logs')
@login_required
@admin_required
def export_logs():
    all_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'Operateur', 'Action', 'Details'])
    for log in all_logs:
        writer.writerow([log.id, log.timestamp, log.username, log.action, log.details])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')), mimetype='text/csv', as_attachment=True, download_name="DorkNet_Audit.csv")

@app.route('/admin/killswitch', methods=['POST'])
@login_required
@admin_required
def trigger_kill_switch():
    global SYSTEM_ACTIVE
    SYSTEM_ACTIVE = False
    send_critical_alert("KILL_SWITCH_ACTIVATED", f"Par {current_user.username}")
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

# --- DÉMARRAGE AVEC DÉTECTION DE PORT RENDER ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
