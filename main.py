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
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

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

# --- CONFIGURATION BASE DE DONNÉES (OPTIMISÉE NEON) ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dorknet-cryptovault-secure-key')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

db_url = os.getenv('DATABASE_URL')
if db_url:
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    if "sslmode" not in db_url:
        db_url += "?sslmode=require"
else:
    db_url = 'sqlite:///cryptovault.db'

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
}

db = SQLAlchemy(app)

# --- INITIALISATION AUTOMATIQUE DU TERRITOIRE (FORCÉE) ---
# Ce bloc s'exécute même sous Gunicorn pour créer les tables sur Neon
with app.app_context():
    try:
        db.create_all()
        print("✅ Base de données Neon synchronisée (Tables créées ou déjà existantes).")
    except Exception as e:
        print(f"⚠️ Erreur d'initialisation DB : {e}")

login_manager = LoginManager(app)
login_manager.login_view = 'index'

# --- ÉTAT DU SYSTÈME ---
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

# --- DÉCORATEURS ET SÉCURITÉ ---

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.username != "Enoch_dorknet":
            if 'admin_violation_count' not in session:
                session['admin_violation_count'] = 0
            session['admin_violation_count'] += 1
            
            if session['admin_violation_count'] >= 3:
                db.session.add(AuditLog(username="INTRUS", action="BOMBE_DECONNEXION", details=get_remote_address()))
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

# --- ROUTES ---

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

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    pwd = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')
    pin = generate_password_hash(request.form.get('pin'), method='pbkdf2:sha256')
    
    if User.query.filter_by(username=username).first():
        flash("Utilisateur déjà existant", "danger")
        return redirect(url_for('index'))
    
    db.session.add(User(username=username, password=pwd, pin_code=pin))
    db.session.commit()
    flash("Accès au bastion généré !", "success")
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
@limiter.limit("10 per hour")
def login():
    user = User.query.filter_by(username=request.form.get('username')).first()
    if user and check_password_hash(user.password, request.form.get('password')):
        session['pending_user_id'] = user.id
        return redirect(url_for('verify_2fa'))
    flash('Identifiants invalides', "danger")
    return redirect(url_for('index'))

@app.route('/verify_2fa', methods=['GET', 'POST'])
@limiter.limit("5 per 15 minutes")
def verify_2fa():
    if 'pending_user_id' not in session: return redirect(url_for('index'))
    if request.method == 'POST':
        user = User.query.get(session['pending_user_id'])
        if user and check_password_hash(user.pin_code, request.form.get('pin')):
            login_user(user)
            session.pop('pending_user_id')
            db.session.add(AuditLog(username=user.username, action="LOGIN_SUCCESS"))
            db.session.commit()
            return redirect(url_for('index'))
        flash("Code PIN erroné", "danger")
    return render_template('2fa.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    if file:
        cloudinary.uploader.upload(file.read(), resource_type="raw", public_id=file.filename, folder="DorkNet_Vault")
        db.session.add(AuditLog(username=current_user.username, action="UPLOAD", details=file.filename))
        db.session.commit()
        flash("Fichier envoyé au coffre-fort.", "success")
    return redirect(url_for('index'))

@app.route('/admin/logs')
@limiter.limit("3 per day")
@login_required
@admin_required
def admin_logs():
    all_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('admin_logs.html', logs=all_logs)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
