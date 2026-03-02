import os
import io
import csv
import cloudinary
import cloudinary.uploader
import cloudinary.api
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text

# --- CHARGEMENT DES VARIABLES D'ENVIRONNEMENT ---
load_dotenv()

app = Flask(__name__)

# --- CONFIGURATION RÉSEAU & PORT (POUR RENDER) ---
PORT = int(os.environ.get("PORT", 10000))

# --- CONFIGURATION BASE DE DONNÉES (OPTIMISÉE NEON/POSTGRES) ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dorknet-secure-key-2026')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

db_url = os.getenv('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True, 
    "pool_recycle": 300,
    "connect_args": {"sslmode": "require"} if "postgresql" in (db_url or "") else {}
}

db = SQLAlchemy(app)

# --- SÉCURITÉ & LIMITES ---
login_manager = LoginManager(app)
login_manager.login_view = 'index'

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# --- CONFIGURATION CLOUDINARY ---
cloudinary.config(
  cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME', '').strip(),
  api_key = os.environ.get('CLOUDINARY_API_KEY', '').strip(),
  api_secret = os.environ.get('CLOUDINARY_API_SECRET', '').strip()
)

# --- MODÈLES DE DONNÉES (PLURIEL POUR ÉVITER CONFLITS POSTGRES) ---
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False) 
    pin_code = db.Column(db.Text, nullable=True)  

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.String(500))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- INITIALISATION DES TABLES ---
with app.app_context():
    try:
        db.create_all()
        print("🚀 BULLDOZER : Base de données synchronisée.")
    except Exception as e:
        print(f"❌ Erreur Init DB : {e}")

# --- DÉCORATEURS ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.username != "Enoch_dorknet":
            abort(404) 
        return f(*args, **kwargs)
    return decorated_function

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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        pwd = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')
        pin = generate_password_hash(request.form.get('pin'), method='pbkdf2:sha256')
        
        if User.query.filter_by(username=username).first():
            flash("Utilisateur déjà existant", "danger")
            return redirect(url_for('index'))
            
        new_user = User(username=username, password=pwd, pin_code=pin)
        db.session.add(new_user)
        db.session.commit()
        flash("Compte créé avec succès !", "success")
        return redirect(url_for('index'))
    return render_template('register.html')

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

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    if file:
        cloudinary.uploader.upload(file.read(), resource_type="raw", public_id=file.filename, folder="DorkNet_Vault")
        db.session.add(AuditLog(username=current_user.username, action="UPLOAD", details=file.filename))
        db.session.commit()
        flash("Fichier sécurisé dans le Cloud.", "success")
    return redirect(url_for('index'))

@app.route('/export_logs')
@login_required
@admin_required
def export_logs():
    # Route ajoutée pour éviter le crash du template index.html
    return "Fonctionnalité d'exportation en cours de maintenance."

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))

# --- ROUTE BULLDOZER (RÉPARATION D'URGENCE) ---
@app.route('/bulldozer-repair/<secret_key>')
def bulldozer_repair(secret_key):
    if secret_key != "DorkNet2026":
        abort(403)
    try:
        # Nettoie les anciens débris (singulier et pluriel)
        db.session.execute(text('DROP TABLE IF EXISTS "user" CASCADE;'))
        db.session.execute(text('DROP TABLE IF EXISTS "users" CASCADE;'))
        db.session.execute(text('DROP TABLE IF EXISTS "audit_log" CASCADE;'))
        db.session.execute(text('DROP TABLE IF EXISTS "audit_logs" CASCADE;'))
        db.session.commit()
        
        # Reconstruction propre sur Neon
        db.create_all()
        return "<h1>🚀 RÉPARATION TERMINÉE</h1><p>Tables 'users' et 'audit_logs' créées. <a href='/register'>Inscrivez-vous ici</a>.</p>"
    except Exception as e:
        db.session.rollback()
        return f"<h1>❌ ÉCHEC</h1><p>Erreur : {str(e)}</p>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
