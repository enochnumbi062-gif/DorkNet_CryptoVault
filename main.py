import os
import io
import requests
import cloudinary
import cloudinary.uploader
import cloudinary.api
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

load_dotenv()
app = Flask(__name__)

# Sécurité & Limiteur
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day"], storage_uri="memory://")

# Database
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dorknet-secret-88')
db_url = os.getenv('DATABASE_URL', 'sqlite:///cryptovault.db')
if db_url.startswith("postgres://"): db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'

# Cloudinary
cloudinary.config(cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'), api_key=os.getenv('CLOUDINARY_API_KEY'), api_secret=os.getenv('CLOUDINARY_API_SECRET'))

ENCRYPTION_KEY = bytes.fromhex(os.getenv('AES_KEY', get_random_bytes(32).hex()))

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
def load_user(user_id): return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.username != "Enoch_dorknet": abort(403)
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    files, logs = [], []
    if current_user.is_authenticated:
        try:
            res = cloudinary.api.resources(resource_type="raw", max_results=10)
            files = [{'public_id': r['public_id'], 'size': f"{r['bytes']/1024:.1} KB"} for r in res.get('resources', [])]
            logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(5).all()
        except: pass
    return render_template('index.html', files=files, logs=logs)

@app.route('/register', methods=['POST'])
def register():
    user = User(username=request.form.get('username'), 
                password=generate_password_hash(request.form.get('password')),
                pin_code=generate_password_hash(request.form.get('pin')))
    db.session.add(user)
    db.session.commit()
    flash("Accès généré. Connectez-vous.", "success")
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(username=request.form.get('username')).first()
    if user and check_password_hash(user.password, request.form.get('password')):
        session['pending_id'] = user.id
        return render_template('2fa.html')
    flash("Erreur d'accès.", "danger")
    return redirect(url_for('index'))

@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    user = User.query.get(session.get('pending_id'))
    if user and check_password_hash(user.pin_code, request.form.get('pin')):
        login_user(user)
        return redirect(url_for('index'))
    return "Code PIN incorrect", 401

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin/logs')
@admin_required
def admin_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('admin_logs.html', logs=logs)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    if file:
        cloudinary.uploader.upload(file, resource_type="raw", public_id=file.filename)
        db.session.add(AuditLog(username=current_user.username, action="UPLOAD", details=file.filename))
        db.session.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
