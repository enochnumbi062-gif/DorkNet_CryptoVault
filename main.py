import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import cloudinary
import cloudinary.uploader
import cloudinary.api
from functools import wraps
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

# --- CONFIGURATION SÉCURITÉ & DB ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dorknet-vault-2026')
db_url = os.getenv('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
if db_url and "sslmode" not in db_url:
    db_url += "?sslmode=require"

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- MODE BULLDOZER : FORCER LA CRÉATION DES TABLES ---
with app.app_context():
    print("🚀 BULLDOZER : Initialisation de Neon...")
    # db.drop_all() # Décommentez cette ligne UNIQUEMENT si vous voulez tout effacer et recommencer
    db.create_all() 
    print("✅ BULLDOZER : Tables 'user' et 'audit_log' créées avec succès.")

# --- CONFIGURATION LOGIN & LIMITER ---
login_manager = LoginManager(app)
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

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

# --- ROUTES ---
@app.route('/')
def index():
    return "<h1>DorkNet Xchange : Bastion Actif</h1><p>Base de données Neon connectée.</p>"

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = User(
            username=request.form.get('username'),
            password=generate_password_hash(request.form.get('password'), method='pbkdf2:sha256'),
            pin_code=generate_password_hash(request.form.get('pin'), method='pbkdf2:sha256')
        )
        db.session.add(user)
        db.session.commit()
        return "Utilisateur Enoch_dorknet créé sur Neon !"
    return '''<form method="post">
        User: <input name="username"><br>
        Pass: <input name="password" type="password"><br>
        PIN: <input name="pin" type="password"><br>
        <input type="submit">
    </form>'''

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
