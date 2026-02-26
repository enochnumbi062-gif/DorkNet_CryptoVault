import os
import io
import csv
import requests
import cloudinary
import cloudinary.uploader
import cloudinary.api
from dotenv import load_dotenv
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Chargement des variables d'environnement
load_dotenv()

app = Flask(__name__)

# --- CONFIGURATION GÉNÉRALE ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dorknet-xchange-88-secure-key')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

# Configuration Base de données
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
    # Génération automatique si absente (Attention: non persistant sur Render sans variable d'env)
    aes_key_hex = get_random_bytes(32).hex()
ENCRYPTION_KEY = bytes.fromhex(aes_key_hex)

# --- MODÈLES DE DONNÉES ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    pin_code = db.Column(db.String(200), nullable=True) # Nouveau : Stockage du PIN 2FA haché

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.String(500))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES DE NAVIGATION & DASHBOARD ---

@app.route('/')
def index():
    db.create_all()
    logs = []
    cloud_files = []
    if current_user.is_authenticated:
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
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

# --- SYSTÈME DE DOUBLE AUTHENTIFICATION (2FA) ---

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
            log = AuditLog(username=user.username, action="2FA_SUCCESS", details="Authentification biométrique/PIN réussie")
            db.session.add(log); db.session.commit()
            return redirect(url_for('index'))
        else:
            flash("Code PIN invalide. Accès refusé.", "danger")
            
    return render_template('2fa.html')

# --- DIAGNOSTIC & SÉCURITÉ ---

@app.route('/test_key')
@login_required
def test_key():
    try:
        test_data = b"DorkNet_Integrity_Check"
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(test_data)
        
        cipher_dec = AES.new(ENCRYPTION_KEY, AES.MODE_EAX, nonce=nonce)
        decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)
        
        if decrypted == test_data:
            flash("✅ Diagnostic : La clé AES-256 est active et fonctionnelle.", "success")
        else:
            flash("⚠️ Diagnostic : Erreur d'intégrité de la clé.", "danger")
    except Exception as e:
        flash(f"❌ Échec du test : {str(e)}", "danger")
    return redirect(url_for('index'))

# --- GESTION DES FICHIERS CLOUD ---

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    if file and file.filename != '':
        try:
            cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(file.read())
            
            enc_filename = file.filename + '.enc'
            with open(enc_filename, 'wb') as f:
                [f.write(x) for x in (nonce, tag, ciphertext)]
            
            cloudinary.uploader.upload(enc_filename, resource_type="raw")
            
            if os.path.exists(enc_filename):
                os.remove(enc_filename)
            
            log = AuditLog(username=current_user.username, action="CLOUD_UPLOAD", details=f"Fichier chiffré : {file.filename}")
            db.session.add(log); db.session.commit()
            flash(f'Succès : {file.filename} est sécurisé dans le Cloud !', "success")
        except Exception as e:
            flash(f'Erreur : {str(e)}', "danger")
    return redirect(url_for('index'))

@app.route('/download_cloud/<path:public_id>')
@login_required
def download_cloud(public_id):
    try:
        res = cloudinary.api.resource(public_id, resource_type="raw")
        file_url = res['secure_url']
        response = requests.get(file_url)
        enc_data = response.content
        
        nonce, tag, ciphertext = enc_data[:16], enc_data[16:32], enc_data[32:]
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        
        original_name = public_id.replace('.enc', '')
        log = AuditLog(username=current_user.username, action="CLOUD_DECRYPT", details=f"Récupération déchiffrée : {original_name}")
        db.session.add(log); db.session.commit()
        
        return send_file(io.BytesIO(decrypted_data), as_attachment=True, download_name=original_name)
    except Exception as e:
        flash(f"Erreur de déchiffrement : {str(e)}", "danger")
        return redirect(url_for('index'))

@app.route('/delete_cloud/<path:public_id>')
@login_required
def delete_cloud(public_id):
    try:
        cloudinary.uploader.destroy(public_id, resource_type="raw")
        log = AuditLog(username=current_user.username, action="CLOUD_DELETE", details=f"Suppression : {public_id}")
        db.session.add(log); db.session.commit()
        flash(f"Fichier supprimé définitivement du Cloud.", "success")
    except Exception as e:
        flash(f"Erreur suppression : {str(e)}", "danger")
    return redirect(url_for('index'))

# --- AUTHENTIFICATION ---

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    
    if user and check_password_hash(user.password, password):
        # Étape 1 réussie : Engagement du 2FA
        session['pending_user_id'] = user.id
        return redirect(url_for('verify_2fa'))
    else:
        flash('Identifiants incorrects.', "danger")
    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    pin = request.form.get('pin')
    
    if User.query.filter_by(username=username).first():
        flash('Pseudo déjà utilisé.', "danger")
    elif not pin or len(pin) < 4:
        flash('Le code PIN doit contenir au moins 4 chiffres.', "danger")
    else:
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        hashed_pin = generate_password_hash(pin, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_pw, pin_code=hashed_pin)
        db.session.add(new_user)
        log = AuditLog(username=username, action="INSCRIPTION", details="Nouveau compte DorkNet avec 2FA")
        db.session.add(log); db.session.commit()
        flash('Compte créé avec succès ! Connectez-vous.', "success")
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))

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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
