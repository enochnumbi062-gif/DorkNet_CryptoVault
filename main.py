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

# Chargement des variables d'environnement
load_dotenv()

app = Flask(__name__)

# --- CONFIGURATION GÉNÉRALE ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dorknet-xchange-88-secure-key')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

# Configuration Base de données (PostgreSQL ou SQLite)
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
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
        proxy = io.StringIO()
        writer = csv.writer(proxy)
        writer.writerow(['Date', 'Utilisateur', 'Action', 'Details'])
        for log in logs:
            writer.writerow([log.timestamp, log.username, log.action, log.details])
        
        msg = Message(f"Rapport d'Audit DorkNet Xchange - {datetime.now().strftime('%d/%m/%Y')}",
                      recipients=[os.getenv('MAIL_USER')])
        msg.body = "Veuillez trouver ci-joint le rapport d'audit complet des dernières 48 heures de DorkNet Xchange."
        msg.attach(f"Audit_DorkNet_{datetime.now().strftime('%Y%m%d')}.csv", "text/csv", proxy.getvalue())
        mail.send(msg)
        print("Rapport d'audit périodique envoyé.")

# Planification : Toutes les 48 heures
scheduler.add_job(id='audit_report_job', func=send_audit_report, trigger='interval', hours=48)
scheduler.start()

# --- ROUTES DE NAVIGATION ---

@app.route('/')
def index():
    db.create_all()
    logs, cloud_files = [], []
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
        except: pass
    return render_template('index.html', logs=logs, files=cloud_files)

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
            log = AuditLog(username=user.username, action="2FA_SUCCESS", details="Connexion sécurisée validée")
            db.session.add(log); db.session.commit()
            return redirect(url_for('index'))
        else:
            flash("Code PIN invalide.", "danger")
    return render_template('2fa.html')

@app.route('/test_key')
@login_required
def test_key():
    try:
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(b"test")
        cipher_dec = AES.new(ENCRYPTION_KEY, AES.MODE_EAX, nonce=cipher.nonce)
        if cipher_dec.decrypt_and_verify(ciphertext, tag) == b"test":
            flash("✅ Clé AES-256 opérationnelle.", "success")
        else: flash("⚠️ Erreur d'intégrité.", "danger")
    except Exception as e: flash(f"❌ Échec : {str(e)}", "danger")
    return redirect(url_for('index'))

@app.route('/test_mail')
@login_required
def test_mail():
    try:
        send_audit_report()
        return f"✅ Rapport envoyé à {os.getenv('MAIL_USER')}"
    except Exception as e: return f"❌ Erreur SMTP : {str(e)}"

# --- GESTION DES FICHIERS ---

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
            log = AuditLog(username=current_user.username, action="UPLOAD", details=f"Fichier : {file.filename}")
            db.session.add(log); db.session.commit()
            flash(f'Succès : {file.filename} est chiffré dans le Cloud !', "success")
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

@app.route('/delete_cloud/<path:public_id>')
@login_required
def delete_cloud(public_id):
    try:
        cloudinary.uploader.destroy(public_id, resource_type="raw")
        db.session.add(AuditLog(username=current_user.username, action="DELETE", details=public_id))
        db.session.commit()
        flash("Supprimé du Cloud.", "success")
    except Exception as e: flash(str(e), "danger")
    return redirect(url_for('index'))

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
    username, password, pin = request.form.get('username'), request.form.get('password'), request.form.get('pin')
    if User.query.filter_by(username=username).first(): flash('Pseudo utilisé.', "danger")
    else:
        new_user = User(username=username, 
                        password=generate_password_hash(password, method='pbkdf2:sha256'),
                        pin_code=generate_password_hash(pin, method='pbkdf2:sha256'))
        db.session.add(new_user); db.session.commit()
        flash('Compte créé ! Connectez-vous.', "success")
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    logout_user(); session.clear()
    return redirect(url_for('index'))

@app.route('/export_logs')
@login_required
def export_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    proxy = io.StringIO()
    writer = csv.writer(proxy)
    writer.writerow(['Date', 'Utilisateur', 'Action', 'Details'])
    for log in logs: writer.writerow([log.timestamp, log.username, log.action, log.details])
    mem = io.BytesIO()
    mem.write(proxy.getvalue().encode('utf-8'))
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name="Audit_DorkNet.csv", mimetype='text/csv')

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True)
