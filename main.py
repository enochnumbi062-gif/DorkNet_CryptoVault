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

# --- CHARGEMENT DES VARIABLES D'ENVIRONNEMENT ---
load_dotenv()

app = Flask(__name__)

# --- CONFIGURATION GÉNÉRALE ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dorknet-cryptovault-secure-key')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

# Configuration Base de données (PostgreSQL ou SQLite)
db_url = os.getenv('DATABASE_URL', 'sqlite:///cryptovault.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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

# --- MODÈLES DE DONNÉES (OPTIMISÉS TEXT) ---
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

# --- SÉCURITÉ : HEADERS HTTP ---
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# --- FONCTIONS D'ALERTE ET AUDIT ---
def send_critical_alert(action, details):
    """Envoie une alerte de sécurité immédiate en haute priorité au Dr Enoch Numbi."""
    with app.app_context():
        try:
            msg = Message(
                subject=f"🚨 ALERTE SÉCURITÉ CRITIQUE : {action}",
                recipients=[os.getenv('MAIL_USER')],
                body=f"Attention Dr Enoch Numbi,\n\nUne violation de sécurité ou une corruption de données a été détectée sur DorkNet CryptoVault.\n\n"
                     f"Action : {action}\n"
                     f"Détails : {details}\n"
                     f"Horodatage : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                     f"Veuillez inspecter le Journal d'Audit immédiatement.",
                extra_headers={'X-Priority': '1 (Highest)', 'Importance': 'high'}
            )
            mail.send(msg)
            print("📧 Alerte de sécurité critique envoyée.")
        except Exception as e:
            print(f"❌ Échec de l'envoi de l'alerte email : {e}")

def send_audit_report():
    with app.app_context():
        try:
            logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
            proxy = io.StringIO()
            writer = csv.writer(proxy)
            writer.writerow(['Date', 'Utilisateur', 'Action', 'Details'])
            for log in logs:
                writer.writerow([log.timestamp, log.username, log.action, log.details])
            
            msg = Message(f"Rapport d'Audit DorkNet CryptoVault - {datetime.now().strftime('%d/%m/%Y')}",
                          recipients=[os.getenv('MAIL_USER')])
            msg.body = "Veuillez trouver ci-joint le rapport d'audit périodique de DorkNet CryptoVault."
            msg.attach(f"Audit_DorkNet_{datetime.now().strftime('%Y%m%d')}.csv", "text/csv", proxy.getvalue())
            mail.send(msg)
        except Exception as e:
            print(f"Erreur Scheduler : {e}")

if not scheduler.running:
    scheduler.add_job(id='audit_report_job', func=send_audit_report, trigger='interval', hours=48)
    scheduler.start()

# --- ROUTES DE NAVIGATION & MAINTENANCE ---

@app.route('/')
def index():
    logs, cloud_files = [], []
    if current_user.is_authenticated:
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
        try:
            resources = cloudinary.api.resources(resource_type="raw", type="upload", max_results=15)
            for res in resources.get('resources', []):
                cloud_files.append({
                    'public_id': res['public_id'],
                    'size': f"{res['bytes'] / 1024:.1f} KB"
                })
        except: pass
    return render_template('index.html', logs=logs, files=cloud_files)

@app.route('/setup_db')
def setup_db():
    try:
        db.drop_all() 
        db.create_all()
        return "✅ Base de données réinitialisée avec les nouveaux formats (Text) !"
    except Exception as e:
        return f"❌ Erreur : {str(e)}"

@app.route('/test_mail')
@login_required
def test_mail():
    send_audit_report()
    return "🚀 Tentative d'envoi du rapport d'audit lancée ! Vérifiez votre boîte mail."

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
            db.session.add(AuditLog(username=user.username, action="2FA_SUCCESS", details="Connexion validée"))
            db.session.commit()
            return redirect(url_for('index'))
        else:
            flash("Code PIN invalide.", "danger")
    return render_template('2fa.html')

# --- GESTION DES FICHIERS & SÉCURITÉ AES ---

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
            db.session.add(AuditLog(username=current_user.username, action="UPLOAD", details=f"Fichier : {file.filename}"))
            db.session.commit()
            flash(f'Succès : {file.filename} est sécurisé !', "success")
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
        # Vérification d'intégrité intégrée
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        
        db.session.add(AuditLog(username=current_user.username, action="DOWNLOAD_SUCCESS", details=f"Fichier : {public_id}"))
        db.session.commit()
        
        return send_file(io.BytesIO(decrypted_data), as_attachment=True, download_name=public_id.replace('.enc', ''))

    except ValueError:
        # VIOLATION D'INTÉGRITÉ OU CLÉ INCORRECTE
        error_msg = f"Échec d'intégrité sur {public_id}. Le fichier a été altéré ou la clé AES est incorrecte."
        db.session.add(AuditLog(username=current_user.username, action="SECURITY_BREACH", details=error_msg))
        db.session.commit()
        
        # Alerte immédiate email au Dr Enoch Numbi
        send_critical_alert("SECURITY_BREACH", error_msg)
        
        flash("🚫 Alerte Sécurité : L'intégrité du fichier est compromise. Administrateur notifié.", "danger")
        return redirect(url_for('index'))

    except Exception as e:
        db.session.add(AuditLog(username=current_user.username, action="DOWNLOAD_ERROR", details=str(e)))
        db.session.commit()
        flash(f"Erreur technique : {str(e)}", "danger")
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
    username = request.form.get('username')
    password = request.form.get('password')
    pin = request.form.get('pin')
    
    if User.query.filter_by(username=username).first():
        flash('Pseudo utilisé.', "danger")
    else:
        new_user = User(
            username=username, 
            password=generate_password_hash(password),
            pin_code=generate_password_hash(pin)
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Compte créé ! Connectez-vous.', "success")
        except Exception as e:
            db.session.rollback()
            return f"Erreur d'écriture : {str(e)}"
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))

# --- LANCEMENT ---
with app.app_context():
    try:
        db.create_all()
        print("✅ DorkNet CryptoVault prêt et sécurisé.")
    except Exception as e:
        print(f"❌ Erreur DB : {e}")

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
