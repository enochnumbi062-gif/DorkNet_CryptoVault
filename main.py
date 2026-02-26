import os
import io
from dotenv import load_dotenv
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Chargement des variables d'environnement
load_dotenv()

app = Flask(__name__)

# --- CONFIGURATION ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dorknet-xchange-default-secret')

# Configuration de la base de données avec correction pour PostgreSQL (Render)
db_url = os.getenv('DATABASE_URL', 'sqlite:///cryptovault.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limite d'upload : 16 Mo

# Initialisation des extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'

# --- SÉCURITÉ : CLÉ AES ---
aes_key_hex = os.getenv('AES_KEY')
if not aes_key_hex:
    aes_key_hex = get_random_bytes(32).hex()
    print(f"⚠️ ATTENTION : AES_KEY générée par défaut. Notez-la : {aes_key_hex}")

ENCRYPTION_KEY = bytes.fromhex(aes_key_hex)

# --- MODÈLES DE DONNÉES ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

@app.route('/')
def index():
    # --- SOLUTION RENDER FREE ---
    # Cette ligne crée les tables PostgreSQL automatiquement dès que vous visitez le site
    # pour éviter l'erreur "relation user does not exist" sans avoir accès au Shell.
    db.create_all() 
    
    files = []
    if current_user.is_authenticated:
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('index.html', files=files)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    
    if user and check_password_hash(user.password, password):
        login_user(user)
    else:
        flash('Identifiants incorrects.')
    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if User.query.filter_by(username=username).first():
        flash('Ce pseudonyme est déjà utilisé.')
    else:
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Compte créé avec succès ! Connectez-vous.')
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    if file and file.filename != '':
        try:
            cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(file.read())
            
            filename = file.filename + '.enc'
            path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(path, 'wb') as f:
                [f.write(x) for x in (nonce, tag, ciphertext)]
            flash(f'Le fichier {file.filename} a été sécurisé.')
        except Exception as e:
            flash(f'Erreur lors du cryptage : {str(e)}')
    return redirect(url_for('index'))

@app.route('/download/<filename>')
@login_required
def download(filename):
    try:
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(path, 'rb') as f:
            nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
        
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        
        return send_file(
            io.BytesIO(data), 
            as_attachment=True, 
            download_name=filename.replace('.enc', '')
        )
    except Exception:
        flash('Échec du déchiffrement (Clé invalide ou fichier corrompu).')
        return redirect(url_for('index'))

@app.route('/delete/<filename>')
@login_required
def delete_file(filename):
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(path):
        os.remove(path)
        flash('Fichier supprimé du coffre.')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- LANCEMENT ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
