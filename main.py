import os
import io
from dotenv import load_dotenv
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

load_dotenv()

app = Flask(__name__)
# IMPORTANT : En production, définissez SECRET_KEY et AES_KEY dans les variables d'environnement
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dorknet-xchange-default-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///cryptovault.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limite à 16 Mo

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_page'

# --- SECURITE : CLÉ AES FIXE ---
# On récupère la clé du .env ou on en crée une persistante
aes_key_hex = os.getenv('AES_KEY')
if not aes_key_hex:
    aes_key_hex = get_random_bytes(32).hex()
    print(f"⚠️ AUCUNE CLÉ AES TROUVÉE. UTILISEZ CELLE-CI DANS VOS VARS D'ENV : {aes_key_hex}")
ENCRYPTION_KEY = bytes.fromhex(aes_key_hex)

# --- MODÈLES ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---
@app.route('/')
@login_required
def index():
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('index.html', files=files)

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
        flash('Identifiants incorrects')
    return render_template('index.html') # Le template gère l'affichage login/index

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    if User.query.filter_by(username=username).first():
        flash('Ce pseudo existe déjà')
    else:
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Compte créé ! Connectez-vous.')
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
            flash(f'Fichier {file.filename} sécurisé !')
        except Exception as e:
            flash(f'Erreur de cryptage : {str(e)}')
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
        return send_file(io.BytesIO(data), as_attachment=True, download_name=filename.replace('.enc', ''))
    except Exception:
        flash('Erreur lors du décryptage.')
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
