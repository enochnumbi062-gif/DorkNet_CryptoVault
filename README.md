# 🌐 DorkNet_CryptoVault - Cryptographic Vault v2.0

**DorkNet_CryptoVault** est une plateforme de stockage cloud ultra-sécurisée conçue sous la direction du **Dr Enoch Numbi**. Elle repose sur une architecture *Zero-Knowledge* et un chiffrement symétrique de haute intensité pour garantir la souveraineté totale des données numériques.

## 🧬 Vision Scientifique
Dans un écosystème numérique vulnérable aux interceptions, DorkNet_CryptoVault propose une barrière mathématique infranchissable entre l'utilisateur et le stockage physique. Le principe fondamental est simple : **Ce que le serveur stocke, il ne peut pas le lire.**



## 🛡️ Spécifications Techniques

### 1. Protocole de Chiffrement
* **Algorithme :** AES-256 (Advanced Encryption Standard).
* **Mode opératoire :** EAX (Encrypt-then-Authenticate-then-Translate).
* **Sécurité :** Utilisation d'un `Nonce` unique et d'un `Tag` d'authentification pour chaque fichier afin d'empêcher les attaques par rejeu ou modification de ciphertext.

### 2. Architecture de Sécurité
* **Double Authentification (2FA) :** Accès protégé par un code PIN secret haché via PBKDF2 avec SHA-256.
* **Stockage Décentralisé :** Intégration hybride avec l'API Cloudinary pour une disponibilité globale.
* **Audit Trail :** Journalisation exhaustive de chaque interaction (upload, déchiffrement, suppression).

### 3. Automatisation de l'Intégrité
* **Rapports Bi-journaliers :** Envoi automatique par SMTP des logs d'audit tous les 2 jours pour une surveillance proactive.
* **Diagnostic d'Intégrité :** Module de test en temps réel de la validité de la clé AES maître.

## 🚀 Installation & Déploiement

### Prérequis
* Python 3.9+
* Compte Cloudinary (API)
* Serveur SMTP (ex: Gmail App Password)

### Configuration (Variables d'Environnement)
Créez un fichier `.env` à la racine :
```env
SECRET_KEY=votre_cle_flask
DATABASE_URL=votre_url_base_de_donnee
CLOUDINARY_CLOUD_NAME=votre_nom
CLOUDINARY_API_KEY=votre_cle
CLOUDINARY_API_SECRET=votre_secret
AES_KEY=votre_cle_32_octets_hex
MAIL_USER=votre_email@gmail.com
MAIL_PASS=votre_mot_de_passe_application

🛠️ Stack Technologique
​Backend : Flask (Python)
​Database : SQLAlchemy (PostgreSQL/SQLite)
​Cryptographie : PyCryptodome
​Frontend : HTML5/CSS3 (Cyber-Terminal Design)
​Scheduler : APScheduler (Tâches automatisées)
​© 2026 Dr Enoch Numbi | DorkNet_CryptoVault : Sécuriser l'avenir de l'échange de données.
