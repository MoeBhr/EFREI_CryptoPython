from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode
from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def hello_world():
    return render_template('hello.html')  # ta page d'accueil

# --- Ton mode actuel (clé volatile par session) ---
key = Fernet.generate_key()
f = Fernet(key)

@app.route('/encrypt/<string:valeur>')
def encryptage(valeur):
    token = f.encrypt(valeur.encode())
    return f"Valeur encryptée : {token.decode()}"

# ==============================
#     MODE "CLÉ PERSONNELLE"
# ==============================

# 0) Générer une clé Fernet pour l'utilisateur (à garder)
@app.route('/key/new')
def new_key():
    return Fernet.generate_key().decode()  # à afficher et stocker côté utilisateur

# A) Utiliser une CLÉ FERNET fournie (format officiel)
#    /encrypt_personal/<valeur>?key=<CLE_FERNET>
#    /decrypt_personal/<token>?key=<CLE_FERNET>
def fernet_from_query_key():
    k = request.args.get("key", "").strip()
    if not k:
        return None, "Clé manquante. Ajoute ?key=<votre_cle_fernet>"
    try:
        return Fernet(k.encode()), None
    except Exception as e:
        return None, f"Clé invalide (format Fernet attendu) : {e}"

@app.route('/encrypt_personal/<string:valeur>')
def encrypt_personal(valeur):
    f_custom, err = fernet_from_query_key()
    if err:
        return err, 400
    token = f_custom.encrypt(valeur.encode()).decode()
    return f"Valeur encryptée (clé perso) : {token}"

@app.route('/decrypt_personal/<path:token>')
def decrypt_personal(token):
    f_custom, err = fernet_from_query_key()
    if err:
        return err, 400
    try:
        texte = f_custom.decrypt(token.encode()).decode()
        return f"Texte déchiffré (clé perso) : {texte}"
    except Exception as e:
        return f"Erreur de décryptage : {e}", 400

# B) Utiliser un MOT DE PASSE pour dériver une clé Fernet (PBKDF2)
#    /encrypt_pw/<valeur>?pwd=monMotDePasse[&salt=monSel]
#    /decrypt_pw/<token>?pwd=monMotDePasse[&salt=monSel]
def fernet_from_password_query():
    pwd = request.args.get("pwd", "")
    salt = request.args.get("salt", "default-salt").encode()  # ⚠️ en prod: mettre un sel aléatoire et stable par utilisateur
    if not pwd:
        return None, "Mot de passe manquant. Ajoute ?pwd=<votre_mot_de_passe>"
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000
        )
        key_bytes = kdf.derive(pwd.encode())
        key_fernet = urlsafe_b64encode(key_bytes)
        return Fernet(key_fernet), None
    except Exception as e:
        return None, f"Erreur dérivation clé : {e}"

@app.route('/encrypt_pw/<string:valeur>')
def encrypt_pw(valeur):
    f_custom, err = fernet_from_password_query()
    if err:
        return err, 400
    token = f_custom.encrypt(valeur.encode()).decode()
    return f"Valeur encryptée (pwd) : {token}"

@app.route('/decrypt_pw/<path:token>')
def decrypt_pw(token):
    f_custom, err = fernet_from_password_query()
    if err:
        return err, 400
    try:
        texte = f_custom.decrypt(token.encode()).decode()
        return f"Texte déchiffré (pwd) : {texte}"
    except Exception as e:
        return f"Erreur de décryptage : {e}", 400

if __name__ == "__main__":
    app.run(debug=True)
