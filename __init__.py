from cryptography.fernet import Fernet
from flask import Flask, render_template
import os

app = Flask(__name__)

# 1) Charger la clé depuis l'environnement (NE PAS générer à chaque run)
FERNET_KEY = os.environ.get("FERNET_KEY")
if not FERNET_KEY:
    raise RuntimeError("La variable d'environnement FERNET_KEY n'est pas définie. "
                       "Définis-la avant de lancer l'app.")
f = Fernet(FERNET_KEY.encode())

@app.route('/')
def hello_world():
    return render_template('hello.html')

@app.route('/encrypt/<string:valeur>')
def encryptage(valeur):
    token = f.encrypt(valeur.encode())
    return f"Valeur encryptée : {token.decode()}"

@app.route('/decrypt/<string:valeur>')
def decryptage(valeur):
    try:
        texte = f.decrypt(valeur.encode()).decode()
        return f"Texte déchiffré : {texte}"
    except Exception as e:
        return f"Erreur lors du décryptage : {e}"

if __name__ == "__main__":
    app.run(debug=True)
