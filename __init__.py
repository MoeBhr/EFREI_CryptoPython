from cryptography.fernet import Fernet
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def hello_world():
    return render_template('hello.html')

#  Génère la clé (temporaire à chaque lancement)
key = Fernet.generate_key()
f = Fernet(key)

@app.route('/encrypt/<string:valeur>')
def encryptage(valeur):
    valeur_bytes = valeur.encode()          # Conversion str -> bytes 
    token = f.encrypt(valeur_bytes)         # Encrypt la valeur
    return f"Valeur encryptée : {token.decode()}"  # Retourne le token en str

#  ROUTE DE DECRYPTAGE
@app.route('/decrypt/<string:valeur>')
def decryptage(valeur):
    try:
        valeur_bytes = valeur.encode()          # Conversion str -> bytes
        texte_dechiffre = f.decrypt(valeur_bytes).decode()  # Décryptage
        return f"Texte déchiffré : {texte_dechiffre}"
    except Exception as e:
        return f"Erreur lors du décryptage : {e}"

if __name__ == "__main__":
    app.run(debug=True)
