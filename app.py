import os
import secrets
import json
import io
from flask import Flask, request, send_file, Response, jsonify, render_template_string
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from PyPDF2 import PdfReader, PdfWriter
from functools import wraps

JOURNALIST_USERNAME = "journalist"
JOURNALIST_PASSWORD = "secret123"
PRIVATE_KEY_INFO = "Nutze den privaten RSA-Schlüssel, der zum öffentlichen Schlüssel passt, welcher die Datei verschlüsselt hat."

UPLOAD_FOLDER = 'uploads'
KEY_DB = 'public_keys.json'
TOKEN_DB = 'tokens.json'
ALLOWED_EXTENSIONS = {'pdf'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -- Hilfsfunktionen zum Laden/Speichern von Keys und Tokens --

def load_public_keys():
    if os.path.exists(KEY_DB):
        with open(KEY_DB, 'r') as f:
            return json.load(f)
    return {}

def save_public_keys(keys):
    with open(KEY_DB, 'w') as f:
        json.dump(keys, f, indent=2)

def load_tokens():
    if os.path.exists(TOKEN_DB):
        with open(TOKEN_DB, 'r') as f:
            return json.load(f)
    return {}

def save_tokens(tokens):
    with open(TOKEN_DB, 'w') as f:
        json.dump(tokens, f, indent=2)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# PDF-Metadaten entfernen
def strip_pdf_metadata(data):
    reader = PdfReader(io.BytesIO(data))
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()

# Verschlüsseln mit AES + RSA
def encrypt_file(file_data, pub_key_pem):
    aes_key = get_random_bytes(32)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)

    public_key = RSA.import_key(pub_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    return enc_aes_key, cipher_aes.nonce, tag, ciphertext

def check_auth(username, password):
    return username == JOURNALIST_USERNAME and password == JOURNALIST_PASSWORD

def authenticate():
    return Response(
        'Zugang verweigert. Bitte korrekt anmelden.', 401,
        {'WWW-Authenticate': 'Basic realm="Login erforderlich"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# -- HTML Template für GUI --

TEMPLATE = """
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8" />
    <title>WhistleDrop Upload Plattform</title>
</head>
<body>
    <h1>WhistleDrop Upload Plattform</h1>

    <form method="post" action="{{ url_for('generate_token') }}">
        <button type="submit">Einmaligen Upload-Token generieren</button>
    </form>

    {% if token %}
    <p><strong>Neues Token:</strong> <code>{{ token }}</code></p>
    {% endif %}

    <hr/>

    <h2>PDF Datei hochladen</h2>
    <form method="post" action="{{ url_for('upload_gui') }}" enctype="multipart/form-data">
        <label>Upload-Token: <input type="text" name="token" required /></label><br/><br/>
        <label>PDF Datei: <input type="file" name="file" accept="application/pdf" required /></label><br/><br/>
        <button type="submit">Upload starten</button>
    </form>

    {% if message %}
    <p style="color:green;">{{ message }}</p>
    {% endif %}
    {% if error %}
    <p style="color:red;">{{ error }}</p>
    {% endif %}
</body>
</html>
"""

# -- Flask Routes --

@app.route('/', methods=['GET'])
def index():
    return render_template_string(TEMPLATE)

@app.route('/generate-token', methods=['POST'])
def generate_token():
    token = secrets.token_urlsafe(16)
    tokens = load_tokens()
    tokens[token] = True
    save_tokens(tokens)
    return render_template_string(TEMPLATE, token=token)

@app.route('/upload', methods=['POST'])
def upload_gui():
    token = request.form.get('token', '').strip()
    file = request.files.get('file')

    if not token:
        return render_template_string(TEMPLATE, error="Kein Token angegeben.")
    if not file:
        return render_template_string(TEMPLATE, error="Keine Datei ausgewählt.")
    if not allowed_file(file.filename):
        return render_template_string(TEMPLATE, error="Nur PDF-Dateien sind erlaubt.")

    tokens = load_tokens()
    if token not in tokens or not tokens[token]:
        return render_template_string(TEMPLATE, error="Ungültiges oder bereits verwendetes Token.")

    public_keys = load_public_keys()
    if not public_keys:
        return render_template_string(TEMPLATE, error="Keine gültigen öffentlichen Schlüssel vorhanden.")

    raw_data = file.read()
    stripped_data = strip_pdf_metadata(raw_data)

    key_id, pub_key = next(iter(public_keys.items()))
    enc_key, nonce, tag, ciphertext = encrypt_file(stripped_data, pub_key)

    transaction_id = secrets.token_hex(8)
    filepath = os.path.join(UPLOAD_FOLDER, f'{transaction_id}.bin')
    with open(filepath, 'wb') as f_out:
        f_out.write(enc_key + nonce + tag + ciphertext)
    keypath = os.path.join(UPLOAD_FOLDER, f'{transaction_id}.key')
    with open(keypath, 'wb') as f_key:
        f_key.write(enc_key)


    # Schlüssel und Token verbrauchen
    del public_keys[key_id]
    save_public_keys(public_keys)
    del tokens[token]
    save_tokens(tokens)

    return render_template_string(TEMPLATE, message=f"")

# --- Original API Endpoints (ohne GUI) ---

@app.route('/upload/<token>', methods=['POST'])
def upload(token):
    tokens = load_tokens()
    if token not in tokens:
        return '', 200

    public_keys = load_public_keys()
    if not public_keys:
        return '', 200

    if 'file' not in request.files:
        return '', 200

    file = request.files['file']
    if not allowed_file(file.filename):
        return '', 200

    raw_data = file.read()
    stripped_data = strip_pdf_metadata(raw_data)

    key_id, pub_key = next(iter(public_keys.items()))
    enc_key, nonce, tag, ciphertext = encrypt_file(stripped_data, pub_key)

    transaction_id = secrets.token_hex(8)
    with open(os.path.join(UPLOAD_FOLDER, f'{transaction_id}.bin'), 'wb') as f:
        f.write(enc_key + nonce + tag + ciphertext)
    keypath = os.path.join(UPLOAD_FOLDER, f'{transaction_id}.key')
    with open(keypath, 'wb') as f_key:
        f_key.write(enc_key)


    del public_keys[key_id]
    save_public_keys(public_keys)
    del tokens[token]
    save_tokens(tokens)

    return '', 200

@app.route('/request-token', methods=['GET'])
def request_token():
    token = secrets.token_urlsafe(16)
    tokens = load_tokens()
    tokens[token] = True
    save_tokens(tokens)
    return token, 200

# Routes for journalist
@app.route('/files', methods=['GET'])
@requires_auth
def list_files():
    # Suche alle .bin Dateien im Upload-Ordner
    files = [f for f in os.listdir(UPLOAD_FOLDER) if f.endswith('.bin')]
    html = """
    <h1>Verfügbare Dateien zum Download</h1>
    <ul>
    """
    for f in files:
        base = f[:-4]  # z.B. "abc123.bin" -> "abc123"
        file_url = f"/download/{f}"
        key_url = f"/download_key/{base}.key"
        html += f"""
        <li>
            Datei: {f} &nbsp; 
            <a href="{file_url}">Datei herunterladen</a> | 
            <a href="{key_url}">AES-Schlüssel herunterladen</a>
        </li>
        """
    html += "</ul>"
    return html


@app.route('/download/<filename>', methods=['GET'])
@requires_auth
def download_file(filename):
    filename = secure_filename(filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(filepath):
        return "Datei nicht gefunden.", 404
    # Hinweis mitgeben, welcher private Schlüssel nötig ist (Text in Header)
    response = send_file(filepath, as_attachment=True)
    response.headers['X-Private-Key-Hinweis'] = PRIVATE_KEY_INFO
    return response

@app.route('/download_key/<filename>', methods=['GET'])
@requires_auth
def download_key(filename):
    filename = secure_filename(filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(filepath):
        return "Schlüssel-Datei nicht gefunden.", 404
    # Hinweis im Header
    response = send_file(filepath, as_attachment=True)
    response.headers['X-Private-Key-Hinweis'] = PRIVATE_KEY_INFO
    return response

if __name__ == '__main__':
    app.run(port=5000)
