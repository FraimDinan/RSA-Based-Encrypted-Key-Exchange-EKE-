from flask import Flask, request, jsonify
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

app = Flask(__name__)

# Database pengguna (dictionary: {username: password_hash})
user_db = {}

# Folder untuk menyimpan kunci publik pengguna
USER_KEYS_FOLDER = 'user_keys'
if not os.path.exists(USER_KEYS_FOLDER):
    os.makedirs(USER_KEYS_FOLDER)

# Set untuk menyimpan nonce yang telah digunakan (untuk mencegah replay)
used_nonces = set()

# Generate pasangan kunci RSA server (privat dan publik)
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
server_public_key = server_private_key.public_key()

# Serialisasi kunci publik server ke format PEM (string)
server_public_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

@app.route('/daftar', methods=['POST'])
def daftar():
    data = request.get_json()
    username = data.get('name')
    password = data.get('password')
    user_public_key_pem = data.get('user_public_key')

    if not username or not password or not user_public_key_pem:
        return jsonify({'error': 'Invalid request, missing fields.'}), 400

    if username in user_db:
        return jsonify({'error': 'User already registered.'}), 400

    # Hash password menggunakan SHA256
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode())
    password_hash = digest.finalize().hex()

    # Simpan hash password di database
    user_db[username] = password_hash

    # Simpan kunci publik pengguna ke dalam file di folder user_keys
    user_key_file = os.path.join(USER_KEYS_FOLDER, f"{username}.pem")
    with open(user_key_file, 'w') as f:
        f.write(user_public_key_pem)

    return jsonify({
        'message': 'berhasil daftar',
        'server_public_key': server_public_pem
    }), 200

@app.route('/otentikasi', methods=['POST'])
def otentikasi():
    data = request.get_json()
    username = data.get('name')
    encrypted_data_b64 = data.get('encrypted_data')  # berisi "password:client_nonce"

    if not username or not encrypted_data_b64:
        return jsonify({'error': 'Invalid request, missing fields.'}), 400

    if username not in user_db:
        return jsonify({'error': 'User not registered.'}), 400

    # Decode encrypted data dari base64
    try:
        encrypted_data = base64.b64decode(encrypted_data_b64)
    except Exception as e:
        return jsonify({'error': f'Base64 decode error: {e}'}), 400

    # Dekripsi dengan kunci privat server
    try:
        decrypted_data = server_private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
    except Exception as e:
        return jsonify({'error': f'Decryption error: {e}'}), 400

    # Format yang diharapkan: "password:client_nonce"
    parts = decrypted_data.split(':')
    if len(parts) != 2:
        return jsonify({'error': 'Invalid message format.'}), 400

    password, client_nonce = parts

    # Cek apakah nonce sudah pernah digunakan
    if client_nonce in used_nonces:
        return jsonify({'error': 'Replay attack detected: nonce sudah digunakan.'}), 400
    used_nonces.add(client_nonce)

    # Verifikasi password
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode())
    password_hash = digest.finalize().hex()

    if password_hash != user_db[username]:
        return jsonify({'error': 'Password verification failed.'}), 400

    return jsonify({'message': 'otentikasi berhasil'}), 200

@app.route('/kunci_sesi', methods=['POST'])
def kunci_sesi():
    data = request.get_json()
    username = data.get('name')

    if not username:
        return jsonify({'error': 'Invalid request, missing username.'}), 400

    # Muat kunci publik pengguna dari file
    user_key_file = os.path.join(USER_KEYS_FOLDER, f"{username}.pem")
    if not os.path.exists(user_key_file):
        return jsonify({'error': 'User public key not found.'}), 400

    with open(user_key_file, 'r') as f:
        user_public_key_pem = f.read()

    try:
        user_public_key = serialization.load_pem_public_key(user_public_key_pem.encode())
    except Exception as e:
        return jsonify({'error': f'Error loading user public key: {e}'}), 400

    # Generate kunci sesi acak (misal 16 byte) dan server nonce baru (misal 8 byte hex)
    session_key = os.urandom(16)
    server_nonce = os.urandom(8).hex()

    # Format respons: "session_key_hex:server_nonce"
    message = session_key.hex() + ':' + server_nonce

    # Enkripsi respons dengan kunci publik pengguna
    try:
        encrypted_message = user_public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        return jsonify({'error': f'Error encrypting session key: {e}'}), 400

    encrypted_message_b64 = base64.b64encode(encrypted_message).decode()

    # Sertakan juga server_nonce secara terpisah untuk verifikasi klien
    return jsonify({
        'encrypted_session_key': encrypted_message_b64,
        'server_nonce': server_nonce
    }), 200

if __name__ == '__main__':
    app.run(debug=True)

