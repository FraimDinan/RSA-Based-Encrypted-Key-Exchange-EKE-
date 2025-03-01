import os
import requests
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# URL server (pastikan server.py berjalan, misal di localhost:5000)
SERVER_URL = 'http://127.0.0.1:5000'

def generate_client_keys():
    # Generate pasangan kunci RSA untuk klien
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private_key, public_pem

def register(username, password, client_public_pem):
    data = {
        'name': username,
        'password': password,
        'user_public_key': client_public_pem
    }
    response = requests.post(f"{SERVER_URL}/daftar", json=data)
    if response.status_code == 200:
        json_data = response.json()
        print("Registration successful. Server public key received:")
        print(json_data['server_public_key'])
        return json_data['server_public_key']
    else:
        print("Registration failed:", response.json())
        return None

def authenticate(username, password, server_public_pem):
    # Generate client nonce (acak)
    client_nonce = os.urandom(8).hex()
    # Format pesan: "password:client_nonce"
    message = f"{password}:{client_nonce}"
    # Muat kunci publik server dari PEM
    server_public_key = serialization.load_pem_public_key(server_public_pem.encode())
    encrypted_data = server_public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_data_b64 = base64.b64encode(encrypted_data).decode()
    data = {
        'name': username,
        'encrypted_data': encrypted_data_b64
    }
    response = requests.post(f"{SERVER_URL}/otentikasi", json=data)
    if response.status_code == 200:
        print("Authentication successful.")
    else:
        print("Authentication failed:", response.json())

def request_session_key(username, client_private_key):
    data = {'name': username}
    response = requests.post(f"{SERVER_URL}/kunci_sesi", json=data)
    if response.status_code == 200:
        json_data = response.json()
        encrypted_session_key_b64 = json_data['encrypted_session_key']
        server_nonce_plain = json_data['server_nonce']
        encrypted_session_key = base64.b64decode(encrypted_session_key_b64)
        # Dekripsi pesan menggunakan kunci privat klien
        decrypted_message = client_private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
        # Format yang diharapkan: "session_key_hex:server_nonce"
        parts = decrypted_message.split(':')
        if len(parts) != 2:
            print("Decrypted message format invalid.")
            return
        session_key_hex, server_nonce_decrypted = parts
        if server_nonce_decrypted != server_nonce_plain:
            print("Server nonce mismatch! Possible replay attack.")
            return
        print("Session key received:", session_key_hex)
        print("Server nonce verified:", server_nonce_decrypted)
    else:
        print("Failed to get session key:", response.json())

def main():
    username = "alice"
    password = "secretpassword"
    # Generate RSA key pair untuk klien
    client_private_key, client_public_pem = generate_client_keys()
    # Langkah 1: Daftar
    server_public_pem = register(username, password, client_public_pem)
    if not server_public_pem:
        return
    # Langkah 2: Otentikasi dengan nonce (Replay prevention)
    authenticate(username, password, server_public_pem)
    # Langkah 3: Permintaan kunci sesi dengan verifikasi nonce dari server
    request_session_key(username, client_private_key)

if __name__ == '__main__':
    main()
