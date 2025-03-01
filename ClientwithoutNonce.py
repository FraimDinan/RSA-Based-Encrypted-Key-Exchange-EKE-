import requests
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# URL server (pastikan server.py berjalan, misal di localhost port 5000)
SERVER_URL = 'http://127.0.0.1:5000'

def generate_client_keys():
    # Generate pasangan kunci RSA klien
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    # Serialisasi kunci publik ke format PEM (string)
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
    # Muat kunci publik server dari PEM
    server_public_key = serialization.load_pem_public_key(server_public_pem.encode())
    # Enkripsi password dengan kunci publik server menggunakan OAEP
    encrypted_password = server_public_key.encrypt(
        password.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_password_b64 = base64.b64encode(encrypted_password).decode()
    data = {
        'name': username,
        'encrypted_password': encrypted_password_b64
    }
    response = requests.post(f"{SERVER_URL}/otentikasi", json=data)
    if response.status_code == 200:
        print("Authentication successful.")
    else:
        print("Authentication failed:", response.json())

def request_session_key(username, client_private_key):
    data = {
        'name': username
    }
    response = requests.post(f"{SERVER_URL}/kunci_sesi", json=data)
    if response.status_code == 200:
        json_data = response.json()
        encrypted_session_key_b64 = json_data['encrypted_session_key']
        encrypted_session_key = base64.b64decode(encrypted_session_key_b64)
        # Dekripsi kunci sesi dengan kunci privat klien
        session_key = client_private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Session key received:", session_key.hex())
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
    # Langkah 2: Otentikasi
    authenticate(username, password, server_public_pem)
    # Langkah 3: Permintaan kunci sesi
    request_session_key(username, client_private_key)

if __name__ == '__main__':
    main()
