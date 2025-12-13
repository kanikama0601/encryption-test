from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os
import json
import base64
from pathlib import Path

app = Flask(__name__)
CORS(app)

# 設定
STORAGE_FOLDER = 'server_storage'
Path(STORAGE_FOLDER).mkdir(exist_ok=True)

# サーバー側のRSA鍵ペア（アップロード用）
SERVER_PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.public_key()

def aes_encrypt(data, key):
    """AES-256-GCMでデータを暗号化"""
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return {
        'ciphertext': ciphertext,
        'iv': iv,
        'tag': encryptor.tag
    }

def aes_decrypt(ciphertext, key, iv, tag):
    """AES-256-GCMでデータを復号化"""
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    """サーバーの公開鍵を返す（アップロード用）"""
    pem = SERVER_PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jsonify({
        'public_key': base64.b64encode(pem).decode('utf-8')
    })

@app.route('/upload', methods=['POST'])
def upload_file():
    """
    アップロード処理
    受信: 暗号化されたファイル + RSAで暗号化された共通鍵
    """
    data = request.json
    
    # 暗号化された共通鍵を復号化
    encrypted_aes_key = base64.b64decode(data['encrypted_aes_key'])
    aes_key = SERVER_PRIVATE_KEY.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 暗号化されたファイルを復号化
    encrypted_file = base64.b64decode(data['encrypted_file'])
    iv = base64.b64decode(data['iv'])
    tag = base64.b64decode(data['tag'])
    
    file_data = aes_decrypt(encrypted_file, aes_key, iv, tag)
    
    # ファイルIDを生成して保存
    file_id = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
    file_path = os.path.join(STORAGE_FOLDER, file_id)
    
    with open(file_path, 'wb') as f:
        f.write(file_data)
    
    # メタデータ保存
    metadata = {
        'file_id': file_id,
        'filename': data['filename'],
        'size': len(file_data)
    }
    
    metadata_path = os.path.join(STORAGE_FOLDER, f'{file_id}.meta')
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f)
    
    print(f"✅ アップロード完了: {data['filename']} ({len(file_data)} bytes)")
    
    return jsonify({
        'success': True,
        'file_id': file_id,
        'filename': data['filename']
    })

@app.route('/download/<file_id>', methods=['POST'])
def download_file(file_id):
    """
    ダウンロード処理
    受信: クライアントの公開鍵
    返却: RSAで暗号化された共通鍵 + AESで暗号化されたファイル
    """
    # メタデータ読み込み
    metadata_path = os.path.join(STORAGE_FOLDER, f'{file_id}.meta')
    if not os.path.exists(metadata_path):
        return jsonify({'error': 'ファイルが見つかりません'}), 404
    
    with open(metadata_path, 'r') as f:
        metadata = json.load(f)
    
    # ファイル読み込み
    file_path = os.path.join(STORAGE_FOLDER, file_id)
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    # クライアントの公開鍵を取得
    client_public_key_pem = base64.b64decode(request.json['public_key'])
    client_public_key = serialization.load_pem_public_key(
        client_public_key_pem,
        backend=default_backend()
    )
    
    # AES共通鍵を生成してファイルを暗号化
    aes_key = os.urandom(32)
    encrypted = aes_encrypt(file_data, aes_key)
    
    # AES共通鍵をRSAで暗号化
    encrypted_aes_key = client_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"✅ ダウンロード準備完了: {metadata['filename']}")
    
    return jsonify({
        'success': True,
        'filename': metadata['filename'],
        'encrypted_file': base64.b64encode(encrypted['ciphertext']).decode('utf-8'),
        'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
        'iv': base64.b64encode(encrypted['iv']).decode('utf-8'),
        'tag': base64.b64encode(encrypted['tag']).decode('utf-8')
    })

@app.route('/files', methods=['GET'])
def list_files():
    """ファイル一覧"""
    files = []
    for file in os.listdir(STORAGE_FOLDER):
        if file.endswith('.meta'):
            with open(os.path.join(STORAGE_FOLDER, file), 'r') as f:
                metadata = json.load(f)
                files.append(metadata)
    return jsonify({'files': files})

if __name__ == '__main__':
    print("🔐 ハイブリッド暗号化サーバー起動")
    print("📁 ストレージ: " + STORAGE_FOLDER)
    print("🔑 サーバーRSA鍵ペア生成完了")
    app.run(debug=True, port=5000)