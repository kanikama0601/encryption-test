import requests
import os
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from pathlib import Path

SERVER_URL = 'http://localhost:5000'
UPLOAD_FOLDER = 'upload_files'      # アップロード対象ファイルを配置
DOWNLOAD_FOLDER = 'downloaded_files' # ダウンロードしたファイルを保存

Path(UPLOAD_FOLDER).mkdir(exist_ok=True)
Path(DOWNLOAD_FOLDER).mkdir(exist_ok=True)

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

def upload_file(filepath):
    """
    ファイルアップロード
    1. クライアントでAES256共通鍵を生成、ファイルを暗号化
    2. サーバーから公開鍵を取得
    3. 公開鍵で共通鍵を暗号化
    4. 暗号化された共通鍵とファイルをサーバーへ送信
    """
    print(f"\n📤 アップロード開始: {filepath}")
    
    # ファイル読み込み
    with open(filepath, 'rb') as f:
        file_data = f.read()
    
    filename = os.path.basename(filepath)
    
    # 1. AES256共通鍵を生成してファイルを暗号化
    print("  🔐 AES-256共通鍵生成...")
    aes_key = os.urandom(32)
    
    print("  🔒 ファイルをAESで暗号化...")
    encrypted = aes_encrypt(file_data, aes_key)
    
    # 2. サーバーの公開鍵を取得
    print("  📡 サーバーからRSA公開鍵を取得...")
    res = requests.get(f'{SERVER_URL}/get_public_key')
    server_public_key_pem = base64.b64decode(res.json()['public_key'])
    server_public_key = serialization.load_pem_public_key(
        server_public_key_pem,
        backend=default_backend()
    )
    
    # 3. 公開鍵で共通鍵を暗号化
    print("  🔑 RSAで共通鍵を暗号化...")
    encrypted_aes_key = server_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 4. サーバーへ送信
    print("  📤 サーバーへ送信...")
    payload = {
        'filename': filename,
        'encrypted_file': base64.b64encode(encrypted['ciphertext']).decode('utf-8'),
        'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
        'iv': base64.b64encode(encrypted['iv']).decode('utf-8'),
        'tag': base64.b64encode(encrypted['tag']).decode('utf-8')
    }
    
    res = requests.post(f'{SERVER_URL}/upload', json=payload)
    result = res.json()
    
    if result['success']:
        print(f"  ✅ アップロード完了: {filename}")
        print(f"  📝 ファイルID: {result['file_id']}")
        return result['file_id']
    else:
        print(f"  ❌ エラー: {result}")
        return None

def download_file(file_id, filename):
    """
    ファイルダウンロード
    1. クライアントでRSA鍵ペアを生成
    2. 公開鍵をサーバーへ送信
    3. 暗号化された共通鍵とファイルを受信
    4. 秘密鍵で共通鍵を復号化
    5. 共通鍵でファイルを復号化
    """
    print(f"\n📥 ダウンロード開始: {filename}")
    
    # 1. RSA鍵ペアを生成
    print("  🔑 クライアント側RSA鍵ペア生成...")
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    client_public_key = client_private_key.public_key()
    
    # 2. 公開鍵をサーバーへ送信してファイルを要求
    print("  📡 サーバーへ公開鍵を送信してファイル要求...")
    client_public_key_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    payload = {
        'public_key': base64.b64encode(client_public_key_pem).decode('utf-8')
    }
    
    res = requests.post(f'{SERVER_URL}/download/{file_id}', json=payload)
    result = res.json()
    
    if not result['success']:
        print(f"  ❌ エラー: {result}")
        return
    
    # 3. 暗号化されたデータを受信
    print("  📦 暗号化データ受信...")
    encrypted_file = base64.b64decode(result['encrypted_file'])
    encrypted_aes_key = base64.b64decode(result['encrypted_aes_key'])
    iv = base64.b64decode(result['iv'])
    tag = base64.b64decode(result['tag'])
    
    # 4. 秘密鍵で共通鍵を復号化
    print("  🔓 RSA秘密鍵で共通鍵を復号化...")
    aes_key = client_private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 5. 共通鍵でファイルを復号化
    print("  🔓 AES共通鍵でファイルを復号化...")
    file_data = aes_decrypt(encrypted_file, aes_key, iv, tag)
    
    # ファイル保存
    output_path = os.path.join(DOWNLOAD_FOLDER, filename)
    with open(output_path, 'wb') as f:
        f.write(file_data)
    
    print(f"  ✅ ダウンロード完了: {output_path}")

def list_files():
    """サーバー上のファイル一覧を取得"""
    res = requests.get(f'{SERVER_URL}/files')
    return res.json()['files']

def main():
    print("=" * 60)
    print("🔐 ハイブリッド暗号化クラウドストレージ クライアント")
    print("=" * 60)
    
    while True:
        print("\n" + "=" * 60)
        print("メニュー:")
        print("  1. ファイルをアップロード")
        print("  2. ファイルをダウンロード")
        print("  3. ファイル一覧表示")
        print("  4. 終了")
        print("=" * 60)
        
        choice = input("\n選択してください (1-4): ").strip()
        
        if choice == '1':
            # アップロード
            files = [f for f in os.listdir(UPLOAD_FOLDER) if os.path.isfile(os.path.join(UPLOAD_FOLDER, f))]
            
            if not files:
                print(f"\n⚠️  {UPLOAD_FOLDER}/ にファイルがありません")
                continue
            
            print(f"\n📁 {UPLOAD_FOLDER}/ 内のファイル:")
            for i, f in enumerate(files, 1):
                print(f"  {i}. {f}")
            
            try:
                idx = int(input("\nアップロードするファイル番号: ")) - 1
                if 0 <= idx < len(files):
                    filepath = os.path.join(UPLOAD_FOLDER, files[idx])
                    upload_file(filepath)
            except (ValueError, IndexError):
                print("❌ 無効な番号です")
        
        elif choice == '2':
            # ダウンロード
            files = list_files()
            
            if not files:
                print("\n⚠️  サーバーにファイルがありません")
                continue
            
            print("\n📁 サーバー上のファイル:")
            for i, f in enumerate(files, 1):
                print(f"  {i}. {f['filename']} ({f['size']} bytes)")
            
            try:
                idx = int(input("\nダウンロードするファイル番号: ")) - 1
                if 0 <= idx < len(files):
                    file = files[idx]
                    download_file(file['file_id'], file['filename'])
            except (ValueError, IndexError):
                print("❌ 無効な番号です")
        
        elif choice == '3':
            # ファイル一覧
            files = list_files()
            
            if not files:
                print("\n⚠️  サーバーにファイルがありません")
            else:
                print("\n📁 サーバー上のファイル:")
                for f in files:
                    print(f"  • {f['filename']} ({f['size']} bytes) [ID: {f['file_id']}]")
        
        elif choice == '4':
            print("\n👋 終了します")
            break
        
        else:
            print("❌ 無効な選択です")

if __name__ == '__main__':
    main()