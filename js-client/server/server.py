from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os
import json
import base64
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class CryptoService:
    """暗号化・復号化サービス"""
    
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self._server_keypair = self._generate_rsa_keypair()
    
    def _generate_rsa_keypair(self) -> Dict:
        """RSA鍵ペアを生成"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        return {
            'private': private_key,
            'public': private_key.public_key()
        }
    
    def get_public_key_pem(self) -> bytes:
        """サーバーの公開鍵をPEM形式で取得"""
        return self._server_keypair['public'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def aes_encrypt(self, data: bytes, key: bytes) -> Dict[str, bytes]:
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
    
    def aes_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
        """AES-256-GCMでデータを復号化"""
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    
    def rsa_decrypt(self, encrypted_data: bytes) -> bytes:
        """サーバーの秘密鍵でRSA復号化"""
        return self._server_keypair['private'].decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def rsa_encrypt(self, data: bytes, public_key_pem: bytes) -> bytes:
        """指定された公開鍵でRSA暗号化"""
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


class FileStorage:
    """ファイルストレージ管理"""
    
    def __init__(self, storage_path: str = 'server_storage'):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
    
    def generate_file_id(self) -> str:
        """一意のファイルIDを生成"""
        return base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
    
    def save_file(self, file_id: str, data: bytes, metadata: Dict) -> None:
        """ファイルとメタデータを保存"""
        # ファイル保存
        file_path = self.storage_path / file_id
        with open(file_path, 'wb') as f:
            f.write(data)
        
        # メタデータ保存
        metadata_path = self.storage_path / f'{file_id}.meta'
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f)
    
    def load_file(self, file_id: str) -> Tuple[bytes, Dict]:
        """ファイルとメタデータを読み込み"""
        # メタデータ読み込み
        metadata_path = self.storage_path / f'{file_id}.meta'
        if not metadata_path.exists():
            raise FileNotFoundError(f'ファイルID {file_id} が見つかりません')
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        # ファイル読み込み
        file_path = self.storage_path / file_id
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        return file_data, metadata
    
    def list_all_files(self) -> List[Dict]:
        """すべてのファイルのメタデータを取得"""
        files = []
        for file in self.storage_path.iterdir():
            if file.suffix == '.meta':
                with open(file, 'r') as f:
                    metadata = json.load(f)
                    files.append(metadata)
        return files
    
    def file_exists(self, file_id: str) -> bool:
        """ファイルが存在するか確認"""
        metadata_path = self.storage_path / f'{file_id}.meta'
        return metadata_path.exists()


class EncryptedFileProcess:
    """暗号化ファイルサービス（ビジネスロジック層）"""
    
    def __init__(self, crypto_service: CryptoService, file_storage: FileStorage):
        self.crypto = crypto_service
        self.storage = file_storage
    
    def handle_upload(self, request_data: Dict) -> Dict:
        """
        アップロード処理
        1. RSAで暗号化されたAES鍵を復号化
        2. AES鍵でファイルを復号化
        3. ファイルを保存
        """
        try:
            # 暗号化された共通鍵を復号化
            encrypted_aes_key = base64.b64decode(request_data['encrypted_aes_key'])
            aes_key = self.crypto.rsa_decrypt(encrypted_aes_key)
            
            # 暗号化されたファイルを復号化
            encrypted_file = base64.b64decode(request_data['encrypted_file'])
            iv = base64.b64decode(request_data['iv'])
            tag = base64.b64decode(request_data['tag'])
            
            file_data = self.crypto.aes_decrypt(encrypted_file, aes_key, iv, tag)
            
            # ファイルを保存
            file_id = self.storage.generate_file_id()
            metadata = {
                'file_id': file_id,
                'filename': request_data['filename'],
                'size': len(file_data)
            }
            
            self.storage.save_file(file_id, file_data, metadata)
            
            print(f"✅ アップロード完了: {request_data['filename']} ({len(file_data)} bytes)")
            
            return {
                'success': True,
                'file_id': file_id,
                'filename': request_data['filename']
            }
        
        except Exception as e:
            print(f"❌ アップロードエラー: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def handle_download(self, file_id: str, client_public_key_b64: str) -> Optional[Dict]:
        """
        ダウンロード処理
        1. ファイルを読み込み
        2. 新しいAES鍵でファイルを暗号化
        3. クライアントの公開鍵でAES鍵を暗号化
        """
        try:
            # ファイルとメタデータを読み込み
            file_data, metadata = self.storage.load_file(file_id)
            
            # クライアントの公開鍵を取得
            client_public_key_pem = base64.b64decode(client_public_key_b64)
            
            # 新しいAES共通鍵を生成してファイルを暗号化
            aes_key = os.urandom(32)
            encrypted = self.crypto.aes_encrypt(file_data, aes_key)
            
            # AES共通鍵をクライアントの公開鍵で暗号化
            encrypted_aes_key = self.crypto.rsa_encrypt(aes_key, client_public_key_pem)
            
            print(f"✅ ダウンロード準備完了: {metadata['filename']}")
            
            return {
                'success': True,
                'filename': metadata['filename'],
                'encrypted_file': base64.b64encode(encrypted['ciphertext']).decode('utf-8'),
                'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
                'iv': base64.b64encode(encrypted['iv']).decode('utf-8'),
                'tag': base64.b64encode(encrypted['tag']).decode('utf-8')
            }
        
        except FileNotFoundError:
            return None
        except Exception as e:
            print(f"❌ ダウンロードエラー: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_file_list(self) -> List[Dict]:
        """ファイル一覧を取得"""
        return self.storage.list_all_files()


class EncryptedFileServer:
    """Flaskアプリケーションのラッパー"""
    
    def __init__(self, storage_path: str = 'server_storage', port: int = 5000):
        self.app = Flask(__name__)
        CORS(self.app)
        
        self.port = port
        self.crypto_service = CryptoService()
        self.file_storage = FileStorage(storage_path)
        self.file_service = EncryptedFileProcess(self.crypto_service, self.file_storage)
        
        self._register_routes()
    
    def _register_routes(self):
        """ルートを登録"""
        
        @self.app.route('/get_public_key', methods=['GET'])
        def get_public_key():
            """サーバーの公開鍵を返す"""
            pem = self.crypto_service.get_public_key_pem()
            return jsonify({
                'public_key': base64.b64encode(pem).decode('utf-8')
            })
        
        @self.app.route('/upload', methods=['POST'])
        def upload_file():
            """ファイルアップロード"""
            result = self.file_service.handle_upload(request.json)
            return jsonify(result)
        
        @self.app.route('/download/<file_id>', methods=['POST'])
        def download_file(file_id):
            """ファイルダウンロード"""
            result = self.file_service.handle_download(
                file_id, 
                request.json['public_key']
            )
            
            if result is None:
                return jsonify({'error': 'ファイルが見つかりません'}), 404
            
            return jsonify(result)
        
        @self.app.route('/files', methods=['GET'])
        def list_files():
            """ファイル一覧"""
            files = self.file_service.get_file_list()
            return jsonify({'files': files})
    
    def run(self, debug: bool = True):
        """サーバーを起動"""
        print("🔐 ハイブリッド暗号化サーバー起動")
        print(f"📁 ストレージ: {self.file_storage.storage_path}")
        print("🔑 サーバーRSA鍵ペア生成完了")
        self.app.run(debug=debug, port=self.port)


if __name__ == '__main__':
    server = EncryptedFileServer()
    server.run()