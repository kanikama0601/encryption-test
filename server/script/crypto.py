from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64


class CryptoServer:
    def __init__(self):
        # サーバーの鍵ペアを生成
        self.server_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.server_public_key = self.server_private_key.public_key()
        self.client_public_key = None

    def get_public_key_pem(self):
        """サーバーの公開鍵をPEM形式で取得"""
        pem = self.server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')

    def set_client_public_key(self, client_public_key_pem):
        """クライアントの公開鍵を設定"""
        self.client_public_key = serialization.load_pem_public_key(
            client_public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

    def handle_upload(self, encrypted_file, encrypted_symmetric_key):
        """
        アップロード時：暗号化されたファイルと共通鍵を受信して復号化
        
        Args:
            encrypted_file (str): IV:暗号化データ の形式（hex）
            encrypted_symmetric_key (str): Base64エンコードされた暗号化共通鍵
        
        Returns:
            bytes: 復号化されたファイルデータ
        """
        try:
            # 1. サーバーの秘密鍵で共通鍵を復号化
            encrypted_key_bytes = base64.b64decode(encrypted_symmetric_key)
            symmetric_key = self.server_private_key.decrypt(
                encrypted_key_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 2. 暗号化されたファイルをパース
            parts = encrypted_file.split(':')
            iv = bytes.fromhex(parts[0])
            encrypted_data = bytes.fromhex(parts[1])

            # 3. 共通鍵でファイルを復号化
            cipher = Cipher(
                algorithms.AES(symmetric_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # 4. パディングを除去
            decrypted_data = self._unpad(decrypted_data)

            return decrypted_data

        except Exception as e:
            print(f'Upload decryption error: {e}')
            raise

    def handle_download(self, file_data):
        """
        ダウンロード時：ファイルを暗号化してクライアントに送信
        
        Args:
            file_data (bytes): 平文のファイルデータ
        
        Returns:
            dict: {
                'encrypted_file': str (IV:暗号化データ の形式),
                'encrypted_symmetric_key': str (Base64)
            }
        """
        try:
            if self.client_public_key is None:
                raise ValueError('Client public key not set')

            # 1. ランダムな共通鍵を生成
            symmetric_key = os.urandom(32)  # AES-256
            iv = os.urandom(16)

            # 2. ファイルを共通鍵で暗号化（パディング追加）
            padded_data = self._pad(file_data)
            cipher = Cipher(
                algorithms.AES(symmetric_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # 3. 共通鍵をクライアントの公開鍵で暗号化
            encrypted_symmetric_key = self.client_public_key.encrypt(
                symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            return {
                'encrypted_file': iv.hex() + ':' + encrypted_data.hex(),
                'encrypted_symmetric_key': base64.b64encode(encrypted_symmetric_key).decode('utf-8')
            }

        except Exception as e:
            print(f'Download encryption error: {e}')
            raise

    @staticmethod
    def _pad(data):
        """PKCS7パディングを追加"""
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    @staticmethod
    def _unpad(data):
        """PKCS7パディングを除去"""
        padding_length = data[-1]
        return data[:-padding_length]


# 使用例
if __name__ == '__main__':
    # サーバーインスタンスを作成
    server = CryptoServer()
    
    # サーバーの公開鍵を取得（クライアントに送信）
    server_public_key = server.get_public_key_pem()
    print("Server Public Key:")
    print(server_public_key)