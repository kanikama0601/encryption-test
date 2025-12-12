from flask import Flask, request, jsonify, send_file
from crypto import CryptoServer
import io
import os

app = Flask(__name__)

# グローバルなサーバーインスタンス（実際はセッションごとに管理）
crypto_servers = {}

@app.route('/api/init', methods=['POST'])
def init_crypto():
    """暗号化の初期化：公開鍵の交換"""
    try:
        data = request.json
        user_id = data.get('user_id')  # 実際は認証から取得
        client_public_key = data.get('client_public_key')
        
        # サーバーインスタンスを作成
        server = CryptoServer()
        crypto_servers[user_id] = server
        
        # クライアントの公開鍵を設定
        server.set_client_public_key(client_public_key)
        
        # サーバーの公開鍵を返す
        return jsonify({
            'server_public_key': server.get_public_key_pem()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """ファイルアップロード"""
    try:
        data = request.json
        user_id = data.get('user_id')
        encrypted_file = data.get('encrypted_file')
        encrypted_symmetric_key = data.get('encrypted_symmetric_key')
        filename = data.get('filename')
        
        # サーバーインスタンスを取得
        server = crypto_servers.get(user_id)
        if not server:
            return jsonify({'error': 'Crypto session not initialized'}), 400
        
        # ファイルを復号化
        decrypted_data = server.handle_upload(
            encrypted_file,
            encrypted_symmetric_key
        )
        
        # ファイルをストレージに保存
        storage_path = f'storage/{user_id}'
        os.makedirs(storage_path, exist_ok=True)
        file_path = os.path.join(storage_path, filename)
        
        with open(file_path, 'wb') as f:
            f.write(decrypted_data)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'size': len(decrypted_data)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/download', methods=['POST'])
def download_file():
    """ファイルダウンロード"""
    try:
        data = request.json
        user_id = data.get('user_id')
        filename = data.get('filename')
        
        # サーバーインスタンスを取得
        server = crypto_servers.get(user_id)
        if not server:
            return jsonify({'error': 'Crypto session not initialized'}), 400
        
        # ファイルをストレージから読み込み
        file_path = f'storage/{user_id}/{filename}'
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # ファイルを暗号化
        encrypted_response = server.handle_download(file_data)
        
        return jsonify({
            'encrypted_file': encrypted_response['encrypted_file'],
            'encrypted_symmetric_key': encrypted_response['encrypted_symmetric_key'],
            'filename': filename
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400


if __name__ == '__main__':
    os.makedirs('storage', exist_ok=True)
    app.run(debug=True, ssl_context='adhoc')  # HTTPS必須