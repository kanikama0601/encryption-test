class CryptoClient {
  constructor() {
    this.clientKeyPair = null;
    this.serverPublicKey = null;
  }

  // クライアントの鍵ペアを生成
  async generateKeyPair() {
    this.clientKeyPair = await window.crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['encrypt', 'decrypt']
    );

    // 公開鍵をエクスポート（サーバーに送信用）
    const exportedPublicKey = await window.crypto.subtle.exportKey(
      'spki',
      this.clientKeyPair.publicKey
    );
    
    return this.arrayBufferToPem(exportedPublicKey, 'PUBLIC KEY');
  }

  // サーバーの公開鍵を設定
  async setServerPublicKey(serverPublicKeyPem) {
    const binaryDer = this.pemToArrayBuffer(serverPublicKeyPem);
    this.serverPublicKey = await window.crypto.subtle.importKey(
      'spki',
      binaryDer,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      true,
      ['encrypt']
    );
  }

  // アップロード時：ファイルを暗号化
  async encryptForUpload(file) {
    try {
      // 1. ランダムな共通鍵を生成
      const symmetricKey = await window.crypto.subtle.generateKey(
        { name: 'AES-CBC', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );

      const iv = window.crypto.getRandomValues(new Uint8Array(16));

      // 2. ファイルを読み込み
      const fileBuffer = await file.arrayBuffer();

      // 3. ファイルを共通鍵で暗号化
      const encryptedFile = await window.crypto.subtle.encrypt(
        { name: 'AES-CBC', iv: iv },
        symmetricKey,
        fileBuffer
      );

      // 4. 共通鍵をエクスポート
      const rawSymmetricKey = await window.crypto.subtle.exportKey(
        'raw',
        symmetricKey
      );

      // 5. 共通鍵をサーバーの公開鍵で暗号化
      const encryptedSymmetricKey = await window.crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        this.serverPublicKey,
        rawSymmetricKey
      );

      return {
        encryptedFile: this.arrayBufferToHex(iv) + ':' + 
                      this.arrayBufferToHex(encryptedFile),
        encryptedSymmetricKey: this.arrayBufferToBase64(encryptedSymmetricKey)
      };
      
    } catch (error) {
      console.error('Upload encryption error:', error);
      throw error;
    }
  }

  // ダウンロード時：暗号化されたファイルを復号化
  async decryptForDownload(encryptedFile, encryptedSymmetricKey) {
    try {
      // 1. クライアントの秘密鍵で共通鍵を復号化
      const symmetricKeyBuffer = await window.crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        this.clientKeyPair.privateKey,
        this.base64ToArrayBuffer(encryptedSymmetricKey)
      );

      // 2. 共通鍵をインポート
      const symmetricKey = await window.crypto.subtle.importKey(
        'raw',
        symmetricKeyBuffer,
        { name: 'AES-CBC', length: 256 },
        false,
        ['decrypt']
      );

      // 3. 暗号化されたファイルをパース
      const parts = encryptedFile.split(':');
      const iv = this.hexToArrayBuffer(parts[0]);
      const encryptedData = this.hexToArrayBuffer(parts[1]);

      // 4. ファイルを復号化
      const decryptedFile = await window.crypto.subtle.decrypt(
        { name: 'AES-CBC', iv: new Uint8Array(iv) },
        symmetricKey,
        encryptedData
      );

      return new Blob([decryptedFile]);
      
    } catch (error) {
      console.error('Download decryption error:', error);
      throw error;
    }
  }

  // ユーティリティ関数
  arrayBufferToPem(buffer, label) {
    const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    const formatted = base64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN ${label}-----\n${formatted}\n-----END ${label}-----`;
  }

  pemToArrayBuffer(pem) {
    const base64 = pem
      .replace(/-----BEGIN [^-]+-----/, '')
      .replace(/-----END [^-]+-----/, '')
      .replace(/\s/g, '');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
  }

  base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  arrayBufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  hexToArrayBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes.buffer;
  }
}


// 初期化
async function initializeCrypto(userId) {
  const client = new CryptoClient();
  
  // 1. クライアントの鍵ペア生成
  const clientPublicKey = await client.generateKeyPair();
  
  // 2. サーバーと公開鍵を交換
  const response = await fetch('/api/init', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user_id: userId,
      client_public_key: clientPublicKey
    })
  });
  
  const data = await response.json();
  await client.setServerPublicKey(data.server_public_key);
  
  return client;
}

// ファイルアップロード
async function uploadFile(client, userId, file) {
  // 1. ファイルを暗号化
  const { encryptedFile, encryptedSymmetricKey } = 
    await client.encryptForUpload(file);
  
  // 2. サーバーに送信
  const response = await fetch('/api/upload', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user_id: userId,
      encrypted_file: encryptedFile,
      encrypted_symmetric_key: encryptedSymmetricKey,
      filename: file.name
    })
  });
  
  return await response.json();
}

// ファイルダウンロード
async function downloadFile(client, userId, filename) {
  // 1. サーバーから暗号化されたファイルを取得
  const response = await fetch('/api/download', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user_id: userId,
      filename: filename
    })
  });
  
  const data = await response.json();
  
  // 2. ファイルを復号化
  const decryptedBlob = await client.decryptForDownload(
    data.encrypted_file,
    data.encrypted_symmetric_key
  );
  
  // 3. ダウンロード
  const url = URL.createObjectURL(decryptedBlob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// 使用例
const userId = 'user123';
const client = await initializeCrypto(userId);

// アップロード
const fileInput = document.getElementById('fileInput');
const file = fileInput.files[0];
await uploadFile(client, userId, file);

// ダウンロード
await downloadFile(client, userId, 'example.pdf');