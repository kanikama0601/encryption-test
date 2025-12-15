import { randomBytes, createCipheriv, createDecipheriv, publicEncrypt, constants, privateDecrypt, generateKeyPairSync } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { basename, join } from 'path';
import { get, post } from 'axios';

class EncryptionClient {
  constructor(serverUrl, uploadFolder, downloadFolder) {
    this.serverUrl = serverUrl;
    this.uploadFolder = uploadFolder;
    this.downloadFolder = downloadFolder;

    // フォルダ作成
    if (!existsSync(this.uploadFolder)) mkdirSync(this.uploadFolder);
    if (!existsSync(this.downloadFolder)) mkdirSync(this.downloadFolder);
  }

  // ========== AES暗号化/復号化 ==========

  aesEncrypt(data, key) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);

    const ciphertext = Buffer.concat([
      cipher.update(data),
      cipher.final()
    ]);

    const tag = cipher.getAuthTag();

    return {
      ciphertext: ciphertext,
      iv: iv,
      tag: tag
    };
  }

  aesDecrypt(ciphertext, key, iv, tag) {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    return Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]);
  }

  // ========== RSA暗号化/復号化 ==========

  rsaEncrypt(data, publicKeyPem) {
    return publicEncrypt(
      {
        key: publicKeyPem,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      data
    );
  }

  rsaDecrypt(encryptedData, privateKey) {
    return privateDecrypt(
      {
        key: privateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      encryptedData
    );
  }

  // ========== API呼び出し ==========

  async getServerPublicKey() {
    console.log('📡 サーバー公開鍵を取得中...');
    const response = await get(`${this.serverUrl}/get_public_key`);
    const publicKeyPem = Buffer.from(response.data.public_key, 'base64');
    console.log('✅ サーバー公開鍵取得完了');
    return publicKeyPem;
  }

  async uploadFile(filePath) {
    console.log(`\n📤 アップロード開始: ${filePath}`);

    // 1. ファイル読み込み
    const fileData = readFileSync(filePath);
    const filename = basename(filePath);
    console.log(`  ファイルサイズ: ${fileData.length} bytes`);

    // 2. AES-256鍵生成してファイルを暗号化
    console.log('  🔐 AES-256鍵生成...');
    const aesKey = randomBytes(32);

    console.log('  🔒 ファイルをAESで暗号化...');
    const encrypted = this.aesEncrypt(fileData, aesKey);

    // 3. サーバーの公開鍵を取得
    const serverPublicKey = await this.getServerPublicKey();

    // 4. AES鍵をRSAで暗号化
    console.log('  🔑 RSAで共通鍵を暗号化...');
    const encryptedAesKey = this.rsaEncrypt(aesKey, serverPublicKey);

    // 5. サーバーへ送信
    console.log('  📤 サーバーへ送信...');
    const payload = {
      filename: filename,
      encrypted_file: encrypted.ciphertext.toString('base64'),
      encrypted_aes_key: encryptedAesKey.toString('base64'),
      iv: encrypted.iv.toString('base64'),
      tag: encrypted.tag.toString('base64')
    };

    const response = await post(`${this.serverUrl}/upload`, payload);

    if (response.data.success) {
      console.log(`✅ アップロード完了: ${filename}`);
      console.log(`  📝 ファイルID: ${response.data.file_id}`);
      return response.data.file_id;
    } else {
      console.log('❌ アップロード失敗');
      return null;
    }
  }

  async downloadFile(fileId, filename) {
    console.log(`\n📥 ダウンロード開始: ${filename}`);

    // 1. クライアント側でRSA鍵ペア生成
    console.log('  🔑 クライアントRSA鍵ペア生成...');
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    // 2. 公開鍵をサーバーへ送信してファイルを要求
    console.log('  📡 サーバーへ公開鍵を送信してファイル要求...');
    const payload = {
      public_key: Buffer.from(publicKey).toString('base64')
    };

    const response = await post(
      `${this.serverUrl}/download/${fileId}`,
      payload
    );

    if (!response.data.success) {
      console.log('❌ ダウンロード失敗');
      return false;
    }

    // 3. 暗号化されたデータを受信
    console.log('  📦 暗号化データ受信...');
    const encryptedFile = Buffer.from(response.data.encrypted_file, 'base64');
    const encryptedAesKey = Buffer.from(response.data.encrypted_aes_key, 'base64');
    const iv = Buffer.from(response.data.iv, 'base64');
    const tag = Buffer.from(response.data.tag, 'base64');

    // 4. RSA秘密鍵でAES鍵を復号化
    console.log('  🔓 RSA秘密鍵で共通鍵を復号化...');
    const aesKey = this.rsaDecrypt(encryptedAesKey, privateKey);

    // 5. AES鍵でファイルを復号化
    console.log('  🔓 AES共通鍵でファイルを復号化...');
    const fileData = this.aesDecrypt(encryptedFile, aesKey, iv, tag);

    // 6. ファイル保存
    const outputPath = join(this.downloadFolder, filename);
    writeFileSync(outputPath, fileData);
    console.log(`✅ ダウンロード完了: ${outputPath}`);

    return true;
  }

  async listFiles() {
    console.log('\n📁 ファイル一覧取得中...');
    const response = await get(`${this.serverUrl}/files`);
    const files = response.data.files;

    if (files.length === 0) {
      console.log('⚠️  サーバーにファイルがありません');
    } else {
      console.log(`\n📁 サーバー上のファイル (${files.length}件):`);
      files.forEach((f, i) => {
        console.log(`  ${i + 1}. ${f.filename} (${f.size} bytes)`);
        console.log(`     ID: ${f.file_id}`);
      });
    }

    return files;
  }
}

export default EncryptionClient;
