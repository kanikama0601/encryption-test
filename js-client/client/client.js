const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

const SERVER_URL = 'http://localhost:5000';
const UPLOAD_FOLDER = 'upload_files';
const DOWNLOAD_FOLDER = 'downloaded_files';

// フォルダ作成
if (!fs.existsSync(UPLOAD_FOLDER)) fs.mkdirSync(UPLOAD_FOLDER);
if (!fs.existsSync(DOWNLOAD_FOLDER)) fs.mkdirSync(DOWNLOAD_FOLDER);

// ========== AES暗号化/復号化 ==========

function aesEncrypt(data, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
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

function aesDecrypt(ciphertext, key, iv, tag) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);
}

// ========== RSA暗号化/復号化 ==========

function rsaEncrypt(data, publicKeyPem) {
  return crypto.publicEncrypt(
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    data
  );
}

function rsaDecrypt(encryptedData, privateKey) {
  return crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    encryptedData
  );
}

// ========== API呼び出し ==========

async function getServerPublicKey() {
  console.log('📡 サーバー公開鍵を取得中...');
  const response = await axios.get(`${SERVER_URL}/get_public_key`);
  const publicKeyPem = Buffer.from(response.data.public_key, 'base64');
  console.log('✅ サーバー公開鍵取得完了');
  return publicKeyPem;
}

async function uploadFile(filePath) {
  console.log(`\n📤 アップロード開始: ${filePath}`);
  
  // 1. ファイル読み込み
  const fileData = fs.readFileSync(filePath);
  const filename = path.basename(filePath);
  console.log(`  ファイルサイズ: ${fileData.length} bytes`);
  
  // 2. AES-256鍵生成してファイルを暗号化
  console.log('  🔐 AES-256鍵生成...');
  const aesKey = crypto.randomBytes(32);
  
  console.log('  🔒 ファイルをAESで暗号化...');
  const encrypted = aesEncrypt(fileData, aesKey);
  
  // 3. サーバーの公開鍵を取得
  const serverPublicKey = await getServerPublicKey();
  
  // 4. AES鍵をRSAで暗号化
  console.log('  🔑 RSAで共通鍵を暗号化...');
  const encryptedAesKey = rsaEncrypt(aesKey, serverPublicKey);
  
  // 5. サーバーへ送信
  console.log('  📤 サーバーへ送信...');
  const payload = {
    filename: filename,
    encrypted_file: encrypted.ciphertext.toString('base64'),
    encrypted_aes_key: encryptedAesKey.toString('base64'),
    iv: encrypted.iv.toString('base64'),
    tag: encrypted.tag.toString('base64')
  };
  
  const response = await axios.post(`${SERVER_URL}/upload`, payload);
  
  if (response.data.success) {
    console.log(`✅ アップロード完了: ${filename}`);
    console.log(`  📝 ファイルID: ${response.data.file_id}`);
    return response.data.file_id;
  } else {
    console.log('❌ アップロード失敗');
    return null;
  }
}

async function downloadFile(fileId, filename) {
  console.log(`\n📥 ダウンロード開始: ${filename}`);
  
  // 1. クライアント側でRSA鍵ペア生成
  console.log('  🔑 クライアントRSA鍵ペア生成...');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
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
  
  const response = await axios.post(
    `${SERVER_URL}/download/${fileId}`,
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
  const aesKey = rsaDecrypt(encryptedAesKey, privateKey);
  
  // 5. AES鍵でファイルを復号化
  console.log('  🔓 AES共通鍵でファイルを復号化...');
  const fileData = aesDecrypt(encryptedFile, aesKey, iv, tag);
  
  // 6. ファイル保存
  const outputPath = path.join(DOWNLOAD_FOLDER, filename);
  fs.writeFileSync(outputPath, fileData);
  console.log(`✅ ダウンロード完了: ${outputPath}`);
  
  return true;
}

async function listFiles() {
  console.log('\n📁 ファイル一覧取得中...');
  const response = await axios.get(`${SERVER_URL}/files`);
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

// ========== メインメニュー ==========

async function showMenu() {
  const readline = require('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  
  const question = (query) => new Promise((resolve) => rl.question(query, resolve));
  
  console.log('\n' + '='.repeat(60));
  console.log('🔐 ハイブリッド暗号化クラウドストレージ クライアント (JS)');
  console.log('='.repeat(60));
  
  while (true) {
    console.log('\n' + '='.repeat(60));
    console.log('メニュー:');
    console.log('  1. ファイルをアップロード');
    console.log('  2. ファイルをダウンロード');
    console.log('  3. ファイル一覧表示');
    console.log('  4. 終了');
    console.log('='.repeat(60));
    
    const choice = await question('\n選択してください (1-4): ');
    
    try {
      if (choice === '1') {
        // アップロード
        const files = fs.readdirSync(UPLOAD_FOLDER)
          .filter(f => fs.statSync(path.join(UPLOAD_FOLDER, f)).isFile());
        
        if (files.length === 0) {
          console.log(`\n⚠️  ${UPLOAD_FOLDER}/ にファイルがありません`);
          continue;
        }
        
        console.log(`\n📁 ${UPLOAD_FOLDER}/ 内のファイル:`);
        files.forEach((f, i) => {
          console.log(`  ${i + 1}. ${f}`);
        });
        
        const idx = await question('\nアップロードするファイル番号: ');
        const fileIdx = parseInt(idx) - 1;
        
        if (fileIdx >= 0 && fileIdx < files.length) {
          const filePath = path.join(UPLOAD_FOLDER, files[fileIdx]);
          await uploadFile(filePath);
        } else {
          console.log('❌ 無効な番号です');
        }
        
      } else if (choice === '2') {
        // ダウンロード
        const files = await listFiles();
        
        if (files.length === 0) {
          continue;
        }
        
        const idx = await question('\nダウンロードするファイル番号: ');
        const fileIdx = parseInt(idx) - 1;
        
        if (fileIdx >= 0 && fileIdx < files.length) {
          const file = files[fileIdx];
          await downloadFile(file.file_id, file.filename);
        } else {
          console.log('❌ 無効な番号です');
        }
        
      } else if (choice === '3') {
        // ファイル一覧
        await listFiles();
        
      } else if (choice === '4') {
        console.log('\n👋 終了します');
        rl.close();
        break;
        
      } else {
        console.log('❌ 無効な選択です');
      }
      
    } catch (error) {
      console.error('❌ エラー:', error.message);
    }
  }
}

// ========== 実行 ==========

if (require.main === module) {
  showMenu().catch(console.error);
}

module.exports = {
  uploadFile,
  downloadFile,
  listFiles,
  aesEncrypt,
  aesDecrypt,
  rsaEncrypt,
  rsaDecrypt
};