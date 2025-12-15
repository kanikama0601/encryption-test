import { readdirSync, statSync } from 'fs';
import { join } from 'path';
import EncryptionClient from './EncryptionClient';

const SERVER_URL = 'http://localhost:5000';
const UPLOAD_FOLDER = 'upload_files';
const DOWNLOAD_FOLDER = 'downloaded_files';

const client = new EncryptionClient(SERVER_URL, UPLOAD_FOLDER, DOWNLOAD_FOLDER);

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
        const files = readdirSync(UPLOAD_FOLDER)
          .filter(f => statSync(join(UPLOAD_FOLDER, f)).isFile());
        
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
          const filePath = join(UPLOAD_FOLDER, files[fileIdx]);
          await client.uploadFile(filePath);
        } else {
          console.log('❌ 無効な番号です');
        }
        
      } else if (choice === '2') {
        // ダウンロード
        const files = await client.listFiles();
        
        if (files.length === 0) {
          continue;
        }
        
        const idx = await question('\nダウンロードするファイル番号: ');
        const fileIdx = parseInt(idx) - 1;
        
        if (fileIdx >= 0 && fileIdx < files.length) {
          const file = files[fileIdx];
          await client.downloadFile(file.file_id, file.filename);
        } else {
          console.log('❌ 無効な番号です');
        }
        
      } else if (choice === '3') {
        // ファイル一覧
        await client.listFiles();
        
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