# Enctyption-Test
研究用暗号化テスト

ハイブリッド暗号方式を作成しました

## 各フォルダ内容
* ``python-client``  
クライアントをpythonで作成しています  
* ``js-client``  
クライアントをjavascriptで作成しています  

どちらもサーバーはflaskで作成しています。  

## サーバー起動
``server.py``が格納されているフォルダで、
```shell
uv run server.py
```
こちらで起動できます。

## クライアント起動
``client.py``を実行する場合、同フォルダ内で
```shell
uv run client.py
```

``client.js``を起動する場合、同フォルダ内で
```shell
node client.js
```