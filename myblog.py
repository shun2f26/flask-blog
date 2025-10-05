#!/usr/bin/env bash

# アプリケーションに必要なライブラリをインストール
pip install -r requirements.txt

# データベースの初期化スクリプト。
# 'flask db init' のようなコマンドは使用できないため、Pythonスクリプトを直接実行します。
# 'myblog.py' の Post モデルを使ってテーブルを作成します。

echo "--- Running database initialization (create_all) ---"

# 環境変数（特にDATABASE_URL）が設定された状態でPythonを実行
python -c "
import os
from myblog import app, db
print('Starting Flask context...')
with app.app_context():
    # 既存のテーブルがあれば削除してから再作成することで、スキーマの不一致を完全に解消します
    print('Dropping all tables...')
    try:
        db.drop_all()
    except Exception as e:
        print(f'Error dropping tables (may be expected if they dont exist): {e}')

    print('Creating all tables...')
    try:
        db.create_all()
        print('Database tables created successfully!')
    except Exception as e:
        print(f'CRITICAL ERROR: Failed to create database tables: {e}')
        # テーブル作成失敗はビルド失敗とみなし、エラーコードを返す
        exit(1)
"

echo "--- Database initialization finished ---"
