#!/usr/bin/env bash

# アプリケーションに必要なライブラリをインストール
pip install -r requirements.txt

echo "--- Running database initialization (Forcing Schema Reset) ---"

python -c "
import os
import sys
from myblog import app, db # myblogからappとdbをインポート

# PostgreSQLのテーブル名を直接指定して削除を試みる
TABLES_TO_DROP = ['user', 'post']

print('Starting Flask context...', file=sys.stderr)

try:
    with app.app_context():
        # データベースURIを取得
        uri = app.config['SQLALCHEMY_DATABASE_URI']
        if not uri:
            print('CRITICAL ERROR: DATABASE_URL is missing.', file=sys.stderr)
            sys.exit(1)
            
        print(f'Attempting to connect to: {uri}', file=sys.stderr)
        
        # ----------------------------------------------------
        # 1. 強制的に全テーブルを削除（CASCADE使用）
        # ----------------------------------------------------
        engine = db.engine
        
        print('Forcing table drop via raw SQL...', file=sys.stderr)
        conn = engine.connect()
        # 既存の接続を強制終了する（Renderでは不要な場合が多いが念のため）
        # conn.execute(text('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid();'))
        
        # テーブルが存在すればDROP TABLEを実行
        for table_name in TABLES_TO_DROP:
            try:
                # CASCADE句を付けてテーブルを削除。外部キー制約も同時に削除される
                conn.execute(db.text(f'DROP TABLE IF EXISTS {table_name} CASCADE;'))
                print(f'Dropped table: {table_name}', file=sys.stderr)
            except Exception as e:
                print(f'Warning: Could not drop table {table_name}: {e}', file=sys.stderr)

        conn.commit()
        conn.close()
        
        # ----------------------------------------------------
        # 2. 最新のスキーマでテーブルを作成
        # ----------------------------------------------------
        print('Creating all tables with latest schema (256 length)...', file=sys.stderr)
        db.create_all()
        print('Database tables created successfully!', file=sys.stderr)

except Exception as e:
    # データベースへの接続やテーブル作成の失敗は致命的エラー
    print(f'CRITICAL ERROR during DB initialization: {e}', file=sys.stderr)
    sys.exit(1)
"

# Pythonスクリプトの実行が失敗したかどうかをチェック
if [ $? -ne 0 ]; then
    echo "--- Database initialization FAILED ---"
    exit 1
fi

echo "--- Database initialization finished ---"
