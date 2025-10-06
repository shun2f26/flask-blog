#!/usr/bin/env bash

# アプリケーションの依存関係をインストール
pip install -r requirements.txt

# --- データベースのリセットと初期化 ---
# 警告: 本番環境では注意して使用してください。
# FlaskのUserモデルのテーブル名はPostgreSQL予約語を避けるため 'users' に変更されています。

echo "=> データベースのリセットを開始..."
# 環境変数からデータベースURLを取得
DB_URL=$DATABASE_URL

if [ -z "$DB_URL" ]; then
    echo "環境変数 DATABASE_URL が設定されていません。スキップします。"
else
    # PostgreSQL接続情報から認証情報を抽出
    python3 -c "
import os
import sqlalchemy as sa
from sqlalchemy.exc import SQLAlchemyError

db_url = os.environ.get('DATABASE_URL')
if not db_url:
    print('データベースURLがありません。')
    exit()

# RenderのPostgreSQL URI互換性のための置換
db_url = db_url.replace('postgres://', 'postgresql://')

try:
    engine = sa.create_engine(db_url)
    connection = engine.connect()

    print('接続を試行しています : ' + db_url.split('@')[0] + '@' + db_url.split('@')[1].split('/')[0] + '...')

    # 生のSQL経由でテーブルを強制的に削除
    print('生のSQL経由でテーブルを強制的に削除しています...')
    # 修正点: 'user' ではなく 'users' を削除対象にする
    connection.execute(sa.text('DROP TABLE IF EXISTS users CASCADE;'))
    connection.execute(sa.text('DROP TABLE IF EXISTS post CASCADE;'))
    connection.commit()
    print('テーブル (users, post) の削除完了。')
    connection.close()
    
    # 既存のテーブルを削除後、新しいテーブルを作成
    print('テーブルを作成します...')
    import myblog
    with myblog.app.app_context():
        # db.create_all() を実行し、myblog.pyで定義されたテーブル（users, post）を作成
        myblog.db.create_all()
    print('データベーステーブルの作成が完了しました。')

except SQLAlchemyError as e:
    print(f'警告: データベース操作中にエラーが発生しました: {e}')
    print('データベースのマイグレーションを手動で行うか、Renderの環境設定を確認してください。')

"
fi

echo "=> ビルド完了"
