# Hello.py (SQLAlchemy 2.0 形式に統一)

import os
import sys
from flask import Flask, render_template, request, redirect, flash, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
import cloudinary 
import cloudinary.uploader
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import secrets
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature 

# --- アプリケーション設定 ---

app = Flask(__name__) 

# Render環境変数から SECRET_KEY と DATABASE_URL を取得
app.config["SECRET_KEY"] = os.environ.get('SECRET_KEY', secrets.token_hex(16))

database_url = os.environ.get('DATABASE_URL')

if database_url:
    # Renderの古いURL形式(postgres://)を新しい形式(postgresql://)に変換
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    # RenderのPostgreSQL接続にはsslmode=requireが必須
    if 'sslmode=require' not in database_url and 'sslmode' not in database_url:
        separator = '&' if '?' in database_url else '?'
        database_url += f'{separator}sslmode=require'
    
    # デバッグ情報
    print("--- データベース接続情報 ---", file=sys.stderr)
    print(f"接続URL: {database_url.split('@')[0]}@...", file=sys.stderr) 
    print("----------------------------", file=sys.stderr)
    
else:
    database_url = 'sqlite:///site.db'
    print("--- データベース接続情報 ---", file=sys.stderr)
    print("使用DB: SQLite", file=sys.stderr)
    print("----------------------------", file=sys.stderr)
    
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Cloudinaryの設定（環境変数から自動読み込み）
cloudinary.config(
    cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME'),
    api_key = os.environ.get('CLOUDINARY_API_KEY'),
    api_secret = os.environ.get('CLOUDINARY_API_SECRET'),
    secure = True
)

# ログイン管理システム
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 
login_manager.login_message = 'ログインが必要です。' 

# --- データベースの設定 ---
db = SQLAlchemy()
db.init_app(app) 

# --- GUNICORN起動時のデータベース初期化 ---
# アプリケーションがGunicornによって起動される際、このコードブロックが一度実行されます。
# データベース接続が確立されている場合にのみテーブルを作成します。
with app.app_context():
    try:
        # テーブルが存在しない場合にのみ作成されます (初回デプロイ、またはデータが失われた場合)
        db.create_all() 
        print("Database tables initialized successfully.", file=sys.stderr)
    except Exception as e:
        # DB接続エラー（PostgreSQLサーバーがまだ起動していないなど）の場合はここでキャッチ
        print(f"Database initialization failed at startup: {e}", file=sys.stderr)
# ----------------------------------------


# アップロードが許可される拡張子 
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# --- データベースモデル ---

class User(UserMixin, db.Model):
# ... (User, Postモデル、およびその下の関数やルートは変更なし)
# ...
# ...

# --- データベースリセット＆初期化専用ルート (重要: 実行後に必ずアクセス) ---
# このルートは既存のテーブルをすべて削除してから再作成します。データは失われます。
@app.route('/db_reset')
def db_reset():
    # 🚨 セキュリティのため、環境変数で指定されたSECRET_KEYを確認するなどの保護を検討してください。
    
    try:
        db.drop_all()
        db.create_all()
        return "Database tables reset and recreated successfully! **IMPORTANT**: Please remove this route after running once."
    except Exception as e:
        # エラーが発生した場合は、contextの欠如ではなく他の問題の可能性が高いため、エラーログを出力
        return f"Database initialization failed: {e}", 500
# ----------------------------------------------------------------------


@app.route("/")
def index():
# ... (他のすべてのルート、エラーハンドラーは変更なし)
# ...
# ...
@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_password(token):
# ...
    return render_template('reset_password.html', token=token)


# --- エラーハンドラー ---

@app.errorhandler(404)
def page_not_found(e):
    try:
        return render_template('404.html'), 404
    except:
        return "404 Not Found", 404


# --- アプリケーション実行 (ローカル開発用) ---
if __name__ == '__main__':
    with app.app_context():
        # ローカルでの開発実行時にテーブルを作成
        db.create_all() 
    app.run(debug=True)
