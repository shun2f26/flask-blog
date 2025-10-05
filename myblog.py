# myblog.py (db_initの再追加)

import os
import sys
from flask import Flask, render_template, request, redirect, flash, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
# UserMixin, login_user, ... はそのまま
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import secrets
# itsdangerousをインポート（トークン生成・検証用）
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
    
    # RenderのPostgreSQL接続にはsslmode=requireが必須 (既に設定されているかチェック)
    if 'sslmode=require' not in database_url and 'sslmode' not in database_url:
        separator = '&' if '?' in database_url else '?'
        database_url += f'{separator}sslmode=require'
    
    # PostgreSQL接続のためのデバッグ情報
    print("--- データベース接続情報 ---", file=sys.stderr)
    print(f"使用DB: PostgreSQL (環境変数 'DATABASE_URL' を使用)", file=sys.stderr)
    # ユーザーが接続URLを確認しやすいように一部表示（パスワードは隠す）
    print(f"接続URL: {database_url.split('@')[0]}@...", file=sys.stderr) 
    print("PostgreSQLを使用するには **'psycopg2-binary'** が必要です。", file=sys.stderr)
    print("----------------------------", file=sys.stderr)
    
else:
    # ローカル開発用のデフォルト設定
    database_url = 'sqlite:///site.db'
    # SQLite接続のためのデバッグ情報
    print("--- データベース接続情報 ---", file=sys.stderr)
    print("使用DB: SQLite (環境変数 'DATABASE_URL' が未設定のため)", file=sys.stderr)
    print("----------------------------", file=sys.stderr)
    
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ログイン管理システム
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 
login_manager.login_message = 'ログインが必要です。' 

# --- データベースとマイグレーションの設定 ---

db = SQLAlchemy()
migrate = Migrate()
db.init_app(app)
migrate.init_app(app, db) 

# アップロードが許可される拡張子 
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# --- データベースモデル ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    
    # Flask-Login の要件を満たすために is_active などを明示的に定義 (UserMixinに含まれているが、明示することで安全性が向上)
    @property
    def is_active(self):
        return True # ユーザーは常にアクティブ
    
    @property
    def is_authenticated(self):
        return True # 認証済み
    
    @property
    def is_anonymous(self):
        return False # 匿名ではない

    # パスワードリセット用のトークンを生成するメソッド
    def get_reset_token(self, expires_sec=1800): # トークン有効期限30分
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        # ユーザーIDをシリアライズしてトークンを生成
        return s.dumps({'user_id': self.id})

    # トークンからユーザーをロードするクラスメソッド
    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            # トークンをロードし、有効期限切れかどうかをチェック
            data = s.loads(token, max_age=expires_sec)
        except (SignatureExpired, BadTimeSignature):
            return None
        # トークンから取得したuser_idでユーザーを検索
        return db.session.get(User, data['user_id'])


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    # bodyの長さをHello.pyの1000から5000に修正 (ブログ記事として十分な長さに)
    body = db.Column(db.String(5000), nullable=False) 
    create_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    img_name = db.Column(db.String(300), nullable=True, default="placeholder.jpg") 
    
@login_manager.user_loader 
def load_user(user_id):
    # **修正点**: user_idがNoneでないことを確認し、db.session.get()を使用
    if user_id is None:
        return None
    return db.session.get(User, int(user_id))

# --- ヘルパー関数 (SQLAlchemy 2.0対応) ---

def get_post_or_404(post_id):
    # SQLAlchemy 2.0 の推奨 get メソッドを使用
    post = db.session.get(Post, post_id)
    if post is None: abort(404)
    return post

def get_user_by_username(username):
    # SQLAlchemy 2.0 の select + scalar_one_or_none を使用
    return db.session.execute(
        db.select(User).filter_by(username=username)
    ).scalar_one_or_none()

# --- ルーティング ---

# 🚨 データベース初期化用の特別なルート (テーブルが存在しないエラー対策)
@app.route("/db_init")
def db_init():
    # 既にテーブルが存在する場合は何もしないようにしたいが、強制的に作成する
    try:
        db.create_all()
        # テーブル作成が成功した後、マイグレーション履歴テーブルも作成されるようにしておく
        # これはFlask-Migrateが初期化されていないとエラーになる可能性があるため、より安全なのはdb.create_all()のみ
        return "Database tables (Post and User) created successfully! Please remove this route after running once.", 200
    except Exception as e:
        # DB接続自体ができていない場合は、エラーメッセージを表示
        return f"Error creating tables. Please check your DATABASE_URL and the psycopg2-binary installation in requirements.txt. Error: {e}", 500


@app.route("/")
def index():
    posts = db.session.execute(
        db.select(Post).order_by(Post.create_at.desc())
    ).scalars().all()
    return render_template("index.html", posts=posts)

@app.route("/post/<int:post_id>")
def view(post_id):
    post = get_post_or_404(post_id)
    return render_template("view.html", post=post)

@app.route("/admin")
@login_required
def admin():
    posts = db.session.execute(
        db.select(Post).order_by(Post.create_at.desc())
    ).scalars().all()
    return render_template("admin.html", posts=posts)

@app.route("/create", methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form.get('title')
        body = request.form.get('body')
        
        # 画像アップロード機能はRender環境では永続化が難しいため、ここでは画像名のみを処理
        img_name = request.form.get('img_name') or "placeholder.jpg" 

        post = Post(title=title, body=body, img_name=img_name) 
        
        db.session.add(post)
        db.session.commit()
        flash('記事が正常に作成されました。', 'success')
        return redirect(url_for('admin'))
    
    return render_template('create.html')
        
@app.route("/<int:post_id>/update",methods =['GET','POST'])
@login_required
def update(post_id):
    post = get_post_or_404(post_id)
    
    if request.method == 'POST':
        post.title = request.form.get('title')
        post.body = request.form.get('body')
        
        db.session.commit()
        flash('記事が正常に更新されました。', 'success')
        return redirect(url_for('admin'))
        
    return render_template('update.html', post=post)
    
@app.route("/<int:post_id>/delete")
@login_required
def delete(post_id):
    post = get_post_or_404(post_id)
    
    db.session.delete(post)
    db.session.commit()
    flash('記事が正常に削除されました。', 'danger')
    return redirect(url_for('admin')) 

# --- 認証ルート ---

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('ユーザー名とパスワードを入力してください。', 'warning')
            return redirect(url_for('signup'))
        
        if get_user_by_username(username):
            flash('そのユーザー名はすでに使われています。', 'warning')
            return redirect(url_for('signup'))

        hashed_pass = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_pass)
        
        db.session.add(new_user)
        db.session.commit()
        # **重要**: サインアップ後、すぐにログイン状態にする
        login_user(new_user)
        flash('登録が完了しました。', 'success')
        return redirect(url_for('admin')) # 登録後、管理画面へ
        
    return render_template('signup.html')
        
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin')) # 既にログイン済みなら管理画面へ

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = get_user_by_username(username)
        
        if user and check_password_hash(user.password, password=password):
            # ログイン成功
            login_user(user)
            flash('ログイン成功！', 'success')
            next_page = request.args.get('next')
            # ログイン要求元（next）がなければ admin へリダイレクト
            return redirect(next_page or url_for('admin')) 
        else:
            flash('ユーザー名またはパスワードが違います', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('ログアウトしました。', 'info')
    return redirect(url_for('index'))


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    user = current_user

    if request.method == 'POST':
        new_username = request.form.get('username')
        current_password = request.form.get('current_password')

        # パスワード確認（現在のパスワードが必須）
        if not check_password_hash(user.password, current_password or ''):
            flash('現在のパスワードが間違っています。', 'danger')
            return redirect(url_for('account'))

        is_updated = False
        
        # ユーザー名更新
        if new_username and new_username != user.username:
            existing_user = get_user_by_username(new_username)
            if existing_user and existing_user.id != user.id:
                flash('そのユーザー名は既に使用されています。', 'warning')
                return redirect(url_for('account'))
            
            user.username = new_username
            is_updated = True

        # パスワード更新
        new_password = request.form.get('new_password')
        if new_password:
            user.password = generate_password_hash(new_password, method='sha256')
            is_updated = True
            
        if is_updated:
            db.session.commit()
            flash('アカウント情報が更新されました。', 'success')
        else:
             flash('更新する情報がありませんでした。', 'info')
            
        return redirect(url_for('account'))

    return render_template('account.html', user=user)

# --- パスワードリセット関連ルート ---

# ステップ1: リセット要求（ユーザー名/メールアドレスの入力）
@app.route("/forgot_password", methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username') # ユーザー名 (メールアドレスの代わり)
        user = get_user_by_username(username)

        if user:
            # 実際にはここで Flask-Mail を使ってメールを送信する
            token = user.get_reset_token()
            
            # **重要**: Render環境ではメール送信機能がないため、デバッグ用にリンクをフラッシュメッセージとして表示します。
            reset_url = url_for('reset_password', token=token, _external=True)
            
            flash(f'パスワードリセットのリンクを送信しました（ダミー）。次のリンクにアクセスしてください（30分有効）：{reset_url}', 'success')
            
            return redirect(url_for('login'))
        else:
            # セキュリティのため、ユーザーが存在しない場合でも成功したかのように振る舞う
            flash('リセット情報が送信されました（ユーザーが存在すれば）。', 'info')
            return redirect(url_for('login'))

    return render_template('forgot_password.html')

# ステップ2: 新しいパスワードの設定
@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    user = User.verify_reset_token(token)

    if user is None:
        flash('トークンが無効であるか、期限切れです。再度リセットを要求してください。', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password') 
        
        if password != confirm_password:
            flash('パスワードが一致しません。', 'danger')
            # エラー時もトークンを保持して同じページに戻る
            return redirect(url_for('reset_password', token=token)) 
            
        user.password = generate_password_hash(password, method='sha256')
        db.session.commit()
        flash('パスワードが正常にリセットされました。新しいパスワードでログインしてください。', 'success')
        return redirect(url_for('login'))

    # 成功したトークンがある場合、リセットフォームを表示
    return render_template('reset_password.html', token=token)


# --- エラーハンドラー ---

@app.errorhandler(404)
def page_not_found(e):
    # 404.html テンプレートが存在することを想定
    try:
        return render_template('404.html'), 404
    except:
        return "404 Not Found", 404


# --- アプリケーション実行 (ローカル開発用) ---
if __name__ == '__main__':
    with app.app_context():
        # SQLiteファイルが存在しない場合にテーブルを作成します。
        # データベースの接続URLが'sqlite:///'で始まる場合にのみ実行。
        if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite:///'):
            db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
            if not os.path.exists(db_path):
                print(f"データベースファイル '{db_path}' が見つかりませんでした。テーブルを作成します...")
                try:
                    # データベースの初期化
                    db.create_all()
                    # 初期ユーザーの作成（オプション）
                    # 例: admin_user = User(username='admin', password=generate_password_hash('password', method='sha256'))
                    # db.session.add(admin_user)
                    # db.session.commit()
                    print("データベーステーブルの作成が完了しました。")
                except Exception as e:
                    print(f"データベースの初期化中にエラーが発生しました: {e}", file=sys.stderr)
                    
        # ローカル開発時にサーバーを起動
        app.run(debug=True)
