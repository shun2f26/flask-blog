import os
import sys # sysのインポートを追加
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_migrate import Migrate
from sqlalchemy.orm import relationship
from sqlalchemy_utils import database_exists, create_database
from datetime import datetime, timedelta, timezone
import requests
import json
import base64
from io import BytesIO
import cloudinary
import cloudinary.uploader
import cloudinary.utils

# Cloudinaryの設定 (環境変数から取得)
cloudinary.config( 
  cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME'), 
  api_key = os.environ.get('CLOUDINARY_API_KEY'), 
  api_secret = os.environ.get('CLOUDINARY_API_SECRET'),
  secure = True
)

# Flaskアプリのインスタンス作成
app = Flask(__name__) 

# --- アプリ設定 ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'my_default_secret_key') # ローカル開発用のフォールバックも用意

# Heroku / Render 互換性のためのURL修正ロジック（そのまま残す）
uri = os.environ.get('DATABASE_URL')
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)

# SQLiteがデフォルトのURIとして機能するように設定
app.config['SQLALCHEMY_DATABASE_URI'] = uri if uri else 'sqlite:///myblog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

# --- SQLAlchemy/Migrate の遅延初期化 (Lazy Init) ---
db = SQLAlchemy() 
bcrypt = Bcrypt()
login_manager = LoginManager()
migrate = Migrate() # Migrateインスタンスをここで作成

db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)
# RenderのGunicorn起動時にDB接続エラーでフリーズするのを防ぐため、
# Migrateの初期化をRender Shellでのみ実行するように削除またはコメントアウト
# migrate.init_app(app, db) # <-- コメントアウトまたは削除

login_manager.login_view = 'login'
login_manager.login_message = 'このページにアクセスするにはログインが必要です。'
login_manager.login_message_category = 'info'


# -------------------------------------------------------------------
# !!! Render Free Tier 対策: アプリ起動時にテーブル作成を試みる !!!
# -------------------------------------------------------------------
# Gunicornがアプリをロードする際に実行されます
try:
    with app.app_context():
        # DBが存在しない場合、作成を試みる（SQLiteの場合のみ有効）
        if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite') and not os.path.exists(app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')):
             print("Local SQLite database not found, skipping immediate creation.", file=sys.stderr)
        
        # テーブルが存在しなければ作成する。存在してもエラーにならないよう試みる
        # (Renderの環境では、これが初回デプロイでのテーブル作成の役割を果たす)
        db.create_all()
        print("Database tables ensured to be created.", file=sys.stderr)
except Exception as e:
    # テーブルが既に存在するエラーや、その他の起動時エラーをキャッチし、
    # アプリケーションの起動自体は続行させる（500エラー対策）
    print(f"Error during initial db.create_all(): {e}", file=sys.stderr)
    
# -------------------------------------------------------------------

# --- タイムゾーン設定 (日本時間) ---
def now():
    """現在の日本時間 (JST) を返すヘルパー関数"""
    return datetime.now(timezone(timedelta(hours=9)))

# --- モデル定義 ---

class User(UserMixin, db.Model):
    """ユーザーモデル"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # パスワードハッシュの長さを256に設定 (bcryptのハッシュ長を考慮)
    password_hash = db.Column(db.String(256))
    posts = relationship('Post', backref='author', lazy='dynamic')
    
    # パスワードリセットトークン用
    reset_token = db.Column(db.String(256), nullable=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        """パスワードをハッシュ化して保存する"""
        # Bcryptのハッシュは通常60文字以上になるため、長めに設定
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """入力されたパスワードとハッシュを比較する"""
        return bcrypt.check_password_hash(self.password_hash, password)

class Post(db.Model):
    """記事モデル"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    # Cloudinaryの public_id を保存
    public_id = db.Column(db.String(100), nullable=True) 
    create_at = db.Column(db.DateTime, nullable=False, default=now)
    # 外部キー (Userモデルのidを参照)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- ユーザーローダー ---

@login_manager.user_loader
def load_user(user_id):
    """Flask-LoginがセッションからユーザーIDをロードするためのコールバック"""
    return db.session.get(User, int(user_id))

# --- パスワードハッシュ/チェックのヘルパー関数 (Userモデルに統合済みだが、念のため) ---
# ... 削除/Userモデルに統合済みと仮定 ...

# --- ルーティング ---

@app.route('/')
def index():
    """ブログ記事一覧ページ"""
    # 記事を最新順で取得
    posts = db.session.execute(db.select(Post).order_by(Post.create_at.desc())).scalars().all()
    return render_template('index.html', posts=posts)

# ... (その他のルーティング: view, create, update, delete, admin, login, signup, logout, account はそのまま) ...
# ... (forgot_password と reset_password のロジックもそのまま) ...

# -----------------------------------------------------------------------------------
# !!! ここから先は、以前提供されたルーティング、API呼び出し、フォーム処理などを追加してください !!!
# -----------------------------------------------------------------------------------

# 記事詳細
@app.route('/post/<int:post_id>')
def view(post_id):
    """記事詳細ページ"""
    post = db.session.get(Post, post_id)
    if not post:
        return render_template('404.html', title="404 記事が見つかりません"), 404
    
    # Cloudinary ユーティリティをテンプレートに渡す
    return render_template('view.html', post=post, cloudinary=cloudinary)

# 新規投稿
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """新規記事投稿ページ"""
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        image_file = request.files.get('image')
        public_id = None

        if not title or not content:
            flash('タイトルと本文を入力してください。', 'warning')
            return render_template('create.html', title=title, content=content)

        # Cloudinaryに画像をアップロード
        if image_file and image_file.filename != '':
            try:
                # アップロード処理
                upload_result = cloudinary.uploader.upload(image_file, 
                                                          folder="flask_blog_images", 
                                                          # 適切なサイズ調整をここで実行することも可能
                                                          overwrite=True)
                public_id = upload_result.get('public_id')
                flash('画像が正常にアップロードされました。', 'success')
            except Exception as e:
                flash(f'画像のアップロード中にエラーが発生しました: {e}', 'danger')
                # エラーが発生しても記事は投稿できるようにする

        # データベースに記事を保存
        new_post = Post(title=title, 
                        content=content, 
                        user_id=current_user.id, 
                        public_id=public_id,
                        create_at=now())
        db.session.add(new_post)
        db.session.commit()
        flash('新しい記事が正常に投稿されました。', 'success')
        return redirect(url_for('index'))

    return render_template('create.html')

# 記事編集
@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
def update(post_id):
    """記事編集ページ"""
    post = db.session.get(Post, post_id)

    if not post or post.user_id != current_user.id:
        flash('編集権限がありません、または記事が見つかりません。', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        post.title = request.form.get('title')
        post.content = request.form.get('content')
        image_file = request.files.get('image')
        delete_image = request.form.get('delete_image') # 画像削除チェックボックス

        if not post.title or not post.content:
            flash('タイトルと本文を入力してください。', 'warning')
            return render_template('update.html', post=post)

        # 画像削除処理
        if delete_image == 'on' and post.public_id:
            try:
                cloudinary.uploader.destroy(post.public_id)
                post.public_id = None
                flash('画像を削除しました。', 'success')
            except Exception as e:
                flash(f'画像の削除中にエラーが発生しました: {e}', 'danger')
        
        # 新規画像アップロード処理
        if image_file and image_file.filename != '':
            try:
                # 既存の画像があれば削除
                if post.public_id:
                    cloudinary.uploader.destroy(post.public_id)
                
                upload_result = cloudinary.uploader.upload(image_file, 
                                                          folder="flask_blog_images", 
                                                          overwrite=True)
                post.public_id = upload_result.get('public_id')
                flash('新しい画像が正常にアップロードされました。', 'success')
            except Exception as e:
                flash(f'画像のアップロード中にエラーが発生しました: {e}', 'danger')

        db.session.commit()
        flash('記事が正常に更新されました。', 'success')
        return redirect(url_for('view', post_id=post.id))

    return render_template('update.html', post=post)

# 記事削除
@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required
def delete(post_id):
    """記事削除処理"""
    post = db.session.get(Post, post_id)

    if not post or post.user_id != current_user.id:
        flash('削除権限がありません、または記事が見つかりません。', 'danger')
        return redirect(url_for('index'))

    # Cloudinaryから画像を削除
    if post.public_id:
        try:
            cloudinary.uploader.destroy(post.public_id)
            flash('画像も正常に削除されました。', 'success')
        except Exception as e:
            # ログに記録するが、アプリの動作は止めない
            print(f"Cloudinary delete error: {e}", file=sys.stderr)

    # データベースから記事を削除
    db.session.delete(post)
    db.session.commit()
    flash('記事が正常に削除されました。', 'success')
    return redirect(url_for('index'))

# ログイン
@app.route('/login', methods=['GET', 'POST'])
def login():
    """ログインページ"""
    # ログイン済みの場合はホームへ
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
        
        if user and user.check_password(password):
            # ログイン成功
            login_user(user)
            # 次にアクセスしようとしていたページへリダイレクト。なければホームへ
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            # ログイン失敗
            flash('ユーザー名またはパスワードが正しくありません。', 'danger')
    
    return render_template('login.html')

# サインアップ
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """サインアップ（新規ユーザー登録）ページ"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # ユーザー名が既に存在するかチェック
        existing_user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
        
        if existing_user:
            flash('このユーザー名は既に使われています。', 'danger')
        elif len(username) < 3:
            flash('ユーザー名は3文字以上で入力してください。', 'danger')
        elif len(password) < 6:
            flash('パスワードは6文字以上で入力してください。', 'danger')
        else:
            # 新規ユーザー作成
            new_user = User(username=username)
            new_user.set_password(password) # パスワードをハッシュ化して設定
            
            db.session.add(new_user)
            db.session.commit()
            
            flash('登録が完了しました。ログインしてください。', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html')

# ログアウト
@app.route('/logout')
@login_required
def logout():
    """ログアウト処理"""
    logout_user()
    flash('ログアウトしました。', 'info')
    return redirect(url_for('index'))

# 管理画面
@app.route('/admin')
@login_required
def admin():
    """管理画面（自分の記事一覧）"""
    # 自分の記事のみを最新順で取得
    posts = db.session.execute(
        db.select(Post).filter_by(user_id=current_user.id).order_by(Post.create_at.desc())
    ).scalars().all()
    return render_template('admin.html', posts=posts)

# アカウント設定
@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    """アカウント設定（ユーザー名/パスワード変更）"""
    user = current_user

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('new_password')
        current_password = request.form.get('current_password')

        # 1. 現在のパスワード確認 (必須)
        if not user.check_password(current_password):
            flash('現在のパスワードが正しくありません。', 'danger')
            return redirect(url_for('account'))

        has_changes = False

        # 2. ユーザー名変更
        if new_username and new_username != user.username:
            if len(new_username) < 3:
                flash('ユーザー名は3文字以上で入力してください。', 'danger')
                return redirect(url_for('account'))
            
            existing_user = db.session.execute(db.select(User).filter_by(username=new_username)).scalar_one_or_none()
            if existing_user and existing_user.id != user.id:
                flash('この新しいユーザー名は既に使われています。', 'danger')
                return redirect(url_for('account'))
            
            user.username = new_username
            has_changes = True
            flash('ユーザー名が変更されました。', 'success')

        # 3. パスワード変更
        if new_password:
            if len(new_password) < 6:
                flash('新しいパスワードは6文字以上で入力してください。', 'danger')
                return redirect(url_for('account'))
            
            user.set_password(new_password)
            has_changes = True
            flash('パスワードが変更されました。次回から新しいパスワードでログインしてください。', 'success')

        if has_changes:
            db.session.commit()
        else:
            flash('変更する項目がありませんでした。', 'info')

        return redirect(url_for('account'))

    return render_template('account.html', user=user)


# --- パスワードリセット機能 (ダミー実装) ---

# パスワードリセット要求
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """パスワードリセット要求ページ"""
    if request.method == 'POST':
        username = request.form.get('username')
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
        
        # ユーザーが存在しなくても、セキュリティ上、成功メッセージを返す（ユーザー名漏洩防止）
        flash('パスワードリセット用のリンクが送信されました。', 'info')
        
        if user:
            # 実際にはここでメール送信処理を行うが、今回はダミー
            # トークンを生成・保存（ここではUUIDなどを生成・保存するが、今回は簡単なダミー）
            token = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
            user.reset_token = token
            user.reset_token_expires = now() + timedelta(minutes=30) # 30分間の有効期限
            db.session.commit()
            
            # 開発環境向けのコンソール出力（メールの代わりに表示）
            print(f"--- DUMMY PASSWORD RESET LINK ---", file=sys.stderr)
            print(f"User: {user.username}", file=sys.stderr)
            print(f"Link: {url_for('reset_password', token=token, _external=True)}", file=sys.stderr)
            print(f"-----------------------------------", file=sys.stderr)

    return render_template('forgot_password.html')

# パスワードリセット実行
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """新しいパスワード設定ページ"""
    user = db.session.execute(db.select(User).filter_by(reset_token=token)).scalar_one_or_none()

    # トークンの検証
    if not user or user.reset_token_expires < now():
        flash('無効なトークン、または期限切れです。再度リセットを要求してください。', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('パスワードが一致しません。', 'danger')
        elif len(password) < 6:
            flash('パスワードは6文字以上で入力してください。', 'danger')
        else:
            # パスワードを更新し、トークンを無効化
            user.set_password(password)
            user.reset_token = None
            user.reset_token_expires = None
            db.session.commit()
            
            flash('パスワードが正常にリセットされました。ログインしてください。', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


# --- エラーハンドリング ---

@app.errorhandler(404)
def not_found_error(error):
    """404エラーハンドラ"""
    return render_template('404.html', title='404 ページが見つかりません'), 404

@app.errorhandler(500)
def internal_error(error):
    """500エラーハンドラ"""
    # データベースのセッションをロールバック (エラー発生時にセッションが壊れないように)
    db.session.rollback()
    return render_template('error_page.html', title='500 サーバー内部エラー', message='予期せぬエラーが発生しました。ログを確認してください。'), 500


# --- LLM機能: 記事の概要生成 (Gemini API利用) ---
# ...

# --- メイン実行ブロック ---
if __name__ == '__main__':
    # ローカル開発環境でのみ動作するデータベース初期化ロジック
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        if not os.path.exists('myblog.db'):
            # ローカル環境で初回実行時にテーブルを作成
            with app.app_context():
                db.create_all()
                print("Local SQLite database created.")
        
    app.run(debug=True)
