import os
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect, generate_csrf
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Cloudinary SDKのインポート
import cloudinary
import cloudinary.uploader

# .envファイルを読み込む (Render環境では自動的に環境変数が設定されるためローカル開発用)
load_dotenv()

# --- アプリケーション設定 ---
app = Flask(__name__)

# タイムゾーンをJSTに設定
JST = timezone(timedelta(hours=+9), 'JST')

# データベースURIの設定
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///myblog.db')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_needs_to_be_complex_and_secret')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MBまでのファイルサイズ制限

# --- 拡張機能の初期化 ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'

# --- Cloudinary設定 ---
# 環境変数から設定を読み込みます
CLOUDINARY_CLOUD_NAME = os.environ.get('CLOUD_NAME')
CLOUDINARY_API_KEY = os.environ.get('API_KEY')
CLOUDINARY_API_SECRET = os.environ.get('API_SECRET')

# Cloudinary設定が全て揃っているかチェック
CLOUDINARY_AVAILABLE = bool(CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET)

if CLOUDINARY_AVAILABLE:
    cloudinary.config(
        cloud_name=CLOUDINARY_CLOUD_NAME,
        api_key=CLOUDINARY_API_KEY,
        api_secret=CLOUDINARY_API_SECRET
    )
    print("Cloudinary is successfully configured.")
else:
    print("Cloudinary configuration missing. Image uploads will be skipped.")

# --- データベースモデル ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    posts = db.relationship('Post', backref='author', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    create_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(JST))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Cloudinary連携のための新しいフィールド
    public_id = db.Column(db.String(255), nullable=True) # Cloudinaryでの画像識別子

# --- ユーザーローダー ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- ヘルパー関数 ---

def get_safe_cloudinary_url(public_id, **options):
    """
    Cloudinaryが利用可能な場合にのみURLを生成し、そうでない場合は空の文字列を返します。
    """
    if CLOUDINARY_AVAILABLE and public_id:
        # width, height, cropなどの変換オプションを適用してURLを生成
        options.setdefault('fetch_format', 'auto')
        options.setdefault('quality', 'auto')
        return cloudinary.utils.cloudinary_url(public_id, **options)[0]
    return ""

def delete_cloudinary_image(public_id):
    """
    Cloudinaryから画像を削除します。
    """
    if CLOUDINARY_AVAILABLE and public_id:
        try:
            # 削除処理
            result = cloudinary.uploader.destroy(public_id)
            if result.get('result') == 'ok':
                print(f"Cloudinary image deleted successfully: {public_id}")
                return True
            else:
                print(f"Cloudinary deletion failed for {public_id}: {result.get('result')}")
                # 削除が失敗しても、致命的なエラーではないため続行
        except Exception as e:
            print(f"Error deleting Cloudinary image {public_id}: {e}")
    return False

# --- コンテキストプロセッサ ---
@app.context_processor
def inject_globals():
    """Jinja2テンプレートにグローバル変数とヘルパーを注入します。"""
    return {
        'now': datetime.now,
        'CLOUDINARY_AVAILABLE': CLOUDINARY_AVAILABLE,
        'get_cloudinary_url': get_safe_cloudinary_url, # これをテンプレートで使う
        'csrf_token': lambda: generate_csrf()
    }

# --- ルート定義 ---

@app.route('/')
@app.route('/index')
def index():
    posts = Post.query.order_by(Post.create_at.desc()).all()
    return render_template('index.html', posts=posts, title='最新のブログ記事')

@app.route('/user/<username>')
def user_blog(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(user_id=user.id).order_by(Post.create_at.desc()).all()
    return render_template('index.html', posts=posts, title=f'{username} のブログ記事')

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        image_file = request.files.get('image_file')
        public_id = None

        if not title or not content:
            flash('タイトルと本文は必須です。', 'danger')
            return render_template('create_update.html', title='新規記事投稿', post=None)

        if CLOUDINARY_AVAILABLE and image_file and image_file.filename != '':
            try:
                # Cloudinaryに画像をアップロード
                upload_result = cloudinary.uploader.upload(
                    image_file,
                    folder=f"flask_blog_images/{current_user.username}",
                    resource_type="image"
                )
                # public_idを保存
                public_id = upload_result.get('public_id')
                flash('画像が正常にアップロードされました。', 'success')
            except Exception as e:
                flash(f'画像のアップロード中にエラーが発生しました: {e}', 'warning')
                print(f"Cloudinary upload error: {e}")

        # データベースに記事を保存
        new_post = Post(
            title=title,
            content=content,
            user_id=current_user.id,
            public_id=public_id  # public_idをモデルに保存
        )
        db.session.add(new_post)
        db.session.commit()
        flash('新しい記事が正常に投稿されました。', 'success')
        return redirect(url_for('index'))

    return render_template('create_update.html', title='新規記事投稿', post=None)

@app.route('/post/<int:post_id>')
def view(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)
    return render_template('view.html', post=post, title=post.title)

@app.route('/post/<int:post_id>/update', methods=['GET', 'POST'])
@login_required
def update(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)

    # 記事の作成者または管理者のみ編集可能
    if post.author != current_user and not current_user.is_admin:
        flash('この記事を編集する権限がありません。', 'danger')
        return redirect(url_for('view', post_id=post.id))

    if request.method == 'POST':
        post.title = request.form.get('title')
        post.content = request.form.get('content')
        image_file = request.files.get('image_file')
        delete_image = request.form.get('delete_image') == 'on'

        if not post.title or not post.content:
            flash('タイトルと本文は必須です。', 'danger')
            return render_template('create_update.html', title='記事の編集', post=post)

        # 1. 画像削除の処理
        if delete_image and post.public_id:
            delete_cloudinary_image(post.public_id)
            post.public_id = None # DBからもpublic_idを削除
            flash('画像が削除されました。', 'success')
        
        # 2. 新しい画像アップロードの処理
        if CLOUDINARY_AVAILABLE and image_file and image_file.filename != '':
            # 既存の画像があれば削除してからアップロード
            if post.public_id:
                delete_cloudinary_image(post.public_id)

            try:
                upload_result = cloudinary.uploader.upload(
                    image_file,
                    folder=f"flask_blog_images/{current_user.username}",
                    resource_type="image"
                )
                post.public_id = upload_result.get('public_id')
                flash('新しい画像が正常にアップロードされました。', 'success')
            except Exception as e:
                flash(f'画像のアップロード中にエラーが発生しました: {e}', 'warning')
                print(f"Cloudinary upload error: {e}")

        db.session.commit()
        flash('記事が正常に更新されました。', 'success')
        return redirect(url_for('view', post_id=post.id))

    return render_template('create_update.html', title='記事の編集', post=post)


@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)

    # 記事の作成者または管理者のみ削除可能
    if post.author != current_user and not current_user.is_admin:
        flash('この記事を削除する権限がありません。', 'danger')
        return redirect(url_for('view', post_id=post.id))

    # Cloudinaryから画像を削除
    if post.public_id:
        delete_cloudinary_image(post.public_id)

    # データベースから記事を削除
    db.session.delete(post)
    db.session.commit()
    flash('記事が正常に削除されました。', 'success')
    return redirect(url_for('index'))

# --- 認証ルート (省略) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        # ... (既存の登録処理) ...
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not username or not email or not password:
            flash('すべてのフィールドを入力してください。', 'danger')
            return render_template('register.html', title='新規登録')
        
        if User.query.filter_by(username=username).first():
            flash('このユーザー名は既に使われています。', 'danger')
            return render_template('register.html', title='新規登録')
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('アカウントが作成されました！ログインしてください。', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='新規登録')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        # ... (既存のログイン処理) ...
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True)
            flash('ログインに成功しました。', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('ログインに失敗しました。ユーザー名またはパスワードが正しくありません。', 'danger')
    return render_template('login.html', title='ログイン')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('ログアウトしました。', 'info')
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# --- データベース初期化 (初回デプロイ時などに実行) ---
@app.cli.command("init-db")
def init_db():
    """データベーステーブルを作成します。"""
    try:
        with app.app_context():
            # 既存のテーブルを削除してから再作成 (開発・デプロイ初期用)
            # db.drop_all()
            db.create_all()
            
            # デモユーザーと管理者を作成 (初回のみ)
            if not User.query.filter_by(username='admin').first():
                admin_user = User(
                    username='admin', 
                    email='admin@example.com', 
                    password=bcrypt.generate_password_hash('password').decode('utf-8'),
                    is_admin=True
                )
                db.session.add(admin_user)
            
            db.session.commit()
            print("Database initialized and tables created successfully.")
            
    except Exception as e:
        print(f"Error during database initialization: {e}")
        # PostgreSQLの場合、接続エラーが発生することがあります
        print("Please ensure your DATABASE_URL is correct and the database is running.")


if __name__ == '__main__':
    # 開発環境での実行
    app.run(debug=True)

# Render環境での実行用に'app'を定義
application = app
