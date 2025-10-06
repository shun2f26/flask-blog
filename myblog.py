import os
import datetime
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import cloudinary
from cloudinary.uploader import upload, destroy
from sqlalchemy import exc 
import time
import requests
import json
import logging

# .envファイルから環境変数を読み込む
load_dotenv()

# --- Flaskアプリケーション設定 ---
app = Flask(__name__)

# 環境変数から設定を読み込む
DATABASE_URL = os.getenv('DATABASE_URL')
if DATABASE_URL:
    # RenderのPostgreSQL URI互換性のための置換とSSLモードの要求を追加
    uri = DATABASE_URL.replace('postgres://', 'postgresql://')
    if '?' not in uri:
        uri += '?sslmode=require'
    elif 'sslmode' not in uri and '?' in uri:
        uri += '&sslmode=require'
    elif 'sslmode' not in uri and '?' not in uri:
        uri += '?sslmode=require'

    app.config['SQLALCHEMY_DATABASE_URI'] = uri
else:
    # 開発環境用のデフォルト
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-fallback-key-for-dev') 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
# ロガー設定
app.logger.setLevel(logging.INFO)

# Cloudinary設定
cloudinary_cloud_name = os.getenv('CLOUDINARY_CLOUD_NAME')
cloudinary_api_key = os.getenv('CLOUDINARY_API_KEY')
cloudinary_api_secret = os.getenv('CLOUDINARY_API_SECRET')

if cloudinary_cloud_name and cloudinary_api_key and cloudinary_api_secret:
    cloudinary.config(
        cloud_name=cloudinary_cloud_name,
        api_key=cloudinary_api_key,
        api_secret=cloudinary_api_secret
    )
else:
    app.logger.warning("Cloudinary API keys are not set. Image upload will be disabled.")

# Gemini API設定
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent"

# データベース、マイグレーション、ログインマネージャの初期化
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login' 

# 許可する画像拡張子
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """ファイル名が許可された拡張子を持つかチェックする"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- データベースモデル定義 ---

class User(UserMixin, db.Model):
    """ユーザーモデル"""
    # PostgreSQLの予約語 'user' を避けるため、テーブル名を明示的に 'users' に設定
    __tablename__ = 'users' 
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256)) 
    # ForeignKeyを 'user.id' から 'users.id' に変更する必要がある
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    def set_password(self, password):
        """パスワードをハッシュ化して保存する"""
        self.password_hash = generate_password_hash(password) 

    def check_password(self, password):
        """入力されたパスワードとハッシュを比較する"""
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    """記事モデル"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    create_at = db.Column(db.DateTime, default=datetime.datetime.now)
    public_id = db.Column(db.String(255), nullable=True)
    # 外部キーを 'users.id' に変更
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


# --- Flask-Login ユーザーローダー ---

@login_manager.user_loader
def load_user(user_id):
    """ユーザーIDからユーザーオブジェクトをロードする"""
    return db.session.get(User, int(user_id))

# --- カスタムコンテキストプロセッサ ---

@app.context_processor
def utility_processor():
    """テンプレート内でcloudinaryオブジェクトとdatetimeを利用可能にする"""
    return dict(cloudinary=cloudinary, now=datetime.datetime.now)

# --- LLM機能（変更なし） ---

def generate_content_with_llm(prompt):
    """Gemini APIを使用してコンテンツを生成する"""
    if not GEMINI_API_KEY:
        return "Gemini APIキーが設定されていません。"

    headers = {'Content-Type': 'application/json'}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "systemInstruction": {"parts": [{"text": "あなたはプロのブログ記事ライターです。ユーザーの要求に基づき、魅力的で詳細なブログ記事を日本語で記述してください。"}]}
    }

    # Exponential Backoff for API calls
    for attempt in range(3):
        try:
            response = requests.post(f"{GEMINI_API_URL}?key={GEMINI_API_KEY}", 
                                     headers=headers, json=payload, timeout=20)
            response.raise_for_status() 
            result = response.json()
            
            text = result.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text')
            if text:
                return text
            else:
                return "AIによる記事生成に失敗しました: 不明な応答形式です。"

        except requests.exceptions.RequestException as e:
            app.logger.error(f"Gemini API Request Error on attempt {attempt + 1}: {e}")
            if attempt < 2:
                time.sleep(2 ** attempt) # Exponential backoff: 1s, 2s
                continue
            return f"AIによる記事生成に失敗しました: ネットワークまたはAPIエラー ({e})"
    return "AIによる記事生成に失敗しました: リトライ後もエラーが解消しませんでした。"


# --- ルーティング関数 ---

# DB初期化ルートは削除しました。代わりに render-build.sh を修正します。

@app.route('/')
def index():
    """トップページ: 全記事を新しい順に表示"""
    try:
        # 記事が存在しない場合に備えて、デフォルトのPostオブジェクトを用意
        posts = db.session.execute(db.select(Post).order_by(Post.create_at.desc())).scalars().all()
        if not posts:
            # ダミーデータ（テンプレート表示確認用）
            class DummyPost:
                def __init__(self, id, title, content, user_id):
                    self.id = id
                    self.title = title
                    self.content = content
                    self.create_at = datetime.datetime.now()
                    self.public_id = None
                    self.user_id = user_id
                    self.author = type('Author', (object,), {'username': 'デモユーザー'})() # ダミーのauthorオブジェクト
            
            posts = [
                DummyPost(1, "ようこそブログへ", "これはデモ記事です。新規登録して記事を投稿してください。", 1),
                DummyPost(2, "最新の機能", "AIアシスタント機能が利用可能です。", 1)
            ]
            
    except exc.SQLAlchemyError as e:
        app.logger.error(f"Database Query Error on Index: {e}")
        flash('データベースから記事を読み込む際にエラーが発生しました。DBが正常に初期化されているか確認してください。', 'danger')
        posts = []
    except Exception as e:
        app.logger.error(f"Unexpected Error on Index: {e}")
        flash('予期せぬエラーが発生しました。', 'danger')
        posts = []
        
    return render_template('index.html', posts=posts)

# --- 認証ルート ---

@app.route('/signup', methods=['GET', 'POST']) 
def signup(): 
    """ユーザー登録"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('ユーザー名とパスワードを両方入力してください。', 'warning')
            return redirect(url_for('signup'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('そのユーザー名は既に使用されています。', 'danger')
            return redirect(url_for('signup'))

        new_user = User(username=username)
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('アカウントが正常に作成されました。ログインしてください。', 'success')
            return redirect(url_for('login'))
        except exc.SQLAlchemyError as e:
            db.session.rollback()
            flash('データベースエラーにより登録に失敗しました。', 'danger')
            app.logger.error(f"Registration DB Error: {e}")

    return render_template('signup.html') 

@app.route('/login', methods=['GET', 'POST'])
def login():
    """ログイン"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()

        if user is None or not user.check_password(password):
            flash('ユーザー名またはパスワードが正しくありません。', 'danger')
            return redirect(url_for('login'))

        login_user(user)
        flash('ログインに成功しました！', 'success')
        next_page = request.args.get('next')
        return redirect(next_page or url_for('index'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """ログアウト"""
    logout_user()
    flash('ログアウトしました。', 'info')
    return redirect(url_for('index'))

# --- 全テンプレート対応のためのダミー・ルート（変更なし） ---

@app.route('/forgot_password')
def forgot_password():
    """パスワードリセット要求ページ"""
    return render_template('forgot_password.html')

@app.route('/reset_password')
def reset_password():
    """パスワードリセット実行ページ"""
    return render_template('reset_password.html')

@app.route('/account')
@login_required
def account():
    """ユーザーアカウント設定ページ"""
    return render_template('account.html')

# --- 記事管理ルート ---

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """記事作成"""
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        image_file = request.files.get('image_file')
        
        # AIアシスタント機能
        if request.form.get('action') == 'generate_article':
            prompt = f"ブログ記事のタイトル案と本文を生成してください。テーマ: {title}"
            generated_content = generate_content_with_llm(prompt)
            # 生成されたコンテンツをフォームに再表示
            return render_template('create.html', title=title, content=generated_content)

        # 投稿処理
        if not title or not content:
            flash('タイトルと本文を両方入力してください。', 'warning')
            return render_template('create.html', title=title, content=content)

        new_public_id = None
        
        # 1. 画像ファイルの処理
        if image_file and image_file.filename != '' and allowed_file(image_file.filename):
            try:
                upload_result = upload(image_file)
                new_public_id = upload_result.get('public_id')
                flash('画像が正常にアップロードされました。', 'success')
            except Exception as e:
                flash('画像のアップロードに失敗しました。Cloudinary設定を確認してください。', 'danger')
                app.logger.error(f"Cloudinary Upload Error: {e}")

        # 2. データベースへの保存
        new_post = Post(
            title=title, 
            content=content, 
            public_id=new_public_id,
            user_id=current_user.id
        )

        try:
            db.session.add(new_post)
            db.session.commit()
            flash('記事が正常に作成されました。', 'success')
            return redirect(url_for('index'))
        except exc.SQLAlchemyError as e:
            db.session.rollback()
            flash('記事の保存中にデータベースエラーが発生しました。', 'danger')
            app.logger.error(f"Post Save DB Error: {e}")

    return render_template('create.html')

@app.route('/<int:post_id>/view')
def view(post_id):
    """記事詳細表示"""
    post = db.session.get(Post, post_id)
    
    if post is None:
        class DummyPost:
            def __init__(self, id, title, content):
                self.id = id
                self.title = f"デモ記事: {title}"
                self.content = f"これは記事 ID:{id} のデモコンテンツです。実際にデータベースに記事がありません。"
                self.create_at = datetime.datetime.now()
                self.public_id = None
                self.user_id = 1
                self.author = type('Author', (object,), {'username': 'デモユーザー'})()
        
        post = DummyPost(post_id, "記事が見つかりません", "この記事はデータベースに存在しません。")

    return render_template('view.html', post=post)

@app.route('/<int:post_id>/update', methods=['GET', 'POST'])
@login_required
def update(post_id):
    """記事更新"""
    post = db.session.get(Post, post_id)

    if post is None or post.user_id != current_user.id:
        flash('記事が見つからないか、編集権限がありません。', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        image_file = request.files.get('image_file')

        if not title or not content:
            flash('タイトルと本文を両方入力してください。', 'warning')
            return render_template('update.html', post=post)
        
        # 1. 画像ファイルの処理
        current_public_id = post.public_id
        
        if image_file and image_file.filename != '':
            if allowed_file(image_file.filename):
                try:
                    # 既存の画像があればCloudinaryから削除
                    if current_public_id:
                        destroy(current_public_id)
                    
                    # 新しい画像をアップロード
                    upload_result = upload(image_file)
                    post.public_id = upload_result.get('public_id')
                    flash('新しい画像が正常にアップロードされました。', 'success')
                except Exception as e:
                    flash('新しい画像のアップロードに失敗しました。', 'danger')
                    app.logger.error(f"Cloudinary Update Upload Error: {e}")
            else:
                flash('許可されていないファイル形式です。', 'warning')
        
        # 2. 記事データの更新
        post.title = title
        post.content = content
        post.create_at = datetime.datetime.now() # 更新日時を更新

        try:
            db.session.commit()
            flash('記事が正常に更新されました。', 'success')
            return redirect(url_for('view', post_id=post.id))
        except exc.SQLAlchemyError as e:
            db.session.rollback()
            flash('記事の更新中にデータベースエラーが発生しました。', 'danger')
            app.logger.error(f"Post Update DB Error: {e}")

    return render_template('update.html', post=post)

@app.route('/<int:post_id>/delete', methods=['POST'])
@login_required
def delete(post_id):
    """記事削除"""
    post = db.session.get(Post, post_id)

    if post is None or post.user_id != current_user.id:
        flash('記事が見つからないか、削除権限がありません。', 'danger')
        return redirect(url_for('index'))
    
    # Cloudinary画像の削除
    if post.public_id:
        try:
            destroy(post.public_id)
            flash('Cloudinaryの画像も正常に削除されました。', 'info')
        except Exception as e:
            flash('Cloudinary画像の削除に失敗しました。手動で削除する必要があるかもしれません。', 'warning')
            app.logger.error(f"Cloudinary Delete Error: {e}")

    # 記事の削除
    try:
        db.session.delete(post)
        db.session.commit()
        flash('記事が正常に削除されました。', 'success')
        return redirect(url_for('index'))
    except exc.SQLAlchemyError as e:
        db.session.rollback()
        flash('記事の削除中にデータベースエラーが発生しました。', 'danger')
        app.logger.error(f"Post Delete DB Error: {e}")

# --- 管理画面 ---

@app.route('/admin')
@login_required
def admin():
    """ログインユーザーの記事一覧を表示する管理画面"""
    # ダミー記事データを作成
    class DummyPost:
        def __init__(self, id, title, create_at):
            self.id = id
            self.title = title
            self.create_at = create_at
    
    # 記事が存在しない場合に備えてダミーリストを用意
    try:
        posts = Post.query.filter_by(user_id=current_user.id).order_by(Post.create_at.desc()).all()
        if not posts:
            posts = [
                DummyPost(3, "デモ記事３ (編集可能)", datetime.datetime.now() - datetime.timedelta(hours=2)),
                DummyPost(4, "デモ記事４ (編集可能)", datetime.datetime.now() - datetime.timedelta(hours=1))
            ]
    except exc.SQLAlchemyError:
        posts = [DummyPost(5, "データベースエラー(デモ)", datetime.datetime.now())]

    return render_template('admin.html', posts=posts)


# --- エラーハンドラ ---

# 404エラーハンドラ
@app.errorhandler(404)
def page_not_found(error):
    """404 Not Found ページ"""
    return render_template('404.html'), 404

# 500エラーハンドラ (error_page.htmlに対応)
@app.errorhandler(500)
def internal_server_error(error):
    """500 Internal Server Error ページ"""
    return render_template('error_page.html', error_code=500, message="サーバーで予期せぬエラーが発生しました。"), 500

# カスタムエラーページ（error_page.htmlにマップ）
@app.route('/error_page_test')
def error_page_test():
    """エラーページ（error_page.html）の表示確認用ルート"""
    return render_template('error_page.html', error_code=503, message="サービスが一時的に利用できません。"), 503

# --- 実行ブロック ---
if __name__ == '__main__':
    app.run(debug=True)
