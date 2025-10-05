import os
from datetime import datetime
import time 
import logging
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from sqlalchemy.exc import OperationalError, ProgrammingError 

# --- Cloudinary Imports & Setup ---
import cloudinary
import cloudinary.uploader
import cloudinary.api

# --- 1. App Configuration ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask App
app = Flask(__name__)

# Load configuration from environment variables
# DATABASE_URLのpostgres://をpostgresql://に置換し、sslmode=requireを追加
db_url = os.environ.get('DATABASE_URL', 'sqlite:///myblog.db')
if db_url.startswith('postgres://'):
    db_url = db_url.replace('postgres://', 'postgresql://', 1)

if db_url.startswith('postgresql://'):
    if '?' not in db_url:
        db_url += '?sslmode=require'
    elif 'sslmode' not in db_url:
        db_url += '&sslmode=require'

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_fallback_secret_key_12345')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Cloudinary Configuration
cloudinary.config(
    cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME'),
    api_key = os.environ.get('CLOUDINARY_API_KEY'),
    api_secret = os.environ.get('CLOUDINARY_API_SECRET'),
    secure = True
)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'このページにアクセスするにはログインしてください。' 

# Token Serializer (有効期限30分)
s = URLSafeTimedSerializer(app.config['SECRET_KEY']) 

# --- 2. Database Models ---

class User(UserMixin, db.Model):
    """ユーザーモデル: ユーザー認証情報を保存します。"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # ハッシュ衝突を避けるため、パスワードハッシュの長さを256に拡張
    password_hash = db.Column(db.String(256), nullable=False)
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    def set_password(self, password):
        # デフォルトで安全なアルゴリズム (Bcryptなど) を使用
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Post(db.Model):
    """記事モデル: ブログ記事の情報を保存します。"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    create_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    
    # Cloudinary Public ID を保存するフィールド
    public_id = db.Column(db.String(255), nullable=True) 
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Post {self.title}>'

# --- 3. Flask-Login Configuration ---

@login_manager.user_loader
def load_user(user_id):
    """ユーザーIDに基づいてユーザーオブジェクトをロードします。"""
    return User.query.get(int(user_id))

# --- 4. Cloudinary Helper Functions ---

def upload_image_to_cloudinary(file, folder="flask_blog_images"):
    """ファイルをCloudinaryにアップロードし、public_idを返します。"""
    # ファイルオブジェクトが空でないか、またはファイル名が存在するか確認
    if not file or file.filename == '':
        return None

    try:
        # アップロード先のフォルダを指定
        upload_result = cloudinary.uploader.upload(file, folder=folder)
        return upload_result.get('public_id')
    except Exception as e:
        logger.error(f"Cloudinary upload failed: {e}")
        return None

def delete_image_from_cloudinary(public_id):
    """Cloudinaryから画像を削除します。"""
    if not public_id:
        return True # 削除する画像がないため成功とみなす
        
    try:
        # 削除を実行
        cloudinary.uploader.destroy(public_id)
        return True
    except Exception as e:
        logger.error(f"Cloudinary deletion failed for {public_id}: {e}")
        return False

# --- 5. Application Context Processor ---

@app.context_processor
def inject_globals():
    """テンプレートで現在時刻やCloudinaryヘルパーを利用可能にする。"""
    return {
        'now': datetime.utcnow, 
        'cloudinary': cloudinary # Cloudinaryユーティリティをテンプレートに渡す
    }

# --- 6. Database Initialization and Health Check ---

def check_db_health():
    """データベース接続とテーブル存在チェックを試みる"""
    try:
        db.session.execute(db.select(User).limit(1)).scalar_one_or_none()
        return True
    except OperationalError as e:
        logger.error(f"Database Operational Error: Connection failed. {e}")
        return False
    except ProgrammingError as e:
        logger.warning(f"Database Programming Error: Tables not found. Initialization required. {e}")
        return False
    except Exception as e:
        logger.error(f"Unknown Database Error: {e}")
        return False

@app.route('/db_init')
def db_init():
    """データベースとテーブルを初期化するためのルート (指数バックオフでリトライ)。"""
    max_retries = 5
    for attempt in range(max_retries):
        try:
            db.drop_all()
            db.create_all()
            logger.info("Database connection successful. Tables created successfully!")
            return "データベース接続が成功し、テーブルが初期化されました。次に <a href='/signup'>/signup</a> からユーザー登録を行ってください。", 200
        except OperationalError as e:
            logger.error(f"Database initialization failed (Attempt {attempt + 1}/{max_retries}): Connection refused or timeout. {e}")
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                logger.info(f"Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                return f"データベース初期化に失敗しました。データベースURLと接続設定を確認してください: {e}", 500
        except Exception as e:
            logger.error(f"予期せぬエラーにより初期化に失敗しました: {e}")
            return f"予期せぬエラーにより初期化に失敗しました: {e}", 500
    return "Initialization failed unexpectedly.", 500

# --- 7. Error Handlers ---

def error_response(error_code, title, message):
    """カスタムエラーページをレンダリングします。"""
    logger.error(f"Error {error_code}: {title} - {message}")
    # 404.html を簡易エラーテンプレートとして使用
    return render_template('404.html'), error_code 

@app.errorhandler(403)
def forbidden(error):
    return error_response(403, '403 アクセス禁止', 'このリソースへのアクセス権がありません。')

@app.errorhandler(404)
def not_found(error):
    return error_response(404, '404 ページが見つかりません', 'お探しのURLは存在しないか、移動された可能性があります。')

@app.errorhandler(500)
def internal_server_error(error):
    # データベース未接続の場合を特別に扱う
    if not check_db_health():
        return f"""
        <!doctype html>
        <title>500 データベース接続エラー</title>
        <style>
          body {{ font-family: sans-serif; text-align: center; padding: 20px; }}
          h1 {{ color: #dc3545; }}
          p {{ font-size: 1.2em; }}
          a {{ color: #007bff; text-decoration: none; font-weight: bold; }}
        </style>
        <h1>500 データベース接続エラー</h1>
        <p>データベースサーバーに接続できません。サービスの起動後、必ず 
        <a href="/db_init">/db_init</a> を実行し、データベースを初期化してください。</p>
        <p>Gunicornのタイムアウト設定が適用されていることを確認してください。</p>
        """, 500
        
    return error_response(500, '500 サーバーエラー', f'サーバー側で予期せぬエラーが発生しました。詳細: {error}')

# --- 8. Authentication Routes ---

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """サインアップ (ユーザー登録) 処理を行います。"""
    if current_user.is_authenticated:
        flash('すでにログインしています。', 'info')
        return redirect(url_for('admin'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('ユーザー名とパスワードは必須です。', 'danger')
            return render_template('signup.html')
            
        try:
            user = User.query.filter_by(username=username).first()
            if user:
                flash('そのユーザー名は既に使用されています。別の名前をお試しください。', 'warning')
                return render_template('signup.html')

            new_user = User(username=username)
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            flash('ユーザー登録が完了しました！ログインしてください。', 'success')
            return redirect(url_for('login'))
        except (OperationalError, ProgrammingError):
            db.session.rollback()
            flash('データベースエラーにより登録に失敗しました。**`/db_init`を実行してください**。', 'danger')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Signup error: {e}")
            flash('データベースエラーにより登録に失敗しました。', 'danger')

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """ログイン処理を行います。"""
    if current_user.is_authenticated:
        flash('すでにログインしています。', 'info')
        return redirect(url_for('admin'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True 

        try:
            user = User.query.filter_by(username=username).first()

            if user and user.check_password(password):
                login_user(user, remember=remember)
                flash(f'ようこそ、{user.username} さん！', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('admin'))
            else:
                flash('ユーザー名またはパスワードが正しくありません。', 'danger')
        except (OperationalError, ProgrammingError):
             flash('データベース接続エラー: **`/db_init`を実行してください**。', 'danger')
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('ログイン中に予期せぬエラーが発生しました。', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """ログアウト処理を行います。"""
    logout_user()
    flash('ログアウトしました。', 'success')
    return redirect(url_for('index'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """パスワードリセットトークン生成のダミー処理。"""
    # テンプレートは reset_password_dummy.html に依存
    if current_user.is_authenticated:
        return redirect(url_for('admin'))

    if request.method == 'POST':
        username = request.form.get('username')
        try:
            user = User.query.filter_by(username=username).first()
            if user:
                token = s.dumps(user.id, salt='password-reset-salt')
                reset_url = url_for('reset_password', token=token, _external=True)
                flash(f'パスワードリセットリンクが生成されました（有効期限30分）。デモのため、以下に表示します: <a href="{reset_url}" class="underline font-bold">リセットリンク</a>', 'info')
                logger.info(f"Password reset link generated for {username}: {reset_url}")
            else:
                flash('ユーザー名が登録されていれば、リセットリンクが生成されました。', 'info')
        except (OperationalError, ProgrammingError):
             flash('データベース接続エラー: **`/db_init`を実行してください**。', 'danger')
        except Exception as e:
            logger.error(f"Forgot password error: {e}")
            flash('処理中に予期せぬエラーが発生しました。', 'danger')
            
        return render_template('forgot_password.html')

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """パスワードリセット実行処理。"""
    try:
        # トークンの有効期限をチェック (1800秒 = 30分)
        user_id = s.loads(token, salt='password-reset-salt', max_age=1800) 
    except SignatureExpired:
        flash('パスワードリセットリンクの有効期限が切れました。再度リクエストしてください。', 'danger')
        return redirect(url_for('forgot_password'))
    except BadTimeSignature:
        flash('無効なリセットリンクです。', 'danger')
        return redirect(url_for('forgot_password'))
        
    try:
        user = User.query.get(user_id)
    except (OperationalError, ProgrammingError):
        flash('データベース接続エラー: **`/db_init`を実行してください**。', 'danger')
        return redirect(url_for('forgot_password'))
        
    if not user:
        flash('無効なユーザー情報です。', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('パスワードと確認用パスワードが一致しません。', 'danger')
            return render_template('reset_password_dummy.html', token=token)
             
        if len(password) < 6:
             flash('パスワードは6文字以上である必要があります。', 'danger')
             return render_template('reset_password_dummy.html', token=token)
             
        try:
            user.set_password(password)
            db.session.commit()
            flash('パスワードが正常にリセットされました。新しいパスワードでログインしてください。', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Password reset commit error: {e}")
            flash('パスワード更新中にエラーが発生しました。', 'danger')

    return render_template('reset_password_dummy.html', token=token)

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    """アカウント設定の変更処理。"""
    user = current_user
    
    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('new_password')
        current_password = request.form.get('current_password')

        if not user.check_password(current_password):
            flash('現在のパスワードが正しくありません。変更は適用されませんでした。', 'danger')
            return redirect(url_for('account'))

        try:
            # ユーザー名の変更
            if new_username and new_username != user.username:
                if User.query.filter_by(username=new_username).first():
                    flash('そのユーザー名は既に使用されています。', 'warning')
                    return redirect(url_for('account'))
                
                user.username = new_username
                flash(f'ユーザー名が「{new_username}」に変更されました。', 'success')

            # パスワードの変更
            if new_password:
                if len(new_password) < 6:
                    flash('新しいパスワードは6文字以上である必要があります。', 'danger')
                    return redirect(url_for('account'))
                user.set_password(new_password)
                flash('パスワードが正常に更新されました。', 'success')

            db.session.commit()
        except (OperationalError, ProgrammingError):
             db.session.rollback()
             flash('データベース接続エラー: **`/db_init`を実行してください**。', 'danger')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Account update error: {e}")
            flash('データベースエラーにより更新に失敗しました。', 'danger')

        return redirect(url_for('account'))

    return render_template('account.html', user=user)


# --- 9. Blog Routes (CRUD with Cloudinary) ---

@app.route('/')
def index():
    """すべての記事を表示するトップページ。"""
    try:
        posts = Post.query.order_by(Post.create_at.desc()).all()
        return render_template('index.html', posts=posts)
    except (OperationalError, ProgrammingError):
        return error_response(500, 'データベースエラー', 'データベース接続またはテーブルの初期化が必要です。**<a href="/db_init">/db_init</a>** を実行してください。')
    except Exception as e:
        logger.error(f"Index route error: {e}")
        return internal_server_error(e)


@app.route('/admin')
@login_required
def admin():
    """ログインユーザーの記事管理画面。"""
    try:
        posts = Post.query.filter_by(user_id=current_user.id).order_by(Post.create_at.desc()).all()
        return render_template('admin.html', posts=posts)
    except (OperationalError, ProgrammingError):
        return error_response(500, 'データベースエラー', 'データベース接続またはテーブルの初期化が必要です。**<a href="/db_init">/db_init</a>** を実行してください。')
    except Exception as e:
        logger.error(f"Admin route error: {e}")
        return internal_server_error(e)


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """新規記事の作成。画像アップロード対応。"""
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        # ファイルオブジェクトを取得
        image_file = request.files.get('image_file') 

        if not title or not content:
            flash('タイトルと本文は必須です。', 'danger')
            return render_template('create.html')

        public_id = None
        # 画像ファイルが選択され、ファイル名が存在する場合のみアップロードを試みる
        if image_file and image_file.filename != '':
             public_id = upload_image_to_cloudinary(image_file)
             if not public_id:
                 # アップロード失敗時
                 flash('画像のアップロードに失敗しました。画像なしで記事を投稿します。', 'warning')
        
        new_post = Post(title=title, content=content, user_id=current_user.id, public_id=public_id)
        
        try:
            db.session.add(new_post)
            db.session.commit()
            flash('新しい記事が正常に投稿されました。', 'success')
            return redirect(url_for('admin'))
        except (OperationalError, ProgrammingError):
            db.session.rollback()
            flash('データベースエラーにより投稿に失敗しました。**`/db_init`を実行してください**。', 'danger')
            return render_template('create.html')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Post creation error: {e}")
            flash('記事の投稿中に予期せぬエラーが発生しました。', 'danger')
            return render_template('create.html')

    return render_template('create.html')

@app.route('/view/<int:post_id>')
def view(post_id):
    """記事の詳細表示。"""
    try:
        # postオブジェクトには public_id が含まれる
        post = Post.query.get_or_404(post_id)
        return render_template('view.html', post=post)
    except (OperationalError, ProgrammingError):
        return error_response(500, 'データベースエラー', 'データベース接続またはテーブルの初期化が必要です。**<a href="/db_init">/db_init</a>** を実行してください。')
    except Exception as e:
        logger.error(f"View route error: {e}")
        return internal_server_error(e)


@app.route('/update/<int:post_id>', methods=['GET', 'POST'])
@login_required
def update(post_id):
    """記事の更新。画像更新・削除対応。"""
    try:
        post = Post.query.get_or_404(post_id)
    except (OperationalError, ProgrammingError):
        return error_response(500, 'データベースエラー', 'データベース接続またはテーブルの初期化が必要です。**<a href="/db_init">/db_init</a>** を実行してください。')
    except Exception as e:
        logger.error(f"Update retrieve error: {e}")
        return internal_server_error(e)

    if post.author != current_user:
        flash('あなたはこの記事を編集する権限がありません。', 'danger')
        return redirect(url_for('view', post_id=post.id))

    if request.method == 'POST':
        post.title = request.form.get('title')
        post.content = request.form.get('content')
        image_file = request.files.get('image_file')
        delete_image_flag = request.form.get('delete_image') # チェックボックスの値

        if not post.title or not post.content:
            flash('タイトルと本文は必須です。', 'danger')
            return render_template('update.html', post=post)

        # 1. 既存の画像の削除を要求された場合 (チェックボックスがON)
        if delete_image_flag == 'on':
            if post.public_id:
                delete_image_from_cloudinary(post.public_id)
                post.public_id = None
                flash('既存の画像を削除しました。', 'info')
        
        # 2. 新しい画像がアップロードされた場合
        if image_file and image_file.filename != '':
            # 既存の画像があれば、先に削除 (新しい画像で置き換えるため)
            if post.public_id:
                delete_image_from_cloudinary(post.public_id)
            
            new_public_id = upload_image_to_cloudinary(image_file)
            if new_public_id:
                post.public_id = new_public_id
                flash('新しい画像をアップロードし、置き換えました。', 'success')
            else:
                 flash('新しい画像のアップロードに失敗しました。', 'warning')
                 # post.public_id は変更しない (既存の画像が削除されていればNoneのまま)

        try:
            db.session.commit()
            flash('記事が正常に更新されました。', 'success')
            return redirect(url_for('view', post_id=post.id))
        except (OperationalError, ProgrammingError):
            db.session.rollback()
            flash('データベースエラーにより更新に失敗しました。**`/db_init`を実行してください**。', 'danger')
            return render_template('update.html', post=post)
        except Exception as e:
            db.session.rollback()
            logger.error(f"Post update commit error: {e}")
            flash('記事の更新中に予期せぬエラーが発生しました。', 'danger')
            return render_template('update.html', post=post)

    return render_template('update.html', post=post)

@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required
def delete(post_id):
    """記事の削除。Cloudinaryの画像も同時に削除。"""
    try:
        post = Post.query.get_or_404(post_id)
    except (OperationalError, ProgrammingError):
        flash('データベース接続エラー: **`/db_init`を実行してください**。', 'danger')
        return redirect(url_for('admin'))
    
    if post.author != current_user:
        flash('あなたはこの記事を削除する権限がありません。', 'danger')
        return redirect(url_for('admin'))

    try:
        # Cloudinaryから画像を削除
        if post.public_id:
            delete_image_from_cloudinary(post.public_id)
            
        db.session.delete(post)
        db.session.commit()
        flash('記事が正常に削除されました。', 'success')
        return redirect(url_for('admin'))
    except (OperationalError, ProgrammingError):
        db.session.rollback()
        flash('データベースエラーにより削除に失敗しました。**`/db_init`を実行してください**。', 'danger')
        return redirect(url_for('admin'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Post deletion error: {e}")
        flash('記事の削除中に予期せぬエラーが発生しました。', 'danger')
        return redirect(url_for('admin'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
