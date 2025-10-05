import os
from datetime import datetime
import time # For exponential backoff
import logging
from flask import Flask, render_template, redirect, url_for, request, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

# --- 1. App Configuration ---
# Set up logging for better debugging in the console
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask App
app = Flask(__name__)

# Load configuration from environment variables
# IMPORTANT: Render typically uses the environment variable 'DATABASE_URL' for PostgreSQL.
# For local testing, you might use 'sqlite:///myblog.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 
    'sqlite:///myblog.db'
).replace('postgres://', 'postgresql://') # SQLAlchemy requires 'postgresql://' prefix

# SECRET_KEY is mandatory for session security and flashing messages
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_fallback_secret_key_12345')

# Suppress the deprecation warning, though setting it to False is now the default behavior
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'このページにアクセスするにはログインしてください。' # Login required message

# Token Serializer for password reset links (valid for 1800 seconds = 30 minutes)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'], serializer_timeout=1800)

# --- 2. Database Models ---

class User(UserMixin, db.Model):
    """ユーザーモデル: ユーザー認証情報を保存します。"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    
    # リレーションシップ: このユーザーが作成したすべての記事
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    def set_password(self, password):
        """パスワードをハッシュ化して保存します。"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """入力されたパスワードと保存されたハッシュを比較します。"""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Post(db.Model):
    """記事モデル: ブログ記事の情報を保存します。"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    create_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    
    # 外部キー: どのユーザーがこの記事を作成したか
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Post {self.title}>'

# --- 3. Flask-Login Configuration ---

@login_manager.user_loader
def load_user(user_id):
    """ユーザーIDに基づいてユーザーオブジェクトをロードします。"""
    return User.query.get(int(user_id))

# --- 4. Database Initialization Route ---

@app.route('/db_init')
def db_init():
    """
    データベースとテーブルを初期化するためのルート。
    デプロイ後の初回アクセス時に実行する必要があります。
    """
    max_retries = 5
    for attempt in range(max_retries):
        try:
            db.drop_all() # 既存のテーブルがあれば削除
            db.create_all() # 新しいテーブルを作成
            logger.info("Database connection successful. Tables (Post and User) created successfully!")
            return "Database connection successful. Tables (Post and User) created successfully! Please proceed to <a href='/signup'>/signup</a> to register the first user."
        except Exception as e:
            logger.error(f"Database initialization failed (Attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                # Exponential backoff: 1s, 2s, 4s, 8s...
                wait_time = 2 ** attempt
                logger.info(f"Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                return f"Database initialization failed after {max_retries} attempts: {e}", 500
    return "Initialization failed unexpectedly.", 500


# --- 5. Error Handlers ---
def error_response(error_code, title, message):
    """カスタムエラーページをレンダリングします。"""
    # ログにエラー情報を記録
    logger.error(f"Error {error_code}: {title} - {message}")
    # error_page.htmlをレンダリング
    return render_template('error_page.html', title=title, message=message), error_code

@app.errorhandler(403)
def forbidden(error):
    return error_response(403, '403 アクセス禁止', 'このリソースへのアクセス権がありません。')

@app.errorhandler(404)
def not_found(error):
    return error_response(404, '404 ページが見つかりません', 'お探しのURLは存在しないか、移動された可能性があります。')

@app.errorhandler(500)
def internal_server_error(error):
    # 500エラーはセキュリティ上の理由で詳細なメッセージを表示しない
    return error_response(500, '500 サーバーエラー', 'サーバー側で予期せぬエラーが発生しました。時間を置いて再度お試しください。')

# --- 6. Authentication Routes ---

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
            
        user = User.query.filter_by(username=username).first()
        if user:
            flash('そのユーザー名は既に使用されています。別の名前をお試しください。', 'warning')
            return render_template('signup.html')

        new_user = User(username=username)
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('ユーザー登録が完了しました！ログインしてください。', 'success')
            return redirect(url_for('login'))
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
        remember = True # 常にセッションを維持

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # ログイン成功
            login_user(user, remember=remember)
            flash(f'ようこそ、{user.username} さん！', 'success')
            
            # ログイン前のページにリダイレクト。なければ/adminへ。
            next_page = request.args.get('next')
            return redirect(next_page or url_for('admin'))
        else:
            # ログイン失敗
            flash('ユーザー名またはパスワードが正しくありません。', 'danger')

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
    if current_user.is_authenticated:
        return redirect(url_for('admin'))

    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        
        # ユーザーが存在するかに関わらず、セキュリティのために一律のメッセージを表示
        if user:
            # ユーザーIDをトークンとしてシリアライズ
            token = s.dumps(user.id, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # 本番環境ではメールで送信しますが、ここではデモとしてフラッシュメッセージに表示
            flash(f'パスワードリセットリンクが生成されました（有効期限30分）。デモのため、以下に表示します: <a href="{reset_url}" class="underline font-bold">リセットリンク</a>', 'info')
            logger.info(f"Password reset link generated for {username}: {reset_url}")
        else:
             # ユーザーが存在しなくても成功メッセージを返し、ユーザー名の存在を推測させない
            flash('ユーザー名が登録されていれば、リセットリンクが生成されました。', 'info')

        return render_template('forgot_password.html')

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """パスワードリセット実行処理。"""
    try:
        # トークンをデシリアライズし、ユーザーIDを取得
        user_id = s.loads(token, salt='password-reset-salt', max_age=1800) # 30分有効
    except SignatureExpired:
        flash('パスワードリセットリンクの有効期限が切れました。再度リクエストしてください。', 'danger')
        return redirect(url_for('forgot_password'))
    except BadTimeSignature:
        flash('無効なリセットリンクです。', 'danger')
        return redirect(url_for('forgot_password'))
        
    user = User.query.get(user_id)
    if not user:
        flash('無効なユーザー情報です。', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('パスワードと確認用パスワードが一致しません。', 'danger')
            return render_template('reset_password.html', token=token)

        if len(password) < 6:
             flash('パスワードは6文字以上である必要があります。', 'danger')
             return render_template('reset_password.html', token=token)
             
        # パスワードを更新
        user.set_password(password)
        db.session.commit()
        
        flash('パスワードが正常にリセットされました。新しいパスワードでログインしてください。', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    """アカウント設定の変更処理。"""
    user = current_user
    
    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('new_password')
        current_password = request.form.get('current_password')

        # 1. 現在のパスワードを確認
        if not user.check_password(current_password):
            flash('現在のパスワードが正しくありません。変更は適用されませんでした。', 'danger')
            return redirect(url_for('account'))

        # 2. ユーザー名の変更
        if new_username and new_username != user.username:
            if User.query.filter_by(username=new_username).first():
                flash('そのユーザー名は既に使用されています。', 'warning')
                return redirect(url_for('account'))
            
            user.username = new_username
            flash(f'ユーザー名が「{new_username}」に変更されました。', 'success')

        # 3. パスワードの変更
        if new_password:
            if len(new_password) < 6:
                flash('新しいパスワードは6文字以上である必要があります。', 'danger')
                return redirect(url_for('account'))
            user.set_password(new_password)
            flash('パスワードが正常に更新されました。', 'success')

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Account update error: {e}")
            flash('データベースエラーにより更新に失敗しました。', 'danger')

        return redirect(url_for('account'))

    return render_template('account.html', user=user)


# --- 7. Blog Routes (CRUD) ---

@app.route('/')
def index():
    """すべての記事を表示するトップページ。"""
    # 記事を新しい順に取得
    posts = Post.query.order_by(Post.create_at.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/admin')
@login_required
def admin():
    """ログインユーザーの記事管理画面。"""
    # 現在のユーザーが作成した記事のみを新しい順に取得
    posts = Post.query.filter_by(user_id=current_user.id).order_by(Post.create_at.desc()).all()
    return render_template('admin.html', posts=posts)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """新規記事の作成。"""
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')

        if not title or not content:
            flash('タイトルと本文は必須です。', 'danger')
            return render_template('create.html')

        new_post = Post(title=title, content=content, user_id=current_user.id)
        
        try:
            db.session.add(new_post)
            db.session.commit()
            flash('新しい記事が正常に投稿されました。', 'success')
            return redirect(url_for('admin'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Post creation error: {e}")
            flash('記事の投稿中にエラーが発生しました。', 'danger')
            return render_template('create.html')

    return render_template('create.html')

@app.route('/view/<int:post_id>')
def view(post_id):
    """記事の詳細表示。"""
    post = Post.query.get_or_404(post_id)
    return render_template('view.html', post=post)

@app.route('/update/<int:post_id>', methods=['GET', 'POST'])
@login_required
def update(post_id):
    """記事の更新。"""
    post = Post.query.get_or_404(post_id)

    # 記事の作者と現在のユーザーが一致するか確認
    if post.author != current_user:
        flash('あなたはこの記事を編集する権限がありません。', 'danger')
        return redirect(url_for('view', post_id=post.id))

    if request.method == 'POST':
        post.title = request.form.get('title')
        post.content = request.form.get('content')
        
        if not post.title or not post.content:
            flash('タイトルと本文は必須です。', 'danger')
            return render_template('update.html', post=post)

        try:
            db.session.commit()
            flash('記事が正常に更新されました。', 'success')
            return redirect(url_for('view', post_id=post.id))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Post update error: {e}")
            flash('記事の更新中にエラーが発生しました。', 'danger')
            return render_template('update.html', post=post)

    return render_template('update.html', post=post)

@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required
def delete(post_id):
    """記事の削除。"""
    post = Post.query.get_or_404(post_id)
    
    # 記事の作者と現在のユーザーが一致するか確認
    if post.author != current_user:
        flash('あなたはこの記事を削除する権限がありません。', 'danger')
        return redirect(url_for('admin'))

    try:
        db.session.delete(post)
        db.session.commit()
        flash('記事が正常に削除されました。', 'success')
        return redirect(url_for('admin'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Post deletion error: {e}")
        flash('記事の削除中にエラーが発生しました。', 'danger')
        return redirect(url_for('admin'))

# --- 8. Run App (for local development) ---

if __name__ == '__main__':
    # Flaskアプリを直接実行するための設定（RenderではGunicornなどのWSGIサーバーが実行します）
    # ローカルでテストする場合は以下のコメントアウトを解除
    # with app.app_context():
    #     # データベースの初期化をローカルで自動的に試みる
    #     try:
    #         db.create_all()
    #         logger.info("Local database initialized or already exists.")
    #     except Exception as e:
    #         logger.error(f"Local database creation failed: {e}")
    # app.run(debug=True)
    
    # Renderで動作させるためにポートとホストを環境変数から取得
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False) # デバッグモードはRenderではFalseに設定
