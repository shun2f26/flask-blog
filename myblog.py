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

# ★注意: Gunicorn起動時のdb.create_all()は削除しました。

# アップロードが許可される拡張子 
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# --- データベースモデル ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    # PostとUserのリレーションを設定。ユーザー削除時に記事も削除される設定を追加
    posts = db.relationship('Post', backref=db.backref('author', lazy=True), cascade="all, delete-orphan")
    
    def get_reset_token(self, expires_sec=1800): 
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=expires_sec)
        except (SignatureExpired, BadTimeSignature):
            return None
        return db.session.get(User, data['user_id'])


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False) 
    image_file = db.Column(db.String(300), nullable=True) 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    create_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow) 

def upload_image_to_cloudinary(file_data):
    """
    アップロードされたファイルをCloudinaryに送信し、公開URLを返す。
    """
    try:
        # Cloudinary API認証情報が設定されているか確認
        if not (os.environ.get('CLOUDINARY_CLOUD_NAME') and os.environ.get('CLOUDINARY_API_KEY')):
             print("Cloudinary API credentials not set. Skipping upload.", file=sys.stderr)
             return None 
             
        # ファイルの内容を直接Cloudinaryにアップロード
        result = cloudinary.uploader.upload(file_data, folder="flask_blog")
        
        # アップロード成功後、安全なHTTPSの公開URLを取得して返す
        return result.get('secure_url')
    except Exception as e:
        # アップロード失敗時はエラーをコンソールに出力し、Noneを返す
        print(f"Cloudinary Upload Error: {e}", file=sys.stderr)
        return None
    
@login_manager.user_loader 
def load_user(user_id):
    if user_id is None:
        return None
    try:
        user_id_int = int(user_id)
        return db.session.get(User, user_id_int)
    except ValueError:
        print(f"Error: Invalid user_id format received: {user_id}", file=sys.stderr)
        return None

# --- ヘルパー関数 (SQLAlchemy 2.0対応) ---
def get_post_or_404(post_id):
    post = db.session.get(Post, post_id)
    if post is None: abort(404)
    return post

def get_user_by_username(username):
    return db.session.execute(
        db.select(User).filter_by(username=username)
    ).scalar_one_or_none()


# ★db_resetルートは削除しました。データベースの初期化はビルドスクリプトで行います。


@app.route("/")
def index():
    # 記事を取得する際に、まだテーブルが存在しない可能性があるためtry-exceptを追加
    try:
        posts = db.session.execute(
            # Post.create_at で降順ソート
            db.select(Post).order_by(Post.create_at.desc()) 
        ).scalars().all()
    except Exception as e:
        # テーブルがない場合は空のリストを返し、エラーをログに出力
        print(f"Error fetching posts (Table may not exist yet): {e}", file=sys.stderr)
        posts = []
        
    return render_template("index.html", posts=posts)

@app.route("/post/<int:post_id>")
def view(post_id):
    post = get_post_or_404(post_id)
    return render_template("view.html", post=post)

@app.route("/admin")
@login_required
def admin():
    # ログインユーザーの記事のみ取得
    posts = db.session.execute(
        db.select(Post).filter_by(user_id=current_user.id).order_by(Post.create_at.desc())
    ).scalars().all()
    return render_template("admin.html", posts=posts)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        image_file_data = request.files.get('image_file') 
        
        if not title or not content:
            flash('タイトルと本文を入力してください。', 'warning')
            return redirect(url_for('create'))
        
        image_url = None
        if image_file_data and image_file_data.filename != '':
            image_url = upload_image_to_cloudinary(image_file_data)
            
            if not image_url:
                flash('画像のアップロードに失敗しました。', 'error')
                
        new_post = Post(
            title=title, 
            content=content, 
            author=current_user,
            image_file=image_url 
        )
        
        db.session.add(new_post)
        db.session.commit()
        flash('新しい記事を投稿しました。', 'success')
        return redirect(url_for('view', post_id=new_post.id))

    return render_template('create.html')
    
@app.route('/update/<int:post_id>', methods=['GET', 'POST'])
@login_required
def update(post_id):
    post = db.session.get(Post, post_id)
    if post is None or post.author != current_user:
        flash('記事が見つからないか、編集権限がありません。', 'danger')
        return redirect(url_for('admin'))

    if request.method == 'POST':
        post.title = request.form.get('title')
        post.content = request.form.get('content')
        image_file_data = request.files.get('image_file')

        if image_file_data and image_file_data.filename != '':
            image_url = upload_image_to_cloudinary(image_file_data)
            
            if image_url:
                post.image_file = image_url
            else:
                flash('画像の更新に失敗しましたが、記事内容は保存されました。', 'error')
        
        db.session.commit()
        flash('記事を更新しました。', 'success')
        return redirect(url_for('view', post_id=post.id))

    return render_template('update.html', post=post)
    
@app.route('/delete/<int:post_id>', methods=['POST']) 
@login_required
def delete(post_id):
    post = db.session.get(Post, post_id)
    
    if post is None or post.author != current_user:
        flash('記事が見つからないか、削除権限がありません。', 'danger')
        return redirect(url_for('admin'))
    
    db.session.delete(post)
    db.session.commit()
    flash(f'記事「{post.title}」を削除しました。', 'info')
    return redirect(url_for('admin'))

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

        # sha256のエラー回避のため、デフォルトのハッシュ関数を使用
        hashed_pass = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pass)
        
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('登録が完了しました。', 'success')
        return redirect(url_for('admin')) 
        
    return render_template('signup.html')
    
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin')) 

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = get_user_by_username(username)
        
        if user and check_password_hash(user.password, password=password):
            login_user(user)
            flash('ログイン成功！', 'success')
            next_page = request.args.get('next')
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

        if not check_password_hash(user.password, current_password or ''):
            flash('現在のパスワードが間違っています。', 'danger')
            return redirect(url_for('account'))

        is_updated = False
        
        if new_username and new_username != user.username:
            existing_user = get_user_by_username(new_username)
            if existing_user and existing_user.id != user.id:
                flash('そのユーザー名は既に使用されています。', 'warning')
                return redirect(url_for('account'))
            
            user.username = new_username
            is_updated = True

        new_password = request.form.get('new_password')
        if new_password:
            user.password = generate_password_hash(new_password)
            is_updated = True
            
        if is_updated:
            db.session.commit()
            flash('アカウント情報が更新されました。', 'success')
        else:
             flash('更新する情報がありませんでした。', 'info')
            
        return redirect(url_for('account'))

    return render_template('account.html', user=user)

# --- パスワードリセット関連ルート ---

@app.route("/forgot_password", methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username') 
        user = get_user_by_username(username)

        if user:
            token = user.get_reset_token()
            reset_url = url_for('reset_password', token=token, _external=True)
            
            flash(f'パスワードリセットのリンクを送信しました（ダミー）。次のリンクにアクセスしてください（30分有効）：{reset_url}', 'success')
            
            return redirect(url_for('login'))
        else:
            flash('リセット情報が送信されました（ユーザーが存在すれば）。', 'info')
            return redirect(url_for('login'))

    return render_template('forgot_password.html')

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
            return redirect(url_for('reset_password', token=token)) 
            
        user.password = generate_password_hash(password)
        db.session.commit()
        flash('パスワードが正常にリセットされました。新しいパスワードでログインしてください。', 'success')
        return redirect(url_for('login'))

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
