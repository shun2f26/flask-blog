import os
import sys
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf.csrf import CSRFProtect 
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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'my_default_secret_key') 

# Heroku / Render 互換性のためのURL修正ロジック
uri = os.environ.get('DATABASE_URL')
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = uri if uri else 'sqlite:///myblog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

# --- SQLAlchemy/Migrate / WTF の遅延初期化 (Lazy Init) ---
db = SQLAlchemy() 
bcrypt = Bcrypt()
login_manager = LoginManager()
migrate = Migrate() 
csrf = CSRFProtect() 

db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)
csrf.init_app(app) 

# Migrateの初期化は意図的に省略

login_manager.login_view = 'login'
login_manager.login_message = 'このページにアクセスするにはログインが必要です。'
login_manager.login_message_category = 'info'


# 💡 修正箇所: Renderの起動時クラッシュ回避のため、強制的なdb.create_all()の呼び出しを削除します。
# -------------------------------------------------------------------
# Render Free Tier 対策: アプリ起動時にテーブル作成を試みる
# -------------------------------------------------------------------
# 削除しました。代わりに、初回のアクセス時にテーブルを作成するロジックを実装します。
# -------------------------------------------------------------------


# -------------------------------------------------------------------
# 初回リクエスト時にデータベース初期化を試みる
# -------------------------------------------------------------------
@app.before_request
def create_tables():
    """最初のHTTPリクエストが来る前にデータベーステーブルが存在することを確認する"""
    if not hasattr(app, 'tables_created'):
        try:
            # データベース接続が確立されていればテーブルを作成（既に存在しても安全）
            db.create_all()
            app.tables_created = True
            # print("Database tables ensured to be created on first request.", file=sys.stderr)
        except Exception as e:
            # Renderの起動直後のDB接続失敗を許容し、クラッシュを防ぐ
            print(f"Delayed db.create_all() error: {e}", file=sys.stderr)
            pass
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
    password_hash = db.Column(db.String(256))
    posts = relationship('Post', backref='author', lazy='dynamic')
    
    # パスワードリセットトークン用
    reset_token = db.Column(db.String(256), nullable=True) 
    reset_token_expires = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        """パスワードをハッシュ化して保存する"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """入力されたパスワードとハッシュを比較する"""
        return bcrypt.check_password_hash(self.password_hash, password)

class Post(db.Model):
    """記事モデル"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    public_id = db.Column(db.String(100), nullable=True) 
    create_at = db.Column(db.DateTime, nullable=False, default=now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- ユーザーローダー ---

@login_manager.user_loader
def load_user(user_id):
    """Flask-LoginがセッションからユーザーIDをロードするためのコールバック"""
    return db.session.get(User, int(user_id))

# --- ルーティング ---

@app.route("/db_reset", methods=["GET", "POST"])
def db_reset():
    # 🚨 修正ポイント: 本番環境でのガードを有効化
    # 環境変数が設定されていない（ローカル）か、開発環境でのみ実行を許可
    if os.environ.get('FLASK_ENV') == 'production' or os.environ.get('SECRET_KEY') == 'my_default_secret_key_needs_a_random_value':
        flash("データベースリセットは本番環境では許可されていません。", 'danger')
        return redirect(url_for('index')) # ホームに戻す

    # 警告: 全てのテーブルを強制削除し、再作成します。PostgreSQLでは不可逆な操作です。
    if request.method == 'POST':
        # ... (POSTメソッド内のリセット処理は変更なし) ...
        try:
            # データベース接続がPostgreSQLの場合
            if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgresql'):
                # ユーザーテーブルとポストテーブルを削除 (CASCADEで関連データも削除)
                # 実行前にセッションを閉じる必要がある場合があります
                db.session.close()
                db.engine.execute("DROP TABLE IF EXISTS post CASCADE;")
                db.engine.execute("DROP TABLE IF EXISTS user CASCADE;")
                
                # テーブル再作成
                db.create_all()
                db.session.commit()
                flash("PostgreSQLのテーブルが正常に削除・再作成されました。サインアップをお試しください。", 'success')
                return redirect(url_for('index'))
            
            # データベース接続がSQLiteの場合
            elif app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
                # SQLiteでは単純にドロップと再作成
                db.drop_all()
                db.create_all()
                db.session.commit()
                flash("SQLiteのテーブルが正常に削除・再作成されました。サインアップをお試しください。", 'success')
                return redirect(url_for('index'))
            
            else:
                flash("サポートされていないデータベースです。", 'danger')
                return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            flash(f"データベースリセット中にエラーが発生しました: {e}", 'danger')
            return redirect(url_for('index'))

    # リセット確認画面の表示
    return render_template("db_reset_confirm.html")
    else:
        # 本番環境ではリセットをブロック
        return "データベースリセットは本番環境では許可されていません。", 403


@app.route('/')
def index():
    """ブログ記事一覧ページ"""
    posts = db.session.execute(db.select(Post).order_by(Post.create_at.desc())).scalars().all()
    return render_template('index.html', posts=posts)

# 記事詳細
@app.route('/post/<int:post_id>')
def view(post_id):
    """記事詳細ページ"""
    post = db.session.get(Post, post_id)
    if not post:
        return render_template('404.html', title="404 記事が見つかりません"), 404
    
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
                upload_result = cloudinary.uploader.upload(image_file, 
                                                          folder="flask_blog_images", 
                                                          overwrite=True)
                public_id = upload_result.get('public_id')
                flash('画像が正常にアップロードされました。', 'success')
            except Exception as e:
                flash(f'画像のアップロード中にエラーが発生しました: {e}', 'danger')

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
        delete_image = request.form.get('delete_image') 

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
        except Exception as e:
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
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
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
        
        existing_user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
        
        if existing_user:
            flash('このユーザー名は既に使われています。', 'danger')
        elif len(username) < 3:
            flash('ユーザー名は3文字以上で入力してください。', 'danger')
        elif len(password) < 6:
            flash('パスワードは6文字以上で入力してください。', 'danger')
        else:
            new_user = User(username=username)
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            
            flash('登録が完了しました。ログインしてください。', 'success')
            # ログインページにリダイレクト
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

        if not user.check_password(current_password):
            flash('現在のパスワードが正しくありません。', 'danger')
            return redirect(url_for('account'))

        has_changes = False

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

# パスワードリセット要求
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """パスワードリセット要求ページ"""
    if request.method == 'POST':
        username = request.form.get('username')
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
        
        flash('パスワードリセット用のリンクが送信されました。', 'info')
        
        if user:
            token = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
            user.reset_token = token
            user.reset_token_expires = now() + timedelta(minutes=30)
            db.session.commit()
            
            # 開発環境向けのコンソール出力
            print(f"--- DUMMY PASSWORD RESET LINK ---", file=sys.stderr)
            print(f"User: {user.username}", file=sys.stderr)
            reset_url = url_for('reset_password', token=token, _external=True)
            print(f"Link: {reset_url}", file=sys.stderr)
            print(f"-----------------------------------", file=sys.stderr)

    return render_template('forgot_password.html')

# パスワードリセット実行
@app.route('/reset_password/<path:token>', methods=['GET', 'POST']) 
def reset_password(token):
    """新しいパスワード設定ページ"""
    user = db.session.execute(db.select(User).filter_by(reset_token=token)).scalar_one_or_none()

    if not user or user.reset_token_expires < now():
        flash('無効なトークン、または期限切れです。再度リセットを要求してください。', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('password_confirm') 

        if password != confirm_password:
            flash('パスワードが一致しません。', 'danger')
        elif len(password) < 6:
            flash('パスワードは6文字以上で入力してください。', 'danger')
        else:
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
    return render_template('404.html'), 404

if __name__ == '__main__':
    # ローカル開発環境でのみ実行
    app.run(debug=True)
