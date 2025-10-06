import os
import sys
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from sqlalchemy.orm import relationship
from sqlalchemy.sql import text
from sqlalchemy_utils import database_exists, create_database
from datetime import datetime, timedelta, timezone
import base64
import requests # requestsは不要ですが、インポートリストに合わせて保持
import json # jsonは不要ですが、インポートリストに合わせて保持
from io import BytesIO # BytesIOは不要ですが、インポートリストに合わせて保持

# Cloudinaryは今回は未使用のためコメントアウト/省略
import cloudinary
import cloudinary.uploader
import cloudinary.utils

from forms import RegistrationForm

# Cloudinaryの設定 (環境変数から取得 - 未設定の場合はエラーにならないよう注意)
# 🚨 警告: 実際のデプロイではCLOUDINARY_*環境変数を設定してください
try:
    cloudinary.config(
        cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'),
        api_key=os.environ.get('CLOUDINARY_API_KEY'),
        api_secret=os.environ.get('CLOUDINARY_API_SECRET'),
        secure=True
    )
except Exception as e:
    print(f"Cloudinary config error (set CLOUDINARY_* env vars): {e}", file=sys.stderr)


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
csrf.init_app(app) # CSRFを有効化

# Migrateの初期化は意図的に省略 (起動時クラッシュ回避のため)

login_manager.login_view = 'login'
login_manager.login_message = 'このページにアクセスするにはログインが必要です。'
login_manager.login_message_category = 'info'


# -------------------------------------------------------------------
# 💡 修正: 初回リクエスト時にデータベース初期化を試みる
# -------------------------------------------------------------------
@app.before_request
def create_tables():
    """
    最初のHTTPリクエストが来る前にデータベーステーブルが存在することを確認する。
    PostgreSQLでテーブルがないエラーを防ぐための措置。
    """
    if not hasattr(app, 'tables_created'):
        try:
            with app.app_context():
                # データベースが存在しない場合は作成（SQLite/PostgreSQL両対応）
                if not database_exists(app.config['SQLALCHEMY_DATABASE_URI']):
                    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite:///'):
                        print("SQLiteデータベースファイルを作成します。", file=sys.stderr)
                    elif app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgresql'):
                        if not os.environ.get('DATABASE_URL'):
                            create_database(app.config['SQLALCHEMY_DATABASE_URI'])

                db.create_all()
                app.tables_created = True
                print("db.create_all()を実行し、テーブル初期化を完了しました。", file=sys.stderr)

        except Exception as e:
            # データベース接続がまだ確立されていない（Render/Herokuの起動初期段階など）可能性を考慮
            print(f"データベースの初期化中にエラーが発生しました: {e}", file=sys.stderr)
            pass
# -------------------------------------------------------------------


# --- タイムゾーン設定 (日本時間) ---
def now():
    """現在の日本時間 (JST) を返すヘルパー関数"""
    return datetime.now(timezone(timedelta(hours=9)))

# --- モデル定義 ---

class User(UserMixin, db.Model):
    """ユーザーモデル"""
    # 💡 修正: PostgreSQLの予約語回避のためテーブル名を明示的に設定
    __tablename__ = 'blog_users' 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    posts = relationship('Post', backref='author', lazy='dynamic', cascade="all, delete-orphan") # カスケード削除を追加

    # パスワードリセットトークン用
    reset_token = db.Column(db.String(256), nullable=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        """パスワードをハッシュ化して保存する"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """入力されたパスワードとハッシュを比較する"""
        return bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.username}', '{self.id}')"

class Post(db.Model):
    """記事モデル"""
    # 💡 修正: テーブル名を明示的に設定
    __tablename__ = 'posts' 
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    public_id = db.Column(db.String(100), nullable=True) # Cloudinary Public ID
    create_at = db.Column(db.DateTime, nullable=False, default=now)
    # 💡 修正: ForeignKeyは 'blog_users.id' を参照
    user_id = db.Column(db.Integer, db.ForeignKey('blog_users.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.create_at}')"

# --- ユーザーローダー ---

@login_manager.user_loader
def load_user(user_id):
    """Flask-LoginがセッションからユーザーIDをロードするためのコールバック"""
    return db.session.get(User, int(user_id))

# --- ルーティング ---

@app.route("/")
@app.route("/index")
def index():
    """ブログ記事一覧ページ"""
    # 全ての記事を新しい順に取得
    posts = db.session.execute(db.select(Post).order_by(Post.create_at.desc())).scalars().all()
    return render_template('index.html', title='ホーム', posts=posts)


@app.route("/db_reset", methods=["GET", "POST"])
def db_reset():
    """データベーステーブルのリセット（開発用）"""
    # 🚨 本番環境でのガード
    if app.config['SECRET_KEY'] == 'my_default_secret_key':
        flash("データベースリセットは本番環境では許可されていません。", 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            with app.app_context():
                db.session.close()

                # PostgreSQLの場合
                if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgresql'):
                    # 💡 修正: 明示的に設定したテーブル名をドロップ
                    db.session.execute(text("DROP TABLE IF EXISTS posts CASCADE;"))
                    db.session.execute(text("DROP TABLE IF EXISTS blog_users CASCADE;"))
                    db.session.execute(text("DROP TABLE IF EXISTS alembic_version CASCADE;"))
                    
                    db.session.commit()
                    db.create_all()

                # SQLiteの場合
                elif app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
                    db.drop_all()
                    db.create_all()
                
                db.session.commit()
                flash("データベースのテーブルが正常に削除・再作成されました。サインアップをお試しください。", 'success')
                return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            print(f"データベースリセット中にエラーが発生しました: {e}", file=sys.stderr)
            flash(f"データベースリセット中にエラーが発生しました: {e}", 'danger')
            return redirect(url_for('index'))

    # リセット確認画面の表示
    return render_template("db_reset_confirm.html", title='DBリセット確認')


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
            flash('ログインに成功しました！', 'success')
            return redirect(next_page or url_for('index'))
        else:
            flash('ユーザー名またはパスワードが正しくありません。', 'danger')

    return render_template('login.html', title='ログイン')

# サインアップ
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    新規ユーザー登録ページ
    """
    # ログイン済みの場合はインデックスページにリダイレクト
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    # forms.py で定義された RegistrationForm のインスタンスを作成し、テンプレートに渡す
    form = RegistrationForm() 
    
    if form.validate_on_submit():
        # フォームの検証に成功した場合の処理
        username = form.username.data
        password = form.password.data
        
        # ユーザー名の重複チェック
        user = User.query.filter_by(username=username).first()
        if user:
            flash('そのユーザー名はすでに使用されています。', 'danger')
        else:
            # 新しいユーザーオブジェクトを作成
            new_user = User(username=username)
            new_user.set_password(password) # パスワードをハッシュ化して設定
            
            # データベースに保存
            db.session.add(new_user)
            db.session.commit()
            
            flash(f'アカウントが作成されました: {username}! ログインしてください。', 'success')
            return redirect(url_for('login'))
        
    # GETリクエスト、または検証に失敗したPOSTリクエストの場合
    # 'form' オブジェクトをテンプレートに渡す (エラー修正箇所)
    return render_template('signup.html', title='サインアップ', form=form) # form=form を渡す

# ログアウト
@app.route('/logout')
@login_required
def logout():
    """ログアウト処理"""
    logout_user()
    flash('ログアウトしました。', 'info')
    return redirect(url_for('index'))

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
            return render_template('create.html', title='新規投稿', post={'title': title, 'content': content})

        # Cloudinaryに画像をアップロード
        if image_file and image_file.filename != '':
            try:
                # 既存の公開IDがない場合、新しいIDを生成してアップロード
                upload_result = cloudinary.uploader.upload(image_file,
                                                          folder="flask_blog_images")
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

    return render_template('create.html', title='新規投稿')

# 記事詳細
@app.route('/post/<int:post_id>')
def view(post_id):
    """記事詳細ページ"""
    post = db.session.get(Post, post_id)
    if not post:
        return render_template('404.html', title="404 記事が見つかりません"), 404

    # 画像URLを生成
    image_url = None
    if post.public_id:
        image_url = cloudinary.utils.cloudinary_url(post.public_id, fetch_format="auto", quality="auto")[0]

    return render_template('view.html', post=post, image_url=image_url, title=post.title)


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
            return render_template('update.html', post=post, title='記事編集')

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
                # 古い画像があれば削除
                if post.public_id:
                    cloudinary.uploader.destroy(post.public_id)

                upload_result = cloudinary.uploader.upload(image_file,
                                                          folder="flask_blog_images")
                post.public_id = upload_result.get('public_id')
                flash('新しい画像が正常にアップロードされました。', 'success')
            except Exception as e:
                flash(f'画像のアップロード中にエラーが発生しました: {e}', 'danger')

        db.session.commit()
        flash('記事が正常に更新されました。', 'success')
        return redirect(url_for('view', post_id=post.id))

    # GETリクエスト時の画像URL
    current_image_url = None
    if post.public_id:
        current_image_url = cloudinary.utils.cloudinary_url(post.public_id, fetch_format="auto", quality="auto", width=200, crop="scale")[0]

    return render_template('update.html', post=post, title='記事編集', current_image_url=current_image_url)

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


# 管理画面
@app.route('/admin')
@login_required
def admin():
    """管理画面（自分の記事一覧）"""
    posts = db.session.execute(
        db.select(Post).filter_by(user_id=current_user.id).order_by(Post.create_at.desc())
    ).scalars().all()
    return render_template('admin.html', posts=posts, title='管理者ダッシュボード')

# アカウント設定 (省略 - テンプレートなし)
@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    """アカウント設定（ユーザー名/パスワード変更）"""
    user = current_user
    # 実際のアカウントロジックはapp.pyの先頭に定義されているが、テンプレートがないため未実装

    if request.method == 'POST':
        # ... (ロジックはapp.pyの前のバージョンで定義済み)
        pass # 処理は省略し、未実装ページとして扱う

    flash("アカウント設定ページは現在未実装です。", 'info')
    return redirect(url_for('admin')) # 管理画面にリダイレクト

# パスワードリセット (省略 - テンプレートなし)
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    flash("パスワードリセット機能は現在未実装です。", 'info')
    return redirect(url_for('login'))

@app.route('/reset_password/<path:token>', methods=['GET', 'POST'])
def reset_password(token):
    flash("パスワードリセット機能は現在未実装です。", 'info')
    return redirect(url_for('login'))


# --- エラーハンドリング ---

@app.errorhandler(404)
def not_found_error(error):
    """404エラーハンドラ"""
    return render_template('404.html', title='404 Not Found'), 404

if __name__ == '__main__':
    # ローカル開発環境でのみ実行
    with app.app_context():
        # ローカル起動時にもテーブル作成を試みる
        if not hasattr(app, 'tables_created'):
            try:
                db.create_all()
                app.tables_created = True
            except Exception as e:
                 print(f"Local db.create_all() error: {e}", file=sys.stderr)

    app.run(debug=True)
