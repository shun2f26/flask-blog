import os
import sys
import re
from flask import Flask, render_template, request, redirect, flash, url_for, abort, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, DateTime, func, ForeignKey
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
# from PIL import Image # ★ PILのインポートを削除
import uuid

# 環境変数の設定とURIの修正（Render環境対応）
SECRET_KEY = os.environ.get('SECRET_KEY', 'default_secret_key_for_development')
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///myblog.db')
POSTGRES_URL_PATTERN = re.compile(r'postgres(ql)?://')

if POSTGRES_URL_PATTERN.match(DATABASE_URL):
    DB_URI = POSTGRES_URL_PATTERN.sub(r'postgresql://', DATABASE_URL)
else:
    DB_URI = DATABASE_URL

# アプリケーション設定
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
# app.config['UPLOAD_FOLDER'] = 'static/uploads' # ★ UPLOAD_FOLDER設定を削除
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MBまでのファイルサイズ制限

# データベース初期化
class Base(DeclarativeBase):
    pass
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Flask-Loginの設定
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'ログインしてください。'

# ユーザーローダー関数
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- モデル定義 ---

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(256), nullable=False)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Post(db.Model):
    __tablename__ = 'post'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(100), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False) # contentカラムの存在を保証
    create_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    # image_file: Mapped[str] = mapped_column(String(100), nullable=True) # ★ image_fileカラムを削除
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)

    # リレーションシップ
    author: Mapped[User] = db.relationship("User")

    def __repr__(self):
        return f'<Post {self.title}>'

# --- ユーティリティ関数 ---

def get_user_by_username(username):
    """ユーザー名を基にユーザーを取得する"""
    return db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()

# def save_picture(form_picture): # ★ save_picture関数を削除
#     """アップロードされた画像を保存し、ファイル名を返す"""
#     return None

# --- ルート定義 ---

@app.route("/")
def index():
    posts = db.session.execute(
        db.select(Post)
        .order_by(Post.create_at.desc())
    ).scalars().all()
    return render_template('index.html', posts=posts)

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
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = get_user_by_username(username)
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('ログインしました。', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('admin'))
        else:
            flash('ログインに失敗しました。ユーザー名またはパスワードを確認してください。', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('ログアウトしました。', 'success')
    return redirect(url_for('index'))

@app.route("/admin")
@login_required
def admin():
    posts = db.session.execute(
        db.select(Post)
        .filter_by(user_id=current_user.id)
        .order_by(Post.create_at.desc())
    ).scalars().all()
    return render_template('admin.html', posts=posts)

@app.route("/create", methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        # image = request.files.get('image') # ★ 画像の取得を削除

        if not title or not content:
            flash('タイトルと本文を入力してください。', 'warning')
            return redirect(url_for('create'))

        # image_file = save_picture(image) # ★ 画像の保存処理を削除
        
        new_post = Post(
            title=title, 
            content=content, 
            # image_file=image_file, # ★ image_fileの保存を削除
            user_id=current_user.id
        )
        
        db.session.add(new_post)
        db.session.commit()
        flash('記事が投稿されました。', 'success')
        return redirect(url_for('admin'))
        
    return render_template('create.html')

@app.route("/view/<int:post_id>")
def view(post_id):
    post = db.session.get(Post, post_id)
    if post is None:
        abort(404)
    return render_template('view.html', post=post)

@app.route("/update/<int:post_id>", methods=['GET', 'POST'])
@login_required
def update(post_id):
    post = db.session.get(Post, post_id)
    if post is None:
        abort(404)
        
    if post.user_id != current_user.id:
        abort(403)
        
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        # image = request.files.get('image') # ★ 画像の取得を削除
        # delete_image = request.form.get('delete_image') # ★ 画像削除フラグの取得を削除

        if not title or not content:
            flash('タイトルと本文を入力してください。', 'warning')
            return redirect(url_for('update', post_id=post_id))
            
        post.title = title
        post.content = content
        
        # ★ 画像の削除・更新処理をすべて削除
        # if delete_image == 'on' and post.image_file: ...
        # if image and image.filename != '': ...

        db.session.commit()
        flash('記事が更新されました。', 'success')
        return redirect(url_for('admin'))
        
    return render_template('update.html', post=post)

@app.route("/delete/<int:post_id>", methods=['POST'])
@login_required
def delete(post_id):
    post = db.session.get(Post, post_id)
    if post is None:
        abort(404)
        
    if post.user_id != current_user.id:
        abort(403)
        
    # ★ 画像ファイル削除処理を削除
    # if post.image_file: ...

    db.session.delete(post)
    db.session.commit()
    flash('記事が削除されました。', 'success')
    return redirect(url_for('admin'))

# --- データベース初期化ルート ---
@app.route('/db_init')
def db_init():
    try:
        engine = create_engine(DB_URI)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        
        with app.app_context():
            # **重要**: Postモデルからimage_fileを削除したため、テーブルを再作成する必要があります
            db.drop_all()
            db.create_all()
            return "Database tables (Post and User) created successfully! Please remove this route after running once."
    except Exception as e:
        return f"Database initialization failed: {e}", 500

# --- データベースリセットルート（開発用） ---
@app.route('/db_reset')
def db_reset():
    try:
        with app.app_context():
            db.drop_all()
            db.create_all()
            return "データベーステーブルがリセットされ、正常に再作成されました。**重要**:一度実行した後は、このルートを削除してください。"
    except Exception as e:
        return f"データベースリセット中にエラーが発生しました: {e}", 500

# --- エラーハンドリング ---

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error_page.html', title='アクセス拒否', message='この記事を編集/削除する権限がありません。'), 403

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error_page.html', title='ページが見つかりません', message='お探しのページは存在しません。'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    # 500エラー発生時にトレースバックをコンソールに出力してデバッグしやすくする
    import traceback
    app.logger.error('500 Internal Server Error:\n' + traceback.format_exc())
    return render_template('error_page.html', title='内部サーバーエラー', message='サーバーで予期せぬエラーが発生しました。'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
    print(f"データベースURI: {DB_URI}")
    app.run(debug=True)
