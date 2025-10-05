import os
import sys
from flask import Flask, render_template, request, redirect, flash, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import secrets

# --- アプリケーション設定 ---

app = Flask(__name__)

# Render環境変数から SECRET_KEY と DATABASE_URL を取得
# secrets.token_hex(16)はローカルフォールバック用
app.config["SECRET_KEY"] = os.environ.get('SECRET_KEY', secrets.token_hex(16))

# RenderのPostgreSQLデータベース接続設定を修正
database_url = os.environ.get('DATABASE_URL')

if database_url:
    # 1. Heroku/Renderの古いURL形式(postgres://)を新しい形式(postgresql://)に変換
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    # 2. RenderのPostgreSQL接続にはsslmode=requireが必須
    if 'sslmode=require' not in database_url:
        separator = '&' if '?' in database_url else '?'
        database_url += f'{separator}sslmode=require'
else:
    # ローカル開発用のデフォルト設定
    database_url = 'sqlite:///site.db'
    
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
migrate.init_app(app, db) # Gunicorn回避策を導入済み

# アップロードが許可される拡張子 (今回は簡易のため、画像アップロード機能は静的なファイル名として扱います)
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# --- データベースモデル ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    body = db.Column(db.String(5000), nullable=False) # 本文を長く
    create_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # 実際にはS3などの外部ストレージを使用しますが、今回は静的ファイル名を保存
    img_name = db.Column(db.String(300), nullable=True, default="placeholder.jpg") 
    
@login_manager.user_loader 
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- ヘルパー関数 (SQLAlchemy 2.0対応) ---

def get_post_or_404(post_id):
    # db.session.getを使用してPostを取得し、見つからなければ404エラー
    post = db.session.get(Post, post_id)
    if post is None: abort(404)
    return post

def get_user_by_username(username):
    # db.session.executeとdb.selectを使用してユーザーを検索
    return db.session.execute(
        db.select(User).filter_by(username=username)
    ).scalar_one_or_none()

# --- ルーティング ---

@app.route("/")
def index():
    # 全投稿を新しい順に取得 (SQLAlchemy 2.0)
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
    # 全投稿を新しい順に取得 (SQLAlchemy 2.0)
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
        
        # 簡易画像処理 (ファイル名のみ保存)
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
        # 画像更新ロジックは今回は省略
        
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
        flash('登録が完了しました。ログインしてください。', 'success')
        return redirect(url_for('login'))
        
    return render_template('signup.html')
        
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

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

        # 1. パスワード確認（必須）
        if not check_password_hash(user.password, current_password):
            flash('現在のパスワードが間違っています。', 'danger')
            return redirect(url_for('account'))

        is_updated = False
        
        # 2. ユーザー名更新
        if new_username and new_username != user.username:
            existing_user = get_user_by_username(new_username)
            if existing_user and existing_user.id != user.id:
                flash('そのユーザー名は既に使用されています。', 'warning')
                return redirect(url_for('account'))
            
            user.username = new_username
            is_updated = True

        # 3. パスワード更新
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

# --- エラーハンドラー ---

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# --- アプリケーション実行 (ローカル開発用) ---

if __name__ == '__main__':
    with app.app_context():
        # ローカル環境の場合、マイグレーションを適用
        if 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI']:
            print("ローカルSQLite環境のため、db upgradeを実行します...", file=sys.stderr)
            try:
                from flask_migrate import upgrade
                upgrade()
            except Exception as e:
                # 初回実行時
                print(f"Migrate実行エラー（初回セットアップ時などは無視可）: {e}", file=sys.stderr)
                db.create_all()

    app.run(debug=True)
