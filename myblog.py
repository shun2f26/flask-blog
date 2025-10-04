# myblog.py (Renderデプロイ用)

import os
import sys # sysモジュールを追加 (printをstderrにリダイレクトするため)
from flask import Flask, render_template, request, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# --- アプリケーション設定 ---

app = Flask(__name__)

# Render環境変数から SECRET_KEY を取得
app.config["SECRET_KEY"] = os.environ.get('SECRET_KEY', os.urandom(24))

# --- PostgreSQL接続設定 (Render対応の最終修正) ---
uri = os.environ.get('DATABASE_URL')

# 1. 接続スキームの修正: 'postgres://' を 'postgresql://' に置き換える
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)

# 2. SSLモードの追加: RenderではSSL接続が必須。クエリパラメータとして 'sslmode=require' を追加
# タイムアウトの原因を解消するため、この設定を確実に追加
if uri:
    if '?' not in uri:
        uri += '?sslmode=require'
    elif 'sslmode' not in uri:
        uri += '&sslmode=require'

app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- データベースとマイグレーションの遅延初期化 (Lazy Init) ---
# アプリケーション起動時のDB接続を遅延させるため、dbオブジェクトを先に作成し、
# 後で app.init_app(db) でバインドするパターンを使用
db = SQLAlchemy()
db.init_app(app) # アプリケーションの構成が完了した後にDBをバインド

migrate = Migrate(app, db)

# ログイン管理システム
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 
login_manager.login_message = 'ログインが必要です。'

# アップロードが許可される拡張子
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# --- データベースモデル ---

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    body = db.Column(db.String(1000), nullable=False)
    create_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    img_name = db.Column(db.String(300), nullable=True, default="") 
    
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    
@login_manager.user_loader 
def load_user(user_id):
    # アプリケーションコンテキスト内で実行されるため、dbは既にバインドされている
    return User.query.get(int(user_id))

# --- ファイルユーティリティ ---

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# --- ルーティング ---

@app.route("/")
def index():
    # 記事がなくても、テーブルが存在しない場合はここでエラーになる（db upgradeが必要）
    posts = Post.query.order_by(Post.create_at.desc()).all()
    # templates/index.html に view ルーティングのURLがないため追加
    return render_template("index.html", posts=posts)

# 記事詳細表示用のルーティング (templates/index.htmlとtemplates/view.htmlで使用)
@app.route("/post/<int:post_id>")
def view(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template("view.html", post=post)

@app.route("/admin")
@login_required
def admin():
    posts = Post.query.order_by(Post.create_at.desc()).all()
    return render_template("admin.html", posts=posts)

@app.route("/create", methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'GET':
        return render_template('create.html')
    
    elif request.method == 'POST':
        file = request.files.get('img')
        db_img_name = None 
        
        if file and file.filename != '':
            uploaded_filename = file.filename
            upload_folder = os.path.join(app.root_path, 'static', 'img')
            
            # Renderでは一時ファイルシステムにしか書き込めないが、処理を続行
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            
            save_path = os.path.join(upload_folder, uploaded_filename)
            file.save(save_path)
            db_img_name = uploaded_filename
            
        title = request.form.get('title')
        body = request.form.get('body')

        post = Post(title=title, body=body, img_name=db_img_name) 
        
        try:
            db.session.add(post)
            db.session.commit()
            flash('記事が作成されました。', 'success')
            return redirect('/admin')
        except Exception as e:
            flash(f'記事の作成中にデータベースエラーが発生しました: {e}', 'danger')
            db.session.rollback()
            return redirect(url_for('create'))

        
@app.route("/<int:post_id>/update",methods =['GET','POST'])
@login_required
def update(post_id):
    post = Post.query.get_or_404(post_id) 
    
    if request.method == 'POST':
        # 画像更新ロジックは今回も省略
        post.title = request.form.get('title')
        post.body = request.form.get('body')
        
        db.session.commit()
        flash('記事が更新されました。', 'success')
        return redirect('/admin')
        
    elif request.method == 'GET':
        return render_template('update.html', post=post)
    
@app.route("/<int:post_id>/delete")
@login_required
def delete(post_id):
    post = Post.query.get_or_404(post_id) 
    db.session.delete(post)
    db.session.commit()
    flash('記事が削除されました。', 'danger')
    return redirect('/admin')  

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('そのユーザー名はすでに使われています。', 'warning')
            return redirect(url_for('signup'))

        hashed_pass = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_pass)
        
        db.session.add(new_user)
        db.session.commit()
        flash('登録が完了しました。ログインしてください。', 'success')
        return redirect('/login')
        
    elif request.method == 'GET':
        return render_template('signup.html')
        
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first() 
        
        if user and check_password_hash(user.password, password=password):
            login_user(user)
            flash('ログイン成功！', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('admin'))
        else:
            flash('ユーザー名またはパスワードが違います', 'danger')
            return redirect('/login')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('ログアウトしました。', 'info')
    return redirect('/login')
    
# アカウント管理ルーティングを追加
@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        # ユーザー名変更ロジック
        new_username = request.form.get('username')
        
        # パスワード変更ロジック
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # ユーザー名変更処理
        if new_username and new_username != current_user.username:
            # 既存チェック
            if User.query.filter_by(username=new_username).first():
                flash('そのユーザー名はすでに使われています。', 'warning')
                return redirect(url_for('account'))
            
            current_user.username = new_username
            flash('ユーザー名が更新されました。', 'success')
            
        # パスワード変更処理
        if new_password:
            if new_password != confirm_password:
                flash('新しいパスワードと確認用パスワードが一致しません。', 'danger')
                return redirect(url_for('account'))
            
            current_user.password = generate_password_hash(new_password, method='sha256')
            flash('パスワードが更新されました。', 'success')

        db.session.commit()
        return redirect(url_for('account'))
    
    return render_template('account.html')

# パスワードリセット関連のルーティングは今回省略
# (認証とメール送信が必要で複雑なため)

if __name__ == '__main__':
    # ローカル開発時に実行
    # 本番環境では gunicorn が実行するため不要
    print("Running Flask in local development mode.", file=sys.stderr)
    # ローカル環境ではデータベースのスキーマが存在しない場合があるため、
    # 開発環境でのみ create_all() を実行する（Render環境では実行しない）
    # with app.app_context():
    #     db.create_all() 
    app.run(debug=True)

# Gunicornは 'myblog:app' を使用してアプリを起動します
