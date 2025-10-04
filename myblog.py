from flask import Flask, render_template, request, redirect, flash, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import uuid # ファイル名の衝突回避用

app = Flask(__name__)

db = SQLAlchemy()
SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://{user}:{password}@{host}/{name}'.format(**{
            'user': 'postgres',
            'password': 'shun2f26',
            'host': 'localhost',
            'name': 'postgres'
    })
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI

# アップロード設定
UPLOAD_FOLDER = os.path.join(app.static_folder, 'img')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# パスワードリセットのためのセキュアなトークン処理用 (ここでは簡易的にSECRET_KEYを利用)
# 本来はitsdangerousなどのライブラリを使用します
app.config['RESET_SECRET'] = app.config["SECRET_KEY"]

# --- 拡張機能の初期化 ---
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ログイン管理システム
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # 未ログイン時のリダイレクト先
login_manager.login_message = 'ログインが必要です。'


# --- モデル定義 ---
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    body = db.Column(db.String(1000), nullable=False)
    create_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # img_nameにはユニークな名前を保存する
    img_name = db.Column(db.String(300), nullable=True, default="") 
    # NOTE: Postモデルから不要なreset_tokenを削除しました
    # reset_token = db.Column(db.String(100), nullable=True) # 削除
    
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    reset_token = db.Column(db.String(100), nullable=True) # パスワードリセット用トークン
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ヘルパー関数 ---
def allowed_file(filename):
    """アップロードが許可される拡張子か判別"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_unique_filename(filename):
    """ファイル名の衝突を避けるためにユニークなIDを付与"""
    ext = filename.rsplit('.', 1)[1].lower()
    unique_name = str(uuid.uuid4())
    return f"{unique_name}.{ext}"

# --- ルーティング ---

# A. 公開ページ

@app.route("/")
def index():
    """ブログの公開トップページ"""
    posts = Post.query.order_by(Post.create_at.desc()).all()
    return render_template("index.html", posts=posts)

@app.route("/post/<int:post_id>")
def view(post_id):
    """ブログ記事の詳細ページ"""
    post = Post.query.get_or_404(post_id)
    return render_template("view.html", post=post)

# B. 管理機能（CRUD）

@app.route("/admin")
@login_required
def admin():
    """管理画面（記事一覧）"""
    # 投稿日時が新しい順に表示
    posts = Post.query.order_by(Post.create_at.desc()).all() 
    return render_template("admin.html", posts=posts)

@app.route("/create", methods=['GET', 'POST'])
@login_required
def create():
    """記事の新規作成"""
    if request.method == 'POST':
        title = request.form.get('title')
        body = request.form.get('body')
        
        file = request.files.get('img')
        db_img_name = "" 
        
        if file and allowed_file(file.filename):
            try:
                # フォルダが存在しない場合に作成
                if not os.path.exists(app.config['UPLOAD_FOLDER']):
                    os.makedirs(app.config['UPLOAD_FOLDER'])
                
                # ユニークなファイル名を生成
                uploaded_filename = generate_unique_filename(file.filename)
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_filename)
                file.save(save_path)
                db_img_name = uploaded_filename
            except Exception as e:
                flash(f'画像のアップロード中にエラーが発生しました: {e}', 'danger')
                print(f"File upload error: {e}")
                
        # Post モデルを作成
        post = Post(title=title, body=body, img_name=db_img_name) 
        
        db.session.add(post)
        db.session.commit()
        flash('新しい記事を作成しました。', 'success')
        return redirect(url_for('admin'))
        
    return render_template('create.html')
    
@app.route("/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update(post_id):
    """記事の更新"""
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        post.title = request.form.get('title')
        post.body = request.form.get('body')

        # 画像更新ロジック
        file = request.files.get('img')
        if file and allowed_file(file.filename):
            try:
                # 古いファイルがあれば削除 (オプション)
                # if post.img_name:
                #     os.remove(os.path.join(app.config['UPLOAD_FOLDER'], post.img_name))

                # 新しいファイルを保存
                uploaded_filename = generate_unique_filename(file.filename)
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_filename)
                file.save(save_path)
                post.img_name = uploaded_filename
            except Exception as e:
                flash(f'画像の更新中にエラーが発生しました: {e}', 'danger')
                print(f"File update error: {e}")
                
        db.session.commit()
        flash('記事が更新されました。', 'success')
        return redirect(url_for('admin'))
        
    return render_template('update.html', post=post)
    
@app.route("/<int:post_id>/delete")
@login_required
def delete(post_id):
    """記事の削除"""
    post = Post.query.get_or_404(post_id)
    
    # 関連する画像ファイルも削除する場合
    if post.img_name:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], post.img_name)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Failed to delete file {file_path}: {e}")

    db.session.delete(post)
    db.session.commit()
    flash('記事が削除されました。', 'warning')
    return redirect(url_for('admin')) 

# C. 認証機能

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    """新規ユーザー登録"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # ユーザー名の重複チェック
        if User.query.filter_by(username=username).first():
            flash('そのユーザー名はすでに使用されています。', 'warning')
            return redirect(url_for('signup'))
            
        hashed_pass = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pass)
        db.session.add(new_user)
        db.session.commit()
        flash('アカウントが作成されました。ログインしてください。', 'success')
        return redirect(url_for('login'))
        
    return render_template('signup.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    """ログイン"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first() 
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('ログインに成功しました。', 'success')
            # ログイン成功後、管理画面にリダイレクト
            return redirect(url_for('admin'))
        else:
            flash('ユーザー名またはパスワードが違います', 'danger')
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """ログアウト"""
    logout_user()
    flash('ログアウトしました。', 'info')
    return redirect(url_for('login'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    """アカウント設定"""
    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        user = current_user
        changes_made = False

        # ユーザー名変更
        if new_username and new_username != user.username:
            # 重複チェック
            if User.query.filter(User.username == new_username, User.id != user.id).first():
                flash('そのユーザー名はすでに使用されています。', 'warning')
                return redirect(url_for('account'))
            user.username = new_username
            changes_made = True

        # パスワード変更
        if new_password:
            if new_password != confirm_password:
                flash('新しいパスワードと確認用パスワードが一致しません。', 'danger')
                return redirect(url_for('account'))
            
            # パスワードのハッシュ化と更新
            user.password = generate_password_hash(new_password)
            changes_made = True
        
        if changes_made:
            db.session.commit()
            flash('アカウント設定を更新しました。', 'success')
        else:
            flash('変更点はありませんでした。', 'info')
            
        return redirect(url_for('account'))
        
    return render_template('account.html', current_user=current_user)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """パスワードリセット要求 (メール機能は省略)"""
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        
        if user:
            # 実際のアプリケーションでは、ここでitsdangerousを使ってトークンを生成し、
            # ユーザーのメールアドレスにリセットURLを送信します。
            # 今回は簡易的に、ユーザーオブジェクトに直接トークンを保存すると仮定します。
            reset_token = str(uuid.uuid4())
            user.reset_token = reset_token
            db.session.commit()
            
            # メール送信の代わりに、デバッグメッセージでリセットURLを表示
            flash(f'パスワードリセットリンクを送信しました。 (デバッグ: {url_for("reset_password", token=reset_token, _external=True)})', 'info')
        else:
            flash('ユーザーが見つかりませんでした。', 'danger')
            
        return redirect(url_for('forgot_password'))
        
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """パスワードリセット実行"""
    user = User.query.filter_by(reset_token=token).first()
    
    if not user:
        flash('無効なリセットリンクです。', 'danger')
        return redirect(url_for('forgot_password'))
        
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('パスワードが一致しません。', 'danger')
            return redirect(url_for('reset_password', token=token))
            
        # パスワードを更新し、トークンをクリア
        user.password = generate_password_hash(password)
        user.reset_token = None
        db.session.commit()
        
        flash('パスワードが正常にリセットされました。新しいパスワードでログインしてください。', 'success')
        return redirect(url_for('login'))
        
    return render_template('reset_password.html', token=token)

# 静的ファイルの提供（Renderで静的ファイルが正しくロードされない場合の代替策）
@app.route('/static/img/<filename>')
def serve_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# アプリケーションの実行 (ローカル用)
if __name__ == "__main__":
    # Renderでは自動で'FLASK_APP'が設定されますが、ローカル実行のために設定
    # with app.app_context():
    #     db.create_all() # マイグレーション使用時は不要
    #     print("Database initialized.")
    app.run(debug=True)
