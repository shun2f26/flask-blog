# -*- coding: utf-8 -*-
import os
import requests
import cloudinary
import cloudinary.uploader
import json
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for, flash, session, abort, make_response
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# 環境変数の設定チェック
if not os.environ.get('SECRET_KEY'):
    print("WARNING: SECRET_KEY is not set. Using a default for local development.")
    
# --- Gemini API 設定 ---
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent"

# Flaskアプリのインスタンス作成
app = Flask(__name__)

# Render環境変数から SECRET_KEY と DATABASE_URL を取得
app.config["SECRET_KEY"] = os.environ.get('SECRET_KEY', os.urandom(24))

# --- PostgreSQL接続設定 (Render対応) ---
uri = os.environ.get('DATABASE_URL')

# 1. 接続スキームの修正: 'postgres://' を 'postgresql://' に置き換える
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)

# 2. SSLモードの追加: RenderではSSL接続が必須。クエリパラメータとして 'sslmode=require' を追加
if uri:
    if '?' not in uri:
        uri += '?sslmode=require'
    elif 'sslmode' not in uri and uri.endswith('require'): # 二重追加防止の簡易チェック
        uri += '&sslmode=require'
    elif 'sslmode' not in uri: # 上記チェックで漏れる場合の追加
        uri += '&sslmode=require'


app.config['SQLALCHEMY_DATABASE_URI'] = uri if uri else 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- データベースとマイグレーションの遅延初期化 ---
db = SQLAlchemy()
db.init_app(app)

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
    app.logger.error("Cloudinary APIキーが設定されていません。画像アップロード機能は無効です。")
    # ダミー設定で、アップロード機能を実行してもエラーにならないようにする
    cloudinary.config(cloud_name="dummy", api_key="dummy", api_secret="dummy")

# --- データベースモデル ---

class User(db.Model):
    __tablename__ = 'users' # PostgreSQLの予約語 'user' を避ける
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256)) # パスワードハッシュに合わせて長さを256に設定
    is_admin = db.Column(db.Boolean, default=False)
    posts = db.relationship('Post', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    public_id = db.Column(db.String(100), nullable=True) # Cloudinaryのpublic_idを保存

    @property
    def image_url(self):
        """CloudinaryのURLを生成するプロパティ"""
        if self.public_id and cloudinary_cloud_name != "dummy":
            return cloudinary.utils.cloudinary_url(self.public_id, fetch_format="auto", quality="auto")[0]
        return None

# --- 認証デコレータ ---

def login_required(f):
    """ログイン必須のデコレータ"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('このページにアクセスするにはログインが必要です。', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """管理者必須のデコレータ"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('このページにアクセスするにはログインが必要です。', 'warning')
            return redirect(url_for('login', next=request.url))
        
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('管理者権限がありません。', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- ヘルパー関数 ---

def gemini_api_call(prompt):
    """Gemini APIを呼び出してテキストを生成するヘルパー関数"""
    if not GEMINI_API_KEY:
        app.logger.error("Gemini APIキーが設定されていません。")
        return "Gemini APIキーが設定されていません。AIアシスタント機能は動作しません。"

    headers = {'Content-Type': 'application/json'}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "systemInstruction": {"parts": [{"text": "あなたはプロの編集者です。ユーザーのブログ記事の草稿を受け取り、文法、明瞭さ、文体、そして読者への魅力を高めるように校正・改善してください。回答は改善された記事本文のみとし、装飾的な前書きや後書きは一切含めないでください。"}]},
        "tools": [{"google_search": {}}]
    }

    try:
        response = requests.post(
            f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
            headers=headers,
            data=json.dumps(payload),
            timeout=30  # タイムアウトを設定
        )
        response.raise_for_status()
        
        result = response.json()
        text = result.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', 'AIからの応答がありませんでした。')
        return text
    
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Gemini APIリクエストエラー: {e}")
        return f"AIアシスタントとの通信中にエラーが発生しました: {e}"

def upload_image_to_cloudinary(file_stream, current_public_id=None):
    """画像をCloudinaryにアップロードし、public_idを返す"""
    if cloudinary_cloud_name == "dummy":
        return None # Cloudinaryが無効な場合は何もしない

    options = {
        'folder': 'flask_blog_app',
        'overwrite': True,
        'unique_filename': True,
        'tags': 'blog_image'
    }
    
    # 既存のpublic_idが渡された場合、それを使って上書きする
    if current_public_id:
        options['public_id'] = current_public_id
        options['overwrite'] = True
    else:
        # 新しい画像をアップロードする場合は、ユニークなpublic_idを生成
        pass 

    try:
        upload_result = cloudinary.uploader.upload(file_stream, **options)
        return upload_result.get('public_id')
    except Exception as e:
        app.logger.error(f"Cloudinaryアップロードエラー: {e}")
        flash(f"画像のアップロードに失敗しました。{e}", 'danger')
        return None

def delete_image_from_cloudinary(public_id):
    """Cloudinaryから画像を削除する"""
    if cloudinary_cloud_name == "dummy" or not public_id:
        return True # Cloudinaryが無効な場合やpublic_idがない場合は成功と見なす
    try:
        cloudinary.uploader.destroy(public_id)
        return True
    except Exception as e:
        app.logger.error(f"Cloudinary削除エラー: {e}")
        return False


# --- ルーティング ---

@app.context_processor
def inject_user():
    """テンプレートでログインユーザー情報を利用可能にする"""
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    return dict(current_user=user)

# --- 記事関連 ---

@app.route('/')
def index():
    """記事一覧ページ"""
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """記事作成ページ"""
    title = request.form.get('title', '')
    content = request.form.get('content', '')
    
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'ai_assist':
            # AIアシスタント処理
            if not title or not content:
                flash('AIアシスタントを利用するには、タイトルとコンテンツを入力してください。', 'warning')
            else:
                prompt = f"タイトル: {title}\n\nコンテンツ:\n{content}"
                improved_content = gemini_api_call(prompt)
                
                # 改善された内容をフォームに戻すために変数にセット
                # titleはそのまま、contentを改善されたものにする
                content = improved_content
                flash('AIアシスタントによる校正が完了しました。内容を確認してください。', 'success')
            
            # 再度create.htmlをレンダリングし、入力内容を維持
            return render_template('create.html', title=title, content=content)

        elif action == 'create':
            # 記事投稿処理
            
            # 必須フィールドのチェック
            if not title or not content:
                flash('タイトルとコンテンツは必須です。', 'danger')
                return render_template('create.html', title=title, content=content)

            # 画像アップロード処理
            image_file = request.files.get('image')
            public_id = None
            
            if image_file and image_file.filename != '':
                public_id = upload_image_to_cloudinary(image_file.stream)
                if not public_id:
                    # Cloudinaryエラーの場合、エラーメッセージは既にフラッシュされている
                    return render_template('create.html', title=title, content=content)
            
            # データベースに記事を保存
            new_post = Post(
                title=title,
                content=content,
                user_id=session['user_id'],
                public_id=public_id
            )
            try:
                db.session.add(new_post)
                db.session.commit()
                flash('記事が正常に作成されました。', 'success')
                return redirect(url_for('index'))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"記事作成DBエラー: {e}")
                flash('記事の作成中にエラーが発生しました。', 'danger')
                return render_template('create.html', title=title, content=content)
            
    # GETリクエストまたはAIアシスタントからの戻り
    return render_template('create.html', title=title, content=content)


@app.route('/<int:post_id>/view')
def view(post_id):
    """記事詳細ページ"""
    post = Post.query.get_or_404(post_id)
    return render_template('view.html', post=post)

@app.route('/<int:post_id>/update', methods=['GET', 'POST'])
@login_required
def update(post_id):
    """記事編集ページ"""
    post = Post.query.get_or_404(post_id)
    
    # 投稿者または管理者のみが編集可能
    if post.user_id != session['user_id'] and not User.query.get(session['user_id']).is_admin:
        flash('この記事を編集する権限がありません。', 'danger')
        return redirect(url_for('view', post_id=post.id))

    if request.method == 'POST':
        action = request.form.get('action')
        title = request.form.get('title')
        content = request.form.get('content')

        if action == 'ai_assist':
            # AIアシスタント処理
            if not title or not content:
                flash('AIアシスタントを利用するには、タイトルとコンテンツを入力してください。', 'warning')
            else:
                prompt = f"タイトル: {title}\n\nコンテンツ:\n{content}"
                improved_content = gemini_api_call(prompt)
                
                # 改善された内容をフォームに戻す
                content = improved_content
                flash('AIアシスタントによる校正が完了しました。内容を確認してください。', 'success')
            
            # 再度update.htmlをレンダリングし、入力内容を維持
            return render_template('update.html', post=post, title=title, content=content)


        elif action == 'update':
            # 記事更新処理
            if not title or not content:
                flash('タイトルとコンテンツは必須です。', 'danger')
                return render_template('update.html', post=post)

            try:
                post.title = title
                post.content = content
                
                # 1. 画像削除チェック
                if request.form.get('delete_image'):
                    if post.public_id:
                        delete_image_from_cloudinary(post.public_id)
                    post.public_id = None
                
                # 2. 新しい画像アップロードチェック
                image_file = request.files.get('image')
                if image_file and image_file.filename != '':
                    # 既存のpublic_idを渡して上書きアップロード（または新規アップロード）
                    new_public_id = upload_image_to_cloudinary(image_file.stream, post.public_id)
                    if new_public_id:
                        post.public_id = new_public_id
                    else:
                        # Cloudinaryエラーの場合、エラーメッセージは既にフラッシュされている
                        return render_template('update.html', post=post) # 処理を中断

                db.session.commit()
                flash('記事が正常に更新されました。', 'success')
                return redirect(url_for('view', post_id=post.id))
            
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"記事更新DBエラー: {e}")
                flash('記事の更新中にエラーが発生しました。', 'danger')
                return render_template('update.html', post=post)

    # GETリクエスト
    # update.htmlでは、request.form.*をチェックし、それがなければpost.*を表示する
    return render_template('update.html', post=post)


@app.route('/<int:post_id>/delete', methods=['POST'])
@login_required
def delete(post_id):
    """記事削除処理"""
    post = Post.query.get_or_404(post_id)
    
    # 投稿者または管理者のみが削除可能
    if post.user_id != session['user_id'] and not User.query.get(session['user_id']).is_admin:
        flash('この記事を削除する権限がありません。', 'danger')
        return redirect(url_for('view', post_id=post.id))

    try:
        # Cloudinaryから画像を削除
        if post.public_id:
            delete_image_from_cloudinary(post.public_id)
        
        db.session.delete(post)
        db.session.commit()
        flash('記事が正常に削除されました。', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"記事削除DBエラー: {e}")
        flash('記事の削除中にエラーが発生しました。', 'danger')
        return redirect(url_for('view', post_id=post.id))


# --- 認証関連 ---

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """ユーザー登録ページ"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('ユーザー名とパスワードは必須です。', 'danger')
            return render_template('signup.html')

        if User.query.filter_by(username=username).first():
            flash('このユーザー名は既に使われています。', 'danger')
            return render_template('signup.html', username=username)

        new_user = User(username=username)
        new_user.set_password(password)
        
        # 最初のユーザーを管理者に設定（任意）
        if User.query.count() == 0:
            new_user.is_admin = True

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('ユーザー登録が完了しました。ログインしてください。', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"ユーザー登録DBエラー: {e}")
            flash('ユーザー登録中にエラーが発生しました。', 'danger')

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """ログインページ"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            flash('ログインに成功しました。', 'success')
            
            # リダイレクト先 ('next'パラメータ) の処理
            next_url = request.args.get('next')
            if next_url and next_url.startswith('/'):
                return redirect(next_url)
            
            return redirect(url_for('index'))
        else:
            flash('無効なユーザー名またはパスワードです。', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    """ログアウト処理"""
    session.pop('user_id', None)
    session.pop('username', None)
    flash('ログアウトしました。', 'info')
    return redirect(url_for('index'))

@app.route('/account')
@login_required
def account():
    """アカウント設定ページ (ダミー)"""
    return render_template('account.html')

@app.route('/admin')
@admin_required
def admin():
    """管理者ダッシュボード (ダミー)"""
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/forgot_password')
def forgot_password():
    """パスワード再設定リクエスト (ダミー)"""
    if request.method == 'POST':
        flash('パスワード再設定のリンクがメールで送信されました (ダミー)。', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password')
def reset_password():
    """パスワードリセット実行 (ダミー)"""
    return render_template('reset_password.html')


# --- エラーハンドリング ---

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.route('/error_page_test')
def error_page_test():
    """意図的に503エラーページを表示するテストルート"""
    return render_template('error_page.html'), 503


# --- アプリケーション実行 ---

if __name__ == '__main__':
    # ローカル開発環境用
    with app.app_context():
        # ローカルSQLiteの場合のみdb.create_all()を実行 (Render環境ではrender-build.shが実行)
        if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
            db.create_all()
    app.run(debug=True)
