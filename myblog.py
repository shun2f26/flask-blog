import os
import requests
import json
from functools import wraps
from datetime import datetime

from flask import (
    Flask, 
    render_template, 
    request, 
    redirect, 
    url_for, 
    flash, 
    session, 
    abort, 
    jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy import create_engine, text as sa_text
from sqlalchemy.orm import sessionmaker
from sqlalchemy_utils import database_exists, create_database
import cloudinary
import cloudinary.uploader
import urllib.parse

# --- データベース設定 ---
# Render/Heroku環境からDATABASE_URLを取得
db_url = os.environ.get("DATABASE_URL")

if db_url:
    # PostgreSQL接続文字列をSQLAlchemy用に修正 (postgres:// -> postgresql://)
    db_url = db_url.replace("postgres://", "postgresql://", 1)
    # Render環境ではSSLmodeが必要な場合がある
    if "sslmode" not in db_url:
        db_url += "?sslmode=require"
else:
    # ローカル開発用 (SQLite)
    db_url = "sqlite:///blog.db"

# Flaskアプリの初期化
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "default-insecure-secret-key-for-local-dev")
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# データベースとセキュリティのインスタンス化
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- 外部サービス設定 ---
# Cloudinary設定
cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET"),
    secure=True
)

# Gemini API設定
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent"
GEMINI_MODEL = "gemini-2.5-flash-preview-05-20"


# --- データベースモデル ---

class User(db.Model):
    """ユーザーモデル"""
    __tablename__ = 'users' # PostgreSQL予約語 'user' を回避するため
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # パスワードハッシュの長さを256に設定 (bcryptのハッシュ長を考慮)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False)
    posts = db.relationship('Post', backref='author', lazy='dynamic')

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
    summary = db.Column(db.String(255)) # AIが生成する要約
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # 画像フィールド (Cloudinaryのpublic_idを保存)
    image_public_id = db.Column(db.String(255))

    @property
    def image_url(self):
        """Cloudinaryからセキュアな画像URLを生成するプロパティ"""
        if self.image_public_id:
            # 記事の画像として最適な変形を適用（例：幅800pxにクロップ）
            return cloudinary.url(self.image_public_id, width=800, crop="limit", secure=True)
        return None

# --- デコレータとヘルパー関数 ---

def login_required(f):
    """ログイン必須デコレータ"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('このページにアクセスするにはログインが必要です。', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """管理者権限必須デコレータ"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('管理者権限が必要です。', 'danger')
            return redirect(url_for('login', next=request.url))
        
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('管理者権限がありません。', 'danger')
            return redirect(url_for('index'))
            
        return f(*args, **kwargs)
    return decorated_function

# --- LLM API 呼び出し関数 ---

def call_gemini_api(prompt, system_instruction=None, json_schema=None):
    """Gemini APIを呼び出す汎用関数"""
    if not GEMINI_API_KEY:
        return {"error": "GEMINI_API_KEYが設定されていません。"}
    
    headers = {'Content-Type': 'application/json'}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "tools": [{"google_search": {}}], # Web検索を有効化
        "config": {}
    }

    if system_instruction:
        payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}
        
    if json_schema:
        payload["config"]["responseMimeType"] = "application/json"
        payload["config"]["responseSchema"] = json_schema

    try:
        response = requests.post(
            f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
            headers=headers,
            json=payload,
            timeout=30 # タイムアウトを設定
        )
        response.raise_for_status() # HTTPエラーを確認

        result = response.json()
        text_content = result['candidates'][0]['content']['parts'][0]['text']
        
        # JSONレスポンスの場合はパースを試みる
        if json_schema:
            try:
                return json.loads(text_content)
            except json.JSONDecodeError:
                return {"error": "AIからのレスポンスのJSONパースに失敗しました。"}
        
        return {"text": text_content}

    except requests.exceptions.Timeout:
        return {"error": "Gemini APIへのリクエストがタイムアウトしました。"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Gemini APIとの通信エラー: {e}"}
    except (IndexError, KeyError):
        return {"error": "Gemini APIからの予期せぬ応答構造です。"}


# --- ルーティング ---

@app.route('/')
def index():
    """ホーム/記事一覧ページ"""
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('index.html', posts=posts)

# --- 認証ルート ---

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """新規登録"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('ユーザー名とパスワードの両方が必要です。', 'danger')
            return render_template('signup.html')

        if User.query.filter_by(username=username).first():
            flash('そのユーザー名は既に使用されています。', 'danger')
            return render_template('signup.html', username=username)

        new_user = User(username=username)
        new_user.set_password(password)

        # 最初のユーザーを管理者に設定
        if User.query.count() == 0:
            new_user.is_admin = True

        db.session.add(new_user)
        try:
            db.session.commit()
            flash('登録が完了しました。ログインしてください。', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'データベースエラー: {e}', 'danger')
            return render_template('signup.html', username=username)

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """ログイン"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            
            # 管理者権限をセッションに保存
            session['is_admin'] = user.is_admin

            flash('ログインに成功しました。', 'success')
            
            # nextパラメータがあればそちらにリダイレクト
            next_url = request.args.get('next')
            if next_url and next_url.startswith('/'):
                return redirect(next_url)
            
            return redirect(url_for('index'))
        else:
            flash('無効なユーザー名またはパスワードです。', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """ログアウト"""
    session.clear()
    flash('ログアウトしました。', 'info')
    return redirect(url_for('index'))

@app.route('/forgot_password')
def forgot_password():
    """パスワードを忘れた場合のダミーページ"""
    flash('パスワード再設定機能は未実装です。', 'info')
    return render_template('forgot_password.html')

@app.route('/reset_password')
def reset_password():
    """パスワード再設定のダミーページ"""
    flash('パスワード再設定機能は未実装です。', 'info')
    return render_template('reset_password.html')

@app.route('/account')
@login_required
def account():
    """アカウント設定のダミーページ"""
    flash('アカウント設定ページです。', 'info')
    return render_template('account.html')


# --- 記事操作ルート ---

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """記事作成"""
    initial_title = request.form.get('title', '')
    initial_content = request.form.get('content', '')
    initial_summary = request.form.get('summary', '')

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        summary = request.form.get('summary')
        image_file = request.files['image']

        if not title or not content:
            flash('タイトルとコンテンツの両方が必要です。', 'danger')
            return render_template('create.html', initial_title=title, initial_content=content, initial_summary=summary)

        image_public_id = None
        if image_file and image_file.filename:
            try:
                # Cloudinaryにアップロード
                upload_result = cloudinary.uploader.upload(image_file, folder="myblog_uploads")
                image_public_id = upload_result['public_id']
            except Exception as e:
                flash(f'画像のアップロードに失敗しました: {e}', 'danger')
                return render_template('create.html', initial_title=title, initial_content=content, initial_summary=summary)

        new_post = Post(
            title=title, 
            content=content, 
            summary=summary,
            user_id=session['user_id'],
            image_public_id=image_public_id
        )

        db.session.add(new_post)
        try:
            db.session.commit()
            flash('記事が正常に作成されました。', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'データベースエラー: {e}', 'danger')
            # データベースエラー時もフォームデータを返す
            return render_template('create.html', initial_title=title, initial_content=content, initial_summary=summary)

    # GETリクエスト
    return render_template('create.html', initial_title=initial_title, initial_content=initial_content, initial_summary=initial_summary)


@app.route('/<int:post_id>/view')
def view(post_id):
    """記事詳細"""
    post = Post.query.get_or_404(post_id)
    return render_template('view.html', post=post)


@app.route('/<int:post_id>/update', methods=['GET', 'POST'])
@login_required
def update(post_id):
    """記事更新"""
    post = Post.query.get_or_404(post_id)
    
    # 権限チェック
    if post.user_id != session['user_id']:
        flash('この記事を編集する権限がありません。', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        # フォームからデータ取得
        title = request.form['title']
        content = request.form['content']
        summary = request.form.get('summary')
        image_file = request.files['image']
        delete_image = 'delete_image' in request.form
        
        # フォームデータが不完全な場合はエラー
        if not title or not content:
            flash('タイトルとコンテンツの両方が必要です。', 'danger')
            return render_template('update.html', post=post, initial_title=title, initial_content=content, initial_summary=summary)

        # 1. 画像削除の処理
        if delete_image and post.image_public_id:
            try:
                cloudinary.uploader.destroy(post.image_public_id)
                post.image_public_id = None
                flash('既存の画像が削除されました。', 'info')
            except Exception as e:
                flash(f'画像の削除に失敗しました: {e}', 'danger')

        # 2. 新しい画像のアップロード処理
        if image_file and image_file.filename:
            # 既存の画像があれば削除してからアップロード
            if post.image_public_id:
                try:
                    cloudinary.uploader.destroy(post.image_public_id)
                except Exception as e:
                    print(f"古い画像の削除中にエラー: {e}") # ログ出力のみ

            try:
                upload_result = cloudinary.uploader.upload(image_file, folder="myblog_uploads")
                post.image_public_id = upload_result['public_id']
                flash('新しい画像がアップロードされました。', 'success')
            except Exception as e:
                flash(f'新しい画像のアップロードに失敗しました: {e}', 'danger')
                return render_template('update.html', post=post, initial_title=title, initial_content=content, initial_summary=summary)

        # 3. 記事データの更新
        post.title = title
        post.content = content
        post.summary = summary
        
        try:
            db.session.commit()
            flash('記事が正常に更新されました。', 'success')
            return redirect(url_for('view', post_id=post.id))
        except Exception as e:
            db.session.rollback()
            flash(f'データベースエラー: {e}', 'danger')
            return render_template('update.html', post=post, initial_title=title, initial_content=content, initial_summary=summary)

    # GETリクエスト
    return render_template(
        'update.html', 
        post=post,
        initial_title=post.title, 
        initial_content=post.content, 
        initial_summary=post.summary
    )


@app.route('/<int:post_id>/delete', methods=['POST'])
@login_required
def delete(post_id):
    """記事削除"""
    post = Post.query.get_or_404(post_id)
    
    # 権限チェック
    if post.user_id != session['user_id']:
        flash('この記事を削除する権限がありません。', 'danger')
        return redirect(url_for('index'))

    # 画像をCloudinaryから削除
    if post.image_public_id:
        try:
            cloudinary.uploader.destroy(post.image_public_id)
        except Exception as e:
            print(f"Cloudinary画像の削除中にエラー: {e}") # ログ出力のみ

    db.session.delete(post)
    try:
        db.session.commit()
        flash('記事が正常に削除されました。', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'データベースエラー: {e}', 'danger')
        
    return redirect(url_for('index'))

# --- AIアシスタント機能ルート ---

@app.route('/api/generate_content', methods=['POST'])
@login_required
def generate_content():
    """AIによる記事本文の提案"""
    data = request.get_json()
    prompt_input = data.get('prompt', '最新のAI技術についてのブログ記事のアイデアをいくつか。')

    system_instruction = "あなたはプロのブログライターです。ユーザーが指定したテーマやキーワードに基づき、魅力的で詳細なブログ記事の本文（マークダウン形式、見出し含む）を生成してください。記事本文のみを返却し、挨拶やタイトルは含めないでください。"
    
    prompt = f"以下のテーマで、読者を惹きつけるブログ記事の本文を作成してください:\n\nテーマ: {prompt_input}"

    response = call_gemini_api(prompt, system_instruction=system_instruction)

    if 'error' in response:
        return jsonify({"success": False, "error": response['error']}), 500
    
    return jsonify({"success": True, "generated_text": response['text']})


@app.route('/api/generate_summary', methods=['POST'])
@login_required
def generate_summary():
    """AIによる要約の生成"""
    data = request.get_json()
    content = data.get('content', '')

    if not content or len(content) < 50:
        return jsonify({"success": False, "error": "コンテンツが短すぎて要約を生成できません。"}), 400

    json_schema = {
        "type": "OBJECT",
        "properties": {
            "summary": {"type": "STRING", "description": "記事の本文から生成された、SNSやメタディスクリプションに使用可能なキャッチーな要約。最大100文字程度。"}
        }
    }

    system_instruction = "あなたはプロのSEOライターです。提供されたブログ記事の本文を読み、読者の興味を引き、クリック率を高めるような、最大100文字程度のキャッチーな要約を生成してください。回答は必ず指定されたJSONスキーマに従ってください。"
    
    prompt = f"以下のブログ記事の本文を要約してください:\n\n本文: {content}"

    response = call_gemini_api(prompt, system_instruction=system_instruction, json_schema=json_schema)

    if 'error' in response:
        return jsonify({"success": False, "error": response['error']}), 500
    
    try:
        summary_text = response['summary']
        return jsonify({"success": True, "generated_summary": summary_text})
    except KeyError:
        return jsonify({"success": False, "error": "AIからのレスポンス形式が不正です。"}), 500


# --- 管理者ルート ---

@app.route('/admin')
@admin_required
def admin():
    """管理者ダッシュボード - ユーザー一覧を表示"""
    # ユーザーをID順に取得
    users = User.query.order_by(User.id).all()
    return render_template('admin.html', users=users)

@app.route('/admin/<int:user_id>', methods=['POST'])
@admin_required
def toggle_admin(user_id):
    """特定のユーザーの管理者権限をトグルする"""
    user = User.query.get_or_404(user_id)
    
    # 自分自身の権限は変更できないようにする
    if user.id == session['user_id']:
        flash('自分自身の管理者権限を変更することはできません。', 'danger')
        return redirect(url_for('admin'))

    # 権限を反転
    user.is_admin = not user.is_admin
    
    try:
        db.session.commit()
        action = "付与" if user.is_admin else "解除"
        flash(f'ユーザー {user.username} の管理者権限を{action}しました。', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'データベースエラーにより権限変更に失敗しました: {e}', 'danger')
        
    return redirect(url_for('admin'))


# --- エラーハンドリングルート（ダミーを含む） ---

@app.route('/error_page_test')
def error_page_test():
    """503エラーページのダミー表示"""
    return render_template('error_page.html', error_code='503', error_message='サービスが一時的に利用できません'), 503

@app.errorhandler(404)
def page_not_found(e):
    """404エラーハンドラ"""
    return render_template('404.html'), 404

# --- アプリケーション起動 ---

if __name__ == '__main__':
    # ローカル実行時のデータベース作成 (Renderではrender-build.shが担当)
    with app.app_context():
        if not database_exists(app.config['SQLALCHEMY_DATABASE_URI']):
            create_database(app.config['SQLALCHEMY_DATABASE_URI'])
        
        # モデルにテーブル情報がない場合は作成
        # Renderで既にdb.create_all()がビルド時に走っているため、ここではコメントアウト推奨
        # db.create_all() 
        
    app.run(debug=True)
