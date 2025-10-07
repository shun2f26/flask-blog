import os
import sys
import time
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from sqlalchemy.orm import relationship
from sqlalchemy import func, select
from sqlalchemy.sql import text
from datetime import datetime, timedelta, timezone

# WTForms関連のインポート
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
# ファイルアップロードのための新しいインポート
from flask_wtf.file import FileField, FileAllowed


# --- Cloudinary設定と依存性チェック ---
# 環境変数はRenderのEnvironment Variablesで設定されることを想定
CLOUD_NAME = os.environ.get('CLOUDINARY_CLOUD_NAME')
API_KEY = os.environ.get('CLOUDINARY_API_KEY')
API_SECRET = os.environ.get('CLOUDINARY_API_SECRET')

CLOUDINARY_AVAILABLE = False
cloudinary = None
try:
    # 依存関係がインストールされているか確認
    if CLOUD_NAME and API_KEY and API_SECRET:
        import cloudinary as actual_cloudinary # 実際のモジュールを別名でインポート
        import cloudinary.uploader
        import cloudinary.utils
        actual_cloudinary.config(
            cloud_name=CLOUD_NAME,
            api_key=API_KEY,
            api_secret=API_SECRET,
            secure=True
        )
        cloudinary = actual_cloudinary # グローバル変数に設定
        CLOUDINARY_AVAILABLE = True
        print("Cloudinary configuration successful.")
    else:
        # 環境変数が設定されていない場合
        print("Cloudinary environment variables are not fully set. Image features disabled.", file=sys.stderr)
except ImportError:
    # Cloudinaryモジュールがインストールされていない場合
    print("Cloudinary module not installed. Image features disabled.", file=sys.stderr)
except Exception as e:
    # その他の設定エラー
    print(f"Cloudinary configuration failed: {e}. Image features disabled.", file=sys.stderr)

# --- 画像URL生成の安全なヘルパー関数 ---
def get_safe_cloudinary_url(public_id, **kwargs):
    """
    Cloudinaryが利用可能かチェックし、可能であればURLを生成して返す。
    利用不可な場合は空の文字列を返す。
    """
    if not public_id or not CLOUDINARY_AVAILABLE:
        return ""
    
    # デフォルトの変換オプション
    kwargs.setdefault('width', 600)
    kwargs.setdefault('crop', 'limit')
    kwargs.setdefault('fetch_format', 'auto')
    kwargs.setdefault('quality', 'auto')
    
    # cloudinary.utils は CLOUDINARY_AVAILABLE が True のときのみ安全にアクセスされる
    return cloudinary.utils.cloudinary_url(public_id, **kwargs)[0]

def delete_cloudinary_image(public_id):
    """Cloudinaryから指定された画像を削除する"""
    if CLOUDINARY_AVAILABLE and public_id:
        try:
            result = cloudinary.uploader.destroy(public_id)
            if result.get('result') == 'ok':
                print(f"Cloudinary image deleted successfully: {public_id}")
                return True
            else:
                print(f"Cloudinary deletion failed for {public_id}: {result.get('result')}", file=sys.stderr)
                return False
        except Exception as e:
            print(f"Error deleting Cloudinary image {public_id}: {e}", file=sys.stderr)
            return False
    return False

# Flaskアプリのインスタンス作成
app = Flask(__name__)

# --- アプリ設定 ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'my_default_secret_key')

# Heroku / Render 互換性のためのURL修正ロジック (PostgreSQL対応)
uri = os.environ.get('DATABASE_URL')
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
    
# RenderではDATABASE_URLが設定されることを想定。ローカルではsqliteをフォールバックとして使用。
app.config['SQLALCHEMY_DATABASE_URI'] = uri if uri else 'sqlite:///myblog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- SQLAlchemy/Migrate / WTF の遅延初期化 (Lazy Init) ---
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()

# シークレットキーはデバッグモード以外では必須です
# app.secret_key は app.config['SECRET_KEY'] で設定済みのため、これは冗長だが残しておく
app.secret_key = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_blog') 

db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)
csrf.init_app(app)
# RenderのPostgreSQLデータベースと連携
migrate.init_app(app, db) 

login_manager.login_view = 'login'
login_manager.login_message = 'このページにアクセスするにはログインが必要です。'
login_manager.login_message_category = 'info'


# --- タイムゾーン設定 (日本時間) ---
def now():
    """現在の日本時間 (JST) を返すヘルパー関数"""
    return datetime.now(timezone(timedelta(hours=9)))

# --- モデル定義 ---

class User(UserMixin, db.Model):
    """ユーザーモデル"""
    __tablename__ = 'blog_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now)
    posts = relationship('Post', backref='author', lazy='dynamic', cascade="all, delete-orphan")

    reset_token = db.Column(db.String(256), nullable=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        """パスワードをハッシュ化して保存する"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """入力されたパスワードとハッシュを比較する"""
        return bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.username}', '{self.id}', admin={self.is_admin})"

class Post(db.Model):
    """記事モデル"""
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    public_id = db.Column(db.String(100), nullable=True) # Cloudinary Public ID
    create_at = db.Column(db.DateTime, nullable=False, default=now)
    user_id = db.Column(db.Integer, db.ForeignKey('blog_users.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.create_at}')"


# --- フォーム定義 ---

class RegistrationForm(FlaskForm):
    """新規ユーザー登録用のフォームクラス"""
    username = StringField('ユーザー名',
                            validators=[DataRequired(message='ユーザー名は必須です。'),
                                        Length(min=2, max=20, message='ユーザー名は2文字以上20文字以内で入力してください。')])

    password = PasswordField('パスワード',
                              validators=[DataRequired(message='パスワードは必須です。'),
                                          Length(min=6, message='パスワードは6文字以上で設定してください。')])

    confirm_password = PasswordField('パスワード（確認用）',
                                      validators=[DataRequired(message='パスワード確認は必須です。'),
                                                  EqualTo('password', message='パスワードが一致しません。')])

    submit = SubmitField('サインアップ')

    def validate_username(self, username):
        """ユーザー名の一意性を検証"""
        user = db.session.execute(db.select(User).filter_by(username=username.data)).scalar_one_or_none()
        if user:
            raise ValidationError('そのユーザー名はすでに使用されています。')

class LoginForm(FlaskForm):
    """ログイン用のフォームクラス"""
    username = StringField('ユーザー名', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('パスワード', validators=[DataRequired()])
    remember_me = BooleanField('ログイン状態を維持する')
    submit = SubmitField('ログイン')

class PostForm(FlaskForm):
    """記事投稿・編集用のフォームクラス (画像ファイルフィールドを追加)"""
    title = StringField('タイトル', validators=[DataRequired(), Length(min=1, max=100)])
    content = TextAreaField('本文', validators=[DataRequired()])
    # FileFieldはバリデーションでサイズチェックはしませんが、FileAllowedでMIMEタイプをチェックします
    image = FileField('画像をアップロード (任意)', validators=[
        FileAllowed(['jpg', 'png', 'jpeg', 'gif'], '画像ファイル (JPG, PNG, GIF) のみをアップロードできます')
    ])
    submit = SubmitField('投稿')

class RequestResetForm(FlaskForm):
    """パスワードリセット要求用のフォームクラス"""
    username = StringField('ユーザー名', validators=[DataRequired()])
    submit = SubmitField('リセットリンクを送信')

class ResetPasswordForm(FlaskForm):
    """パスワードリセット（新しいパスワード設定）用のフォームクラス"""
    password = PasswordField('新しいパスワード', validators=[DataRequired()])
    confirm_password = PasswordField('パスワード（確認用）', validators=[DataRequired(), EqualTo('password', message='パスワードが一致しません')])
    submit = SubmitField('パスワードをリセット')

# --- ユーザーローダーとコンテキストプロセッサ ---

@app.context_processor
def inject_globals():
    """Jinja2テンプレートにグローバル変数とヘルパーを注入します。"""

    return {
        'now': now,
        'CLOUDINARY_AVAILABLE': CLOUDINARY_AVAILABLE,
        'get_cloudinary_url': get_safe_cloudinary_url # 安全なヘルパー関数を注入
    }

@login_manager.user_loader
def load_user(user_id):
    """Flask-LoginがセッションからユーザーIDをロードするためのコールバック"""
    return db.session.get(User, int(user_id))

# --- デコレータ ---

def admin_required(f):
    """管理者権限が必要なルートのためのデコレータ"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('この操作には管理者権限が必要です。', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


# --- ルーティング ---

@app.route("/")
@app.route("/index")
def index():
    """ブログ記事一覧ページ (全ユーザーの最新記事)"""
    posts = db.session.execute(db.select(Post).order_by(Post.create_at.desc())).scalars().all()
    return render_template('index.html', title='ホーム', posts=posts)


# -----------------------------------------------
# 公開ブログ閲覧ページ
# -----------------------------------------------

@app.route("/blog/<username>")
def user_blog(username):
    """特定のユーザーの公開ブログページ"""
    target_user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()

    if not target_user:
        flash(f'ユーザー "{username}" は見つかりませんでした。', 'danger')
        return redirect(url_for('index'))

    posts = db.session.execute(
        db.select(Post)
        .filter_by(user_id=target_user.id)
        .order_by(Post.create_at.desc())
    ).scalars().all()

    return render_template('user_blog.html',
                           title=f'{username} のブログ',
                           target_user=target_user,
                           posts=posts)

@app.route('/view/<int:post_id>')
def view(post_id):
    """個別の記事を表示するページ"""
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)

    return render_template('view.html', post=post, title=post.title)


# -----------------------------------------------
# 認証関連のルーティング
# -----------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    """ログインページ"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()

        if user and user.check_password(password):
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            flash(f'ログインに成功しました！ようこそ、{user.username}さん。', 'success')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('ユーザー名またはパスワードが正しくありません。', 'danger')

    return render_template('login.html', title='ログイン', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """新規ユーザー登録ページ"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        new_user = User(username=username)
        new_user.set_password(password)

        # 最初のユーザーを管理者にする
        is_first_user = db.session.execute(db.select(User).limit(1)).scalar_one_or_none() is None

        if is_first_user:
            new_user.is_admin = True
            flash(f'システム管理アカウントが作成されました: {username}! ログインしてください。', 'success')
        else:
            flash(f'アカウントが作成されました: {username}! ログインしてください。', 'success')

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('signup.html', title='サインアップ', form=form)


@app.route('/logout')
@login_required
def logout():
    """ログアウト処理"""
    logout_user()
    flash('ログアウトしました。', 'info')
    return redirect(url_for('index'))

# -----------------------------------------------
# パスワードリセット関連 (ダミー実装)
# -----------------------------------------------

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """パスワードリセット要求ページ"""
    form = RequestResetForm()

    if form.validate_on_submit():
        flash(f'ユーザー名 "{form.username.data}" にリセットリンクを送信しました。(※ダミー)', 'info')
        # TODO: 実際にはリセットトークンを生成し、メールを送信する
        return redirect(url_for('login'))

    return render_template('forgot_password.html', title='パスワードを忘れた場合', form=form)


@app.route('/reset_password/<path:token>', methods=['GET', 'POST'])
def reset_password(token):
    """パスワードリセット実行ページ"""
    # TODO: 実際にはここでトークンの検証を行う
    form = ResetPasswordForm()

    if form.validate_on_submit():
        flash('パスワードが正常にリセットされました。新しいパスワードでログインしてください。(※ダミー)', 'success')
        # TODO: 実際にはここでユーザーのパスワードを更新する
        return redirect(url_for('login'))

    print(f"Received reset token: {token}", file=sys.stderr)

    return render_template('reset_password.html', title='パスワードリセット', form=form)


# -----------------------------------------------
# ユーザー専用管理画面
# -----------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    """ログインユーザー専用の記事管理画面"""
    posts = db.session.execute(
        db.select(Post)
        .filter_by(user_id=current_user.id)
        .order_by(Post.create_at.desc())
    ).scalars().all()

    return render_template('dashboard.html',
                           title=f'{current_user.username} のダッシュボード',
                           posts=posts)


# -----------------------------------------------
# 記事作成・編集・削除
# -----------------------------------------------

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """新規記事投稿ページ (create.htmlを使用)"""
    form = PostForm()

    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        
        image_file = request.files.get(form.image.name)
        public_id = None
        
        if image_file and image_file.filename != '' and CLOUDINARY_AVAILABLE:
            try:
                # Cloudinaryにアップロード
                upload_result = cloudinary.uploader.upload(
                    image_file, 
                    folder=f"flask_blog_images/{current_user.username}", # ユーザーごとにフォルダ分け
                    resource_type="image"
                )
                public_id = upload_result.get('public_id')
                flash('記事と画像が正常に投稿されました。', 'success')
            except Exception as e:
                flash(f'画像のアップロード中にエラーが発生しました: {e}', 'danger')
                print(f"Cloudinary upload error: {e}", file=sys.stderr)
        
        if not public_id:
             # 画像のアップロードが試みられなかった、またはアップロードに失敗した場合
             flash('新しい記事が正常に投稿されました。', 'success')

        new_post = Post(title=title,
                        content=content,
                        user_id=current_user.id,
                        public_id=public_id,
                        create_at=now())
        db.session.add(new_post)
        db.session.commit()
        
        return redirect(url_for('dashboard'))

    return render_template('create.html', title='新規投稿', form=form)


@app.route('/update/<int:post_id>', methods=['GET', 'POST'])
@login_required
def update(post_id):
    """記事編集ページ (update.htmlを使用)"""
    post = db.session.get(Post, post_id)

    if not post or (post.user_id != current_user.id and not current_user.is_admin):
        flash('編集権限がありません、または記事が見つかりません。', 'danger')
        abort(403)

    form = PostForm(obj=post)

    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data

        # フォームデータから画像削除のチェックボックスを取得
        delete_image = request.form.get('delete_image') == 'on'
        # request.files から新しいファイルオブジェクトを取得
        image_file = request.files.get(form.image.name)
        
        image_action_performed = False

        # 1. 画像削除処理
        if delete_image and post.public_id and CLOUDINARY_AVAILABLE:
            if delete_cloudinary_image(post.public_id):
                post.public_id = None
                flash('画像が削除されました。', 'info')
                image_action_performed = True
            else:
                flash('画像の削除に失敗しました。', 'danger')

        # 2. 新規画像アップロード処理
        if image_file and image_file.filename != '' and CLOUDINARY_AVAILABLE:
            
            # 既存の画像があれば削除（新しい画像をアップロードする場合は置き換え）
            if post.public_id: 
                delete_cloudinary_image(post.public_id)

            try:
                # 新しい画像をアップロード
                upload_result = cloudinary.uploader.upload(
                    image_file, 
                    folder=f"flask_blog_images/{current_user.username}",
                    resource_type="image"
                )
                post.public_id = upload_result.get('public_id')
                flash('新しい画像が正常にアップロードされました。', 'success')
                image_action_performed = True
            except Exception as e:
                flash(f'新しい画像のアップロード中にエラーが発生しました: {e}', 'danger')
                print(f"Cloudinary upload error: {e}", file=sys.stderr)
                # アップロード失敗時はpublic_idを更新しない

        
        if not image_action_performed:
            flash('記事が正常に更新されました。', 'success')
        

        db.session.commit()
        
        # リダイレクト先を決定
        if current_user.is_admin and post.user_id != current_user.id:
            return redirect(url_for('admin'))
        else:
            return redirect(url_for('dashboard'))

    # GETリクエストの場合、またはバリデーションエラーの場合
    current_image_url = get_safe_cloudinary_url(post.public_id, width=300, crop="limit")

    return render_template('update.html',
                           post=post,
                           title='記事編集',
                           form=form,
                           current_image_url=current_image_url)


@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required
def delete(post_id):
    """記事削除処理"""
    post = db.session.get(Post, post_id)

    target_redirect = 'dashboard'

    if not post or (post.user_id != current_user.id and not current_user.is_admin):
        flash('削除権限がありません、または記事が見つかりません。', 'danger')
        abort(403)

    if current_user.is_admin and post.user_id != current_user.id:
        target_redirect = 'admin'

    # Cloudinaryから画像を削除
    if post.public_id and CLOUDINARY_AVAILABLE:
        delete_cloudinary_image(post.public_id)

    # データベースから記事を削除
    db.session.delete(post)
    db.session.commit()
    flash('記事が正常に削除されました。', 'success')

    return redirect(url_for(target_redirect))


# -----------------------------------------------
# 管理者機能関連のルーティング
# -----------------------------------------------

@app.route('/admin')
@login_required
@admin_required
def admin():
    """管理者ダッシュボード: 全ユーザー管理と記事数の取得"""
    post_count_sq = db.session.query(
        Post.user_id,
        func.count(Post.id).label('post_count')
    ).group_by(Post.user_id).subquery()

    users_with_count_stmt = db.select(
        User,
        post_count_sq.c.post_count
    ).outerjoin(
        post_count_sq,
        User.id == post_count_sq.c.user_id
    ).order_by(User.created_at.desc())

    users_data = db.session.execute(users_with_count_stmt).all()

    users = []
    for user_obj, post_count in users_data:
        users.append({
            'user': user_obj,
            'post_count': post_count or 0,
        })

    return render_template('admin.html',
                           users=users,
                           title='管理者ダッシュボード')


@app.route('/admin/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_admin(user_id):
    """指定したユーザーの管理者権限をトグルする"""
    if user_id == current_user.id:
        flash('自分自身の管理者ステータスを変更することはできません。', 'danger')
        return redirect(url_for('admin'))

    user = db.session.get(User, user_id)
    if not user:
        flash('ユーザーが見つかりませんでした。', 'danger')
        return redirect(url_for('admin'))

    user.is_admin = not user.is_admin
    db.session.commit()

    if user.is_admin:
        flash(f'ユーザー "{user.username}" を管理者に設定しました。', 'success')
    else:
        flash(f'ユーザー "{user.username}" の管理者権限を解除しました。', 'info')

    return redirect(url_for('admin'))


# -----------------------------------------------
# その他ユーティリティ (エラーハンドリングを含む)
# -----------------------------------------------

@app.route("/db_reset", methods=["GET", "POST"])
def db_reset():
    """データベーステーブルのリセット（開発/テスト用）"""
    # プロダクション環境では注意が必要
    if request.method == 'POST' or request.args.get('confirm') == 'yes':
        try:
            with app.app_context():
                db.session.close()
                db.drop_all()
                db.create_all()
                if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgresql'):
                    # PostgreSQLでalembic_versionテーブルの削除が必要になる場合がある
                    db.session.execute(text("DROP TABLE IF EXISTS alembic_version CASCADE;"))
                    db.session.commit()
                flash("データベースのテーブルが正常に削除・再作成されました。サインアップで管理者アカウントを作成してください。", 'success')
                return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            print(f"データベースリセット中にエラーが発生しました: {e}", file=sys.stderr)
            flash(f"データベースリセット中にエラーが発生しました: {e}", 'danger')
            return redirect(url_for('index'))
    flash("データベースリセットを実行するには、POSTリクエストまたはURLに ?confirm=yes をつけてください。", 'danger')
    return redirect(url_for('index'))


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    # account.html をレンダリング
    return render_template('account.html', title='アカウント設定')

# カスタムエラーハンドラ

@app.errorhandler(404)
def not_found_error(error):
    """404エラーハンドラ"""
    return render_template('404.html', title='404 Not Found'), 404

@app.errorhandler(403)
def forbidden_error(error):
    """403エラーハンドラ (権限なし)"""
    return render_template('error_page.html', title='403 Forbidden', error_code=403, message='このリソースにアクセスする権限がありません。'), 403

@app.errorhandler(500)
def internal_error(error):
    """500エラーハンドラ (内部サーバーエラー)"""
    db.session.rollback()
    return render_template('error_page.html', title='サーバーエラー', error_code=500, message='サーバー内部でエラーが発生しました。しばらくしてからお試しください。'), 500

# GunicornなどのWSGIサーバーはこの 'app' オブジェクトをエクスポートして使用します。
