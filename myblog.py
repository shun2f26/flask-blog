import os
import sys
import time
from io import BytesIO
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
    Cloudinaryが利用可能かチェックし、可能であれば画像URLを生成して返す。
    利用不可な場合は空の文字列を返す。
    """
    if not public_id or not CLOUDINARY_AVAILABLE:
        return ""
    
    # デフォルトの画像変換オプションを適用
    kwargs.setdefault('width', 600)
    kwargs.setdefault('crop', 'limit')
    kwargs.setdefault('fetch_format', 'auto')
    kwargs.setdefault('quality', 'auto')
    
    return cloudinary.utils.cloudinary_url(public_id, resource_type="image", **kwargs)[0]

def get_safe_cloudinary_video_url(public_id, **kwargs):
    """
    Cloudinaryが利用可能かチェックし、可能であれば動画URLを生成して返す。
    利用不可な場合は空の文字列を返す。
    """
    if not public_id or not CLOUDINARY_AVAILABLE:
        return ""
        
    # 動画URLの生成
    kwargs.setdefault('format', 'mp4') # ブラウザ互換性のためにmp4を推奨
    
    return cloudinary.utils.cloudinary_url(public_id, resource_type="video", **kwargs)[0]

def delete_cloudinary_media(public_id, resource_type="image"):
    """Cloudinaryから指定されたメディアを削除する"""
    if CLOUDINARY_AVAILABLE and public_id:
        try:
            # uploader は CLOUDINARY_AVAILABLE が True のときのみ安全にアクセスされる
            result = cloudinary.uploader.destroy(public_id, resource_type=resource_type)
            if result.get('result') == 'ok':
                print(f"Cloudinary {resource_type} deleted successfully: {public_id}")
                return True
            else:
                print(f"Cloudinary deletion failed for {public_id} ({resource_type}): {result.get('result')}", file=sys.stderr)
                return False
        except Exception as e:
            print(f"Error deleting Cloudinary {resource_type} {public_id}: {e}", file=sys.stderr)
            return False
    return False

# Flaskアプリのインスタンス作成
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# --- アプリ設定 ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'my_default_secret_key')

# Heroku / Render 互換性のためのURL修正ロジック (PostgreSQL対応)
uri = os.environ.get('DATABASE_URL')
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
    
# RenderではDATABASE_URLが設定されることを想定。ローカルではsqliteをフォールバックとして使用。
app.config['SQLALCHEMY_DATABASE_URI'] = uri if uri else 'sqlite:///myblog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ---------------------------------------------
# ★追加: セッション非アクティブタイムアウトの設定 (30分)
# ---------------------------------------------
SESSION_INACTIVITY_TIMEOUT = timedelta(minutes=30) 
app.config['PERMANENT_SESSION_LIFETIME'] = SESSION_INACTIVITY_TIMEOUT # セッション自体の寿命も設定

# --- SQLAlchemy/Migrate / WTF の遅延初期化 (Lazy Init) ---
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()

# シークレットキーはデバッグモード以外では必須です
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
    """現在の日本時間 (JST) を返すヘルパー関数 (タイムゾーンアウェア)"""
    return datetime.now(timezone(timedelta(hours=9)))

# --- カスタムJinjaフィルターの定義と登録 ---
def datetimeformat(value, format_string='%Y年%m月%d日 %H:%M'):
    """
    日付/時刻オブジェクトを指定された形式の文字列にフォーマットするフィルター。
    JST (UTC+9) に対応。
    """
    if value is None:
        return "日付なし"
        
    # タイムゾーン情報がない場合は、アプリケーションのデフォルト（JST）と見なす
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        # DBに保存されたDateTimeオブジェクトには通常tzinfoがないため、JSTとして扱う
        jst = timezone(timedelta(hours=9))
        # データベースから取得したnaive datetimeをJSTとして設定
        try:
            value = value.replace(tzinfo=jst)
        except ValueError:
             # 例外処理: 既にtzinfoがある場合など
            pass

    return value.strftime(format_string)

# Jinja環境に 'datetimeformat' フィルターとして登録
app.jinja_env.filters['datetimeformat'] = datetimeformat


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
    """記事モデル (修正: public_idを画像と動画で分割)"""
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    # ★修正: 画像専用のCloudinary Public ID
    image_public_id = db.Column(db.String(100), nullable=True) 
    # ★追加: 動画専用のCloudinary Public ID
    video_public_id = db.Column(db.String(100), nullable=True) 
    created_at = db.Column(db.DateTime, nullable=False, default=now) 
    user_id = db.Column(db.Integer, db.ForeignKey('blog_users.id'), nullable=False)
    
    # 記事に紐づくコメント (Post -> Comment)
    comments = relationship('Comment', backref='post', lazy='dynamic', cascade="all, delete-orphan") 

    def __repr__(self):
        return f"Post('{self.title}', '{self.created_at}')"

class Comment(db.Model):
    """コメントモデル (匿名投稿対応)"""
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    # ログインユーザーのID (匿名の場合はNoneを許可)
    author_id = db.Column(db.Integer, db.ForeignKey('blog_users.id'), nullable=True) 
    # 匿名コメント用の名前（ログインユーザーの場合もユーザー名が入る）
    name = db.Column(db.String(50), nullable=False) # ニックネームは必須とする
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now) # 投稿日時

    # リレーションは Post モデル側で定義済み
    # author = relationship('User', backref='user_comments') # UserモデルとCommentモデルが関連付けられる

    def __repr__(self):
        return f"Comment('{self.name}', Post ID: {self.post_id}, User ID: {self.author_id})"


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
    """記事投稿・編集用のフォームクラス (画像と動画を分割)"""
    title = StringField('タイトル', validators=[DataRequired(), Length(min=1, max=100)])
    content = TextAreaField('本文', validators=[DataRequired()])
    
    # ★修正: 画像専用フィールド
    image = FileField('画像をアップロード (任意)', validators=[
        FileAllowed(['jpg', 'png', 'jpeg', 'gif'], '画像ファイル (JPG, PNG, GIF) のみアップロードできます')
    ])
    
    # ★追加: 動画専用フィールド
    video = FileField('動画をアップロード (任意)', validators=[
        FileAllowed(['mp4', 'mov', 'avi', 'webm'], '動画ファイル (MP4, MOV, AVI, WEBM) のみアップロードできます')
    ])
    
    submit = SubmitField('更新')

class CommentForm(FlaskForm):
    """コメント投稿用のフォームクラス (匿名投稿対応)"""
    # 匿名ユーザー向けの名前フィールド (ログイン/非ログインに関わらず必須)
    name = StringField('ニックネーム', 
                       validators=[DataRequired(message='ニックネームは必須です。'), 
                                   Length(min=1, max=50, message='ニックネームは1文字以上50文字以内で入力してください。')])
    content = TextAreaField('コメント', validators=[DataRequired(message='コメント内容は必須です。')])
    submit = SubmitField('コメントを送信')

class RequestResetForm(FlaskForm):
    """パスワードリセット要求用のフォームクラス"""
    username = StringField('ユーザー名', validators=[DataRequired()])
    submit = SubmitField('パスワードリセットに進む') # 文言を変更

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
        'get_cloudinary_url': get_safe_cloudinary_url,       # 画像専用ヘルパー関数を注入
        'get_cloudinary_video_url': get_safe_cloudinary_video_url # 動画専用ヘルパー関数を注入
    }

@login_manager.user_loader
def load_user(user_id):
    """Flask-LoginがセッションからユーザーIDをロードするためのコールバック"""
    return db.session.get(User, int(user_id))

@app.route('/download/<path:public_id>', methods=['GET'])
@login_required # ダウンロードはログインユーザーに限定
def download_file(public_id):
    """
    Cloudinaryに保存されているファイルをストリーミングダウンロードします。
    requestsを使ってファイルをチャンクに分け、メモリ効率を高めます。
    public_idは、'uploads/image_name.jpg' のようなパス全体を受け取ります。
    """
    # 実際には、ここで post_id などを使って、
    # ユーザーがそのファイルをダウンロードする権限があるかを確認するロジックが必要です。
    # 例: post = Post.query.filter_by(public_id=public_id).first()
    # if not post or post.author != current_user:
    #     flash('このファイルをダウンロードする権限がありません。', 'danger')
    #     return redirect(url_for('admin'))
    
    try:
        # 1. Cloudinary APIを使用してファイルの情報を取得
        resource_info = cloudinary.api.resource(public_id, all=True)
        
        if not resource_info or 'url' not in resource_info:
            flash('指定されたファイルが見つかりません。', 'danger')
            return redirect(url_for('admin'))

        file_url = resource_info['url']
        original_filename = resource_info.get('original_filename', public_id.split('/')[-1])
        
        # Cloudinaryのフォーマット情報から拡張子を取得し、元のファイル名に追加
        content_format = resource_info.get('format', None)
        if content_format and not original_filename.lower().endswith(f".{content_format.lower()}"):
             original_filename = f"{original_filename}.{content_format}"
        
        # 2. ファイルをストリーミングダウンロード開始
        # stream=Trueを設定し、ファイル全体をメモリにロードしないようにする
        response = requests.get(file_url, stream=True)
        
        if response.status_code != 200:
            flash('ファイルの取得中にエラーが発生しました。', 'danger')
            return redirect(url_for('admin'))

        # 3. ジェネレータ関数を定義して、チャンクごとにデータを送信
        def generate():
            # iter_content()を使って、requestsの応答をチャンクに分割
            for chunk in response.iter_content(chunk_size=4096):
                if chunk: # フィルタリングアウト keep-alive chunks
                    yield chunk
        
        # FlaskのResponseオブジェクトを使ってストリーミングレスポンスを作成
        # Content-Dispositionヘッダーを設定してダウンロード時のファイル名を指定
        return Response(
            generate(),
            mimetype=response.headers.get('Content-Type', 'application/octet-stream'),
            headers={
                "Content-Disposition": f"attachment; filename=\"{original_filename}\"",
                # ファイルサイズがわかっている場合はContent-Lengthを設定すると良い
                "Content-Length": response.headers.get('Content-Length')
            }
        )

    except cloudinary.api.NotFound:
        flash('指定された public_id のファイルはCloudinaryに見つかりませんでした。', 'danger')
        return redirect(url_for('admin'))
    except Exception as e:
        # 詳細なエラーはログに記録
        print(f"ファイルダウンロードエラー: {e}")
        flash('ファイルダウンロード中に予期せぬエラーが発生しました。', 'danger')
        return redirect(url_for('admin'))


# ---------------------------------------------
# ★追加: セッション非アクティブタイムアウト処理
# ---------------------------------------------
@app.before_request
def before_request_session_check():
    """
    ユーザーが非アクティブな状態が続いた場合に自動的にログアウトさせる。
    すべてのアクティビティでチェックを行い、タイムアウト後はログインページにリダイレクト。
    """
    if current_user.is_authenticated:
        current_time = now() 
        last_activity_str = session.get('last_activity')
        
        # 最後に活動した時刻をセッションから取得
        if last_activity_str:
            # 文字列からdatetimeオブジェクトに変換
            try:
                # fromisoformatはタイムゾーン情報を含む文字列を正しくパース
                last_activity = datetime.fromisoformat(last_activity_str)
            except ValueError:
                # パースエラーの場合は、安全のためにログアウトせず、現在の時刻をセット
                last_activity = current_time 

            # タイムアウトチェック
            if (current_time - last_activity) > SESSION_INACTIVITY_TIMEOUT:
                # Flask-Loginのログアウト処理
                logout_user() 
                # セッションから活動時刻を削除
                session.pop('last_activity', None) 
                
                flash('非アクティブな状態が続いたため、自動的にログアウトしました。', 'info')
                
                # リダイレクト後のページをログイン前に試みていたページに設定
                return redirect(url_for('login', next=request.path))

        # ログイン継続中の場合、最後に活動した時刻を更新
        # タイムゾーン情報を含めてISOフォーマットの文字列で保存
        session['last_activity'] = current_time.isoformat()
        
    # ログインしていないユーザーの場合、過去のセッション情報をクリア
    elif 'last_activity' in session:
        session.pop('last_activity', None)


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
    # 修正: Post.created_at.desc() に変更
    posts = db.session.execute(db.select(Post).order_by(Post.created_at.desc())).scalars().all()
    return render_template('index.html', title='ホーム', posts=posts)


# -----------------------------------------------
# 公開ブログ閲覧ページとコメント機能
# -----------------------------------------------

@app.route("/blog/<username>")
def user_blog(username):
    """特定のユーザーの公開ブログページ"""
    target_user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()

    if not target_user:
        flash(f'ユーザー "{username}" は見つかりませんでした。', 'danger')
        return redirect(url_for('index'))

    # 修正: Post.created_at.desc() に変更
    posts = db.session.execute(
        db.select(Post)
        .filter_by(user_id=target_user.id)
        .order_by(Post.created_at.desc())
    ).scalars().all()

    return render_template('user_blog.html',
                           title=f'{username} のブログ',
                           target_user=target_user,
                           posts=posts)

@app.route('/view/<int:post_id>')
def view(post_id):
    """個別の記事とコメントを表示するページ"""
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)

    # コメントフォームをインスタンス化
    comment_form = CommentForm()
    
    # 記事に紐づくコメントを日時順で取得
    comments = db.session.execute(
        post.comments.order_by(Comment.created_at.asc())
    ).scalars().all()

    # ログインユーザーがフォームにアクセスした場合、名前フィールドにユーザー名を設定（任意）
    if current_user.is_authenticated:
        # 匿名コメントフォームにログインユーザー名を設定して手間を減らす
        comment_form.name.data = current_user.username
        
    return render_template('view.html', 
                           post=post, 
                           title=post.title, 
                           comments=comments, # コメントリストを渡す
                           comment_form=comment_form) # フォームを渡す

@app.route('/comment/<int:post_id>', methods=['POST'])
def post_comment(post_id):
    """コメント投稿処理"""
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)

    form = CommentForm()

    if form.validate_on_submit():
        comment_content = form.content.data
        comment_name = form.name.data # 匿名/ログインに関わらずこの名前を使用
        author_id = None

        if current_user.is_authenticated:
            # ログイン済みユーザーの場合、author_idをセット
            author_id = current_user.id
            # 匿名投稿を許可するため、nameフィールドはユーザー入力の値をそのまま使用（またはユーザー名で上書きしても良いが、ここでは入力値を尊重）
            
        elif not comment_name:
            # 匿名ユーザーの場合、nameフィールドはフォームバリデーションで必須チェック済みだが、念のため。
            flash('コメントを投稿するにはニックネームが必要です。', 'danger')
            return redirect(url_for('view', post_id=post_id))

        new_comment = Comment(
            post_id=post_id,
            author_id=author_id,
            name=comment_name,
            content=comment_content,
            created_at=now()
        )
        
        db.session.add(new_comment)
        db.session.commit()
        
        flash('コメントが正常に投稿されました。', 'success')
        # コメント欄までスクロールさせるためにフラグメントを設定
        return redirect(url_for('view', post_id=post_id) + '#comments')

    # バリデーションエラーがあった場合、フォームデータを保持して記事ページに戻る
    flash('コメントの投稿に失敗しました。すべての必須フィールドが入力されているか確認してください。', 'danger')
    return redirect(url_for('view', post_id=post_id))


@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required # ログインユーザーのみ削除可能とする
def delete_comment(comment_id):
    """コメント削除処理"""
    comment = db.session.get(Comment, comment_id)
    if not comment:
        flash('コメントが見つかりませんでした。', 'danger')
        # 削除前のページ（request.referrer）が不明な場合はインデックスにリダイレクト
        return redirect(request.referrer or url_for('index'))

    # 記事の作成者、管理者、またはコメントの作成者（ログインユーザーであるコメントのみ）のみ削除可能
    can_delete = False
    if comment.post.user_id == current_user.id:
        # 記事の作成者
        can_delete = True
    elif comment.author_id == current_user.id:
        # コメントの作成者
        can_delete = True
        
    if not can_delete and not current_user.is_admin:
        flash('このコメントを削除する権限がありません。', 'danger')
        abort(403)
        
    post_id = comment.post_id # リダイレクト用に取得
    
    db.session.delete(comment)
    db.session.commit()
    
    flash('コメントが削除されました。', 'success')
    return redirect(url_for('view', post_id=post_id) + '#comments')


# -----------------------------------------------
# 認証関連のルーティング
# -----------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    """ログインページ"""
    if current_user.is_authenticated:
        # ログイン後はコンテンツ管理ページへリダイレクト
        return redirect(url_for('admin'))

    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()

        if user and user.check_password(password):
            login_user(user, remember=form.remember_me.data)
            
            # ★変更: ログイン成功時、セッションに最終活動時刻を記録
            session['last_activity'] = now().isoformat()
            
            next_page = request.args.get('next')
            flash(f'ログインに成功しました！ようこそ、{user.username}さん。', 'success')
            # ログイン後はコンテンツ管理ページへリダイレクト
            return redirect(next_page or url_for('admin'))
        else:
            flash('ユーザー名またはパスワードが正しくありません。', 'danger')

    return render_template('login.html', title='ログイン', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """新規ユーザー登録ページ"""
    if current_user.is_authenticated:
        return redirect(url_for('admin'))

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
    
    # ★変更: ログアウト時、セッションから最終活動時刻を削除
    session.pop('last_activity', None) 
    
    flash('ログアウトしました。', 'info')
    return redirect(url_for('index'))

# -----------------------------------------------
# パスワードリセット関連 (変更なし)
# -----------------------------------------------

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    パスワードリセット要求ページ: ユーザー名を検証し、即時リセットページへリダイレクト。
    メール送信ロジックは削除されました。
    """
    if current_user.is_authenticated:
        # ログインしている場合はコンテンツ管理ページへ
        return redirect(url_for('admin'))

    form = RequestResetForm()

    if form.validate_on_submit():
        user = db.session.execute(
            db.select(User).filter_by(username=form.username.data)
        ).scalar_one_or_none()

        if user:
            # メール送信ロジックを削除し、代わりにユーザーIDを含む即時リセットページへリダイレクト
            flash(f'ユーザー "{user.username}" のパスワードをリセットします。新しいパスワードを設定してください。', 'info')
            return redirect(url_for('reset_password_immediate', user_id=user.id))
        else:
            # ユーザーが見つからない場合
            flash('ユーザー名が見つかりませんでした。', 'danger')

    return render_template('forgot_password.html', title='パスワードを忘れた場合', form=form)


@app.route('/reset_password_immediate/<int:user_id>', methods=['GET', 'POST'])
def reset_password_immediate(user_id):
    """
    ユーザーIDを使用してパスワードを即時リセットするページ（トークン検証をスキップ）。
    """
    user = db.session.get(User, user_id)

    if not user:
        flash('無効なユーザーIDです。', 'danger')
        return redirect(url_for('login'))

    # 既にログインしている場合は、そのアカウントのリセットでない限りアクセスを拒否
    if current_user.is_authenticated and current_user.id != user_id:
        flash('別のアカウントのパスワードをリセットすることはできません。', 'danger')
        return redirect(url_for('admin'))
    
    # リセットフォームを表示する前にログアウトさせる（セキュリティ対策）
    # ただし、リセット処理後にログイン状態を保持したい場合はこの行をコメントアウト
    if current_user.is_authenticated:
        logout_user()

    form = ResetPasswordForm()

    if form.validate_on_submit():
        # パスワードを更新
        user.set_password(form.password.data)
        user.reset_token = None
        user.reset_token_expires = None
        db.session.commit()

        flash('パスワードが正常にリセットされました。新しいパスワードでログインしてください。', 'success')
        return redirect(url_for('login'))

    # テンプレートに必要な user_id と user_name を追加してレンダリング
    return render_template(
        'reset_password.html', 
        title=f'{user.username} のパスワードリセット', 
        form=form,
        user_id=user_id,    # フォームのアクション（url_for）用
        user_name=user.username # テンプレートの表示用
    )

# -----------------------------------------------
# 記事作成・編集・削除
# -----------------------------------------------

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    パスワードリセット要求ページ: ユーザー名を検証し、即時リセットページへリダイレクト。
    メール送信ロジックは削除されました。
    """
    if current_user.is_authenticated:
        # ログインしている場合はコンテンツ管理ページへ
        return redirect(url_for('admin'))

    form = RequestResetForm()

    if form.validate_on_submit():
        user = db.session.execute(
            db.select(User).filter_by(username=form.username.data)
        ).scalar_one_or_none()

        if user:
            # メール送信ロジックを削除し、代わりにユーザーIDを含む即時リセットページへリダイレクト
            flash(f'ユーザー "{user.username}" のパスワードをリセットします。新しいパスワードを設定してください。', 'info')
            return redirect(url_for('reset_password_immediate', user_id=user.id))
        else:
            # ユーザーが見つからない場合
            flash('ユーザー名が見つかりませんでした。', 'danger')

    return render_template('forgot_password.html', title='パスワードを忘れた場合', form=form)


@app.route('/reset_password_immediate/<int:user_id>', methods=['GET', 'POST'])
def reset_password_immediate(user_id):
    """
    ユーザーIDを使用してパスワードを即時リセットするページ（トークン検証をスキップ）。
    """
    user = db.session.get(User, user_id)

    if not user:
        flash('無効なユーザーIDです。', 'danger')
        return redirect(url_for('login'))

    # 既にログインしている場合は、そのアカウントのリセットでない限りアクセスを拒否
    if current_user.is_authenticated and current_user.id != user_id:
        flash('別のアカウントのパスワードをリセットすることはできません。', 'danger')
        return redirect(url_for('admin'))
    
    # リセットフォームを表示する前にログアウトさせる（セキュリティ対策）
    # ただし、リセット処理後にログイン状態を保持したい場合はこの行をコメントアウト
    if current_user.is_authenticated:
        logout_user()

    form = ResetPasswordForm()

    if form.validate_on_submit():
        # パスワードを更新
        user.set_password(form.password.data)
        user.reset_token = None
        user.reset_token_expires = None
        db.session.commit()

        flash('パスワードが正常にリセットされました。新しいパスワードでログインしてください。', 'success')
        return redirect(url_for('login'))

    # テンプレートに必要な user_id と user_name を追加してレンダリング
    return render_template(
        'reset_password.html', 
        title=f'{user.username} のパスワードリセット', 
        form=form,
        user_id=user_id,    # フォームのアクション（url_for）用
        user_name=user.username # テンプレートの表示用
    )

# -----------------------------------------------
# 記事作成・編集・削除 (大幅修正)
# -----------------------------------------------

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """新規記事投稿ページ (修正: 画像と動画のアップロードを分離)"""
    form = PostForm()

    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        
        image_file = request.files.get(form.image.name)
        video_file = request.files.get(form.video.name)
        
        image_public_id = None
        video_public_id = None
        upload_success = False

        # 画像アップロード処理
        if image_file and image_file.filename != '' and CLOUDINARY_AVAILABLE:
            try:
                upload_result = cloudinary.uploader.upload(
                    image_file, 
                    folder=f"flask_blog_images/{current_user.username}", 
                    resource_type="image"
                )
                image_public_id = upload_result.get('public_id')
                flash('画像が正常にアップロードされました。', 'success')
                upload_success = True
            except Exception as e:
                flash(f'画像のアップロード中にエラーが発生しました: {e}', 'danger')
                print(f"Cloudinary image upload error: {e}", file=sys.stderr)
        
        # 動画アップロード処理 (画像アップロードとは独立)
        if video_file and video_file.filename != '' and CLOUDINARY_AVAILABLE:
            try:
                upload_result = cloudinary.uploader.upload(
                    video_file, 
                    folder=f"flask_blog_videos/{current_user.username}", 
                    resource_type="video" # resource_typeをvideoに設定
                )
                video_public_id = upload_result.get('public_id')
                flash('動画が正常にアップロードされました。', 'success')
                upload_success = True
            except Exception as e:
                flash(f'動画のアップロード中にエラーが発生しました: {e}', 'danger')
                print(f"Cloudinary video upload error: {e}", file=sys.stderr)

        # メディアのアップロードが試行されなかった、または両方のアップロードに成功/失敗した場合
        if not upload_success and image_file.filename == '' and video_file.filename == '':
            flash('新しい記事が正常に投稿されました。', 'success')


        new_post = Post(title=title,
                        content=content,
                        user_id=current_user.id,
                        image_public_id=image_public_id, # ★変更
                        video_public_id=video_public_id, # ★追加
                        created_at=now()) 
        db.session.add(new_post)
        db.session.commit()
        
        return redirect(url_for('admin')) 

    return render_template('create.html', title='新規投稿', form=form)


@app.route('/update/<int:post_id>', methods=['GET', 'POST'])
@login_required
def update(post_id):
    """記事編集ページ (修正: 画像と動画の編集・削除を分離)"""
    post = db.session.get(Post, post_id)

    # 記事の作成者、または管理者のみ編集可能
    if not post or (post.user_id != current_user.id and not current_user.is_admin):
        flash('編集権限がありません、または記事が見つかりません。', 'danger')
        abort(403)

    form = PostForm(obj=post)

    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data

        delete_image = request.form.get('delete_image') == 'on'
        delete_video = request.form.get('delete_video') == 'on' # ★追加
        
        image_file = request.files.get(form.image.name)
        video_file = request.files.get(form.video.name) # ★追加
        
        media_action_performed = False

        # --- 1. 画像削除処理 ---
        if delete_image and post.image_public_id and CLOUDINARY_AVAILABLE:
            if delete_cloudinary_media(post.image_public_id, resource_type="image"):
                post.image_public_id = None
                flash('画像が削除されました。', 'info')
            else:
                flash('画像の削除に失敗しました。', 'danger')
            media_action_performed = True

        # --- 2. 動画削除処理 ---
        if delete_video and post.video_public_id and CLOUDINARY_AVAILABLE:
            if delete_cloudinary_media(post.video_public_id, resource_type="video"):
                post.video_public_id = None
                flash('動画が削除されました。', 'info')
            else:
                flash('動画の削除に失敗しました。', 'danger')
            media_action_performed = True

        # --- 3. 新規画像アップロード処理 ---
        elif image_file and image_file.filename != '' and CLOUDINARY_AVAILABLE:
            # 既存の画像を削除
            if post.image_public_id: 
                delete_cloudinary_media(post.image_public_id, resource_type="image")

            try:
                upload_result = cloudinary.uploader.upload(
                    image_file, 
                    folder=f"flask_blog_images/{current_user.username}",
                    resource_type="image"
                )
                post.image_public_id = upload_result.get('public_id')
                
                flash('新しい画像が正常にアップロードされました。', 'success')
            except Exception as e:
                flash(f'新しい画像のアップロード中にエラーが発生しました: {e}', 'danger')
                print(f"Cloudinary image upload error: {e}", file=sys.stderr)
            media_action_performed = True

        # --- 4. 新規動画アップロード処理 ---
        elif video_file and video_file.filename != '' and CLOUDINARY_AVAILABLE:
            # 既存の動画を削除
            if post.video_public_id: 
                delete_cloudinary_media(post.video_public_id, resource_type="video")

            try:
                upload_result = cloudinary.uploader.upload(
                    video_file, 
                    folder=f"flask_blog_videos/{current_user.username}",
                    resource_type="video" # resource_typeをvideoに設定
                )
                post.video_public_id = upload_result.get('public_id')
            
                flash('新しい動画が正常にアップロードされました。', 'success')
            except Exception as e:
                flash(f'新しい動画のアップロード中にエラーが発生しました: {e}', 'danger')
                print(f"Cloudinary video upload error: {e}", file=sys.stderr)
            media_action_performed = True
        
        # 5. メディア操作が行われず、記事の内容のみ更新された場合
        if not media_action_performed:
            flash('記事が正常に更新されました。', 'success')
        
        db.session.commit()
        
        return redirect(url_for('admin'))

    # GETリクエストの場合、またはバリデーションエラーの場合
    current_image_url = get_safe_cloudinary_url(post.image_public_id, width=300, crop="limit")
    # ★追加: 動画のURLも取得
    current_video_url = get_safe_cloudinary_video_url(post.video_public_id, width=300, crop="limit")


    return render_template('update.html',
                            post=post,
                            title='記事編集',
                            form=form,
                            current_image_url=current_image_url,
                            current_video_url=current_video_url) # ★追加


@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required
def delete(post_id):
    """記事削除処理 (修正: 画像と動画の両方を削除)"""
    post = db.session.get(Post, post_id)

    # 記事の作成者、または管理者のみ削除可能
    if not post or (post.user_id != current_user.id and not current_user.is_admin):
        flash('削除権限がありません、または記事が見つかりません。', 'danger')
        abort(403)

    # Cloudinaryから画像を削除
    if post.image_public_id and CLOUDINARY_AVAILABLE:
        delete_cloudinary_media(post.image_public_id, resource_type="image")
        
    # Cloudinaryから動画を削除 (★追加)
    if post.video_public_id and CLOUDINARY_AVAILABLE:
        delete_cloudinary_media(post.video_public_id, resource_type="video")

    # データベースから記事を削除 (カスケード削除によりコメントも削除されます)
    db.session.delete(post)
    db.session.commit()
    flash('記事が正常に削除されました。', 'success')

    # 常に管理ページへリダイレクト
    return redirect(url_for('admin'))


# -----------------------------------------------
# コンテンツ管理・管理者機能関連のルーティング (変更なし)
# -----------------------------------------------

@app.route('/admin')
@login_required
def admin():
    """
    全ログインユーザーのためのコンテンツ管理ビュー。（エンドポイント名: admin）
    管理者は全ユーザーのリストと全記事を見る。一般ユーザーは自分の記事のみ見る。
    """
    
    users = None
    
    if current_user.is_admin:
        # 管理者: 全ユーザーのデータと記事数を取得
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
            
        # 管理者は全記事も取得
        # 修正: Post.created_at.desc() に変更
        posts = db.session.execute(db.select(Post).order_by(Post.created_at.desc())).scalars().all()
        title = '管理者ダッシュボード'
        
    else:
        # 一般ユーザー: 自分の記事のみ取得
        # 修正: Post.created_at.desc() に変更
        posts = db.session.execute(
            db.select(Post)
            .filter_by(user_id=current_user.id)
            .order_by(Post.created_at.desc())
        ).scalars().all()
        
        title = f'{current_user.username} のコンテンツ管理'


    return render_template('admin.html',
                           users=users, # 管理者のみ使用
                           posts=posts, # ログインユーザーの記事一覧として使用
                           is_admin_view=current_user.is_admin, # テンプレートで出し分け用
                           title=title)


@app.route('/admin/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_admin(user_id):
    """指定したユーザーの管理者権限をトグルする (管理者専用)"""
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
# その他ユーティリティ (エラーハンドリングを含む) (変更なし)
# -----------------------------------------------

# エンドポイント名を 'db_clear' から 'db_clear_data' に変更
@app.route("/db_clear", methods=["GET"])
def db_clear_data():
    """データベースの全テーブルを削除し、再作成する（確認なし）"""
    try:
        with app.app_context():
            # セッションを閉じる
            db.session.close()
            
            # 生のSQLを使用してテーブルを強制削除 (PostgreSQLで特に必要)
            # db.drop_all() を使用する前に、念のため生のSQLで依存関係を考慮して削除
            # コメントテーブル、ユーザーテーブル、記事テーブル、Alembicテーブルの削除
            db.session.execute(text("DROP TABLE IF EXISTS comments CASCADE;"))
            db.session.execute(text("DROP TABLE IF EXISTS posts CASCADE;"))
            db.session.execute(text("DROP TABLE IF EXISTS blog_users CASCADE;"))
            db.session.execute(text("DROP TABLE IF EXISTS alembic_version CASCADE;"))
            
            db.session.commit() # 削除をコミット
            
            # 再度すべてのテーブルを作成
            db.create_all()
            
            flash("データベースの全データが削除され、テーブルが正常に再作成されました。", 'success')
            print("Database cleared and recreated successfully.")
            return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        error_message = f"データベースのクリーンアップ中にエラーが発生しました: {e}"
        print(error_message, file=sys.stderr)
        flash(error_message, 'danger')
        return redirect(url_for('index'))


# 修正: methods=["POST"] に変更し、内部のメソッドチェックとGETでの実行ロジックを削除しました。
@app.route("/db_reset", methods=["POST"])
def db_reset():
    """データベーステーブルのリセット（開発/テスト用）。POSTリクエストでのみ実行可能。"""
    # プロダクション環境では注意が必要
    try:
        with app.app_context():
            # **注意: db_clear と同じロジックをよりシンプルに実行**
            db.session.close()
            db.drop_all()
            
            if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgresql'):
                # PostgreSQLでalembic_versionテーブルの削除が必要になる場合がある
                db.session.execute(text("DROP TABLE IF EXISTS alembic_version CASCADE;"))
                db.session.commit()
                
            db.create_all()
                
            flash("データベースのテーブルが正常に削除・再作成されました。サインアップで管理者アカウントを作成してください。", 'success')
            return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        print(f"データベースリセット中にエラーが発生しました: {e}", file=sys.stderr)
        flash(f"データベースリセット中にエラーが発生しました: {e}", 'danger')
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

if __name__ == '__main__':
    # 開発環境で実行する場合の初期設定
    with app.app_context():
        # データベースが存在しない場合は作成
        if not os.path.exists('myblog.db'):
            db.create_all()
            print("SQLite database 'myblog.db' created.")
    
    app.run(debug=True)
