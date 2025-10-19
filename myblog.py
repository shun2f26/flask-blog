import os
import sys
import time
from io import BytesIO
from functools import wraps
# 修正: Responseとrequestsをインポートリストに追加
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, Response, render_template_string, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from sqlalchemy.orm import relationship
from sqlalchemy import func, select
from sqlalchemy.sql import text
from datetime import datetime, timedelta, timezone

# 追加: requestsはダウンロード機能に必要です
import requests

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
        import cloudinary.api # ★修正: API呼び出しのために明示的にインポート
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
app.config['CLOUDINARY_CLOUD_NAME'] = 'your_cloudinary_cloud_name'

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
# RenderのgreSQLデータベースと連携
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
    # 修正: 記事とのリレーションシップを明確に定義
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
    __tablename__ = 's' # ユーザー提供のテーブル名
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_public_id = db.Column(db.String(100), nullable=True) 
    video_public_id = db.Column(db.String(100), nullable=True) 
    created_at = db.Column(db.DateTime, nullable=False, default=now) 
    user_id = db.Column(db.Integer, db.ForeignKey('blog_users.id'), nullable=False)
    
    # 修正: 記事に紐づくコメント (backrefを'post'に設定)
    comments = relationship('Comment', backref='post', lazy='dynamic', cascade="all, delete-orphan") 

    def __repr__(self):
        return f"('{self.title}', '{self.created_at}')"

class Comment(db.Model):
    """コメントモデル (匿名投稿対応)"""
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    # ユーザー提供の外部キー名 ('s.id'はPostモデルのテーブル名)
    post_id = db.Column('post_id', db.Integer, db.ForeignKey('s.id'), nullable=False)
    # ログインユーザーのID (匿名の場合はNoneを許可)
    author_id = db.Column(db.Integer, db.ForeignKey('blog_users.id'), nullable=True) 
    name = db.Column(db.String(50), nullable=False) # ニックネームは必須とする
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now) # 投稿日時

    def __repr__(self):
        return f"Comment('{self.name}', Post ID: {self.post_id}, User ID: {self.author_id})"

# ====================================================================
# フォーム定義 (ユーザー提供の定義をそのまま使用)
# ====================================================================

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
    
    image = FileField('画像をアップロード (任意)', validators=[
        FileAllowed(['jpg', 'png', 'jpeg', 'gif'], '画像ファイル (JPG, PNG, GIF) のみアップロードできます')
    ])
    
    video = FileField('動画をアップロード (任意)', validators=[
        FileAllowed(['mp4', 'mov', 'avi', 'webm'], '動画ファイル (MP4, MOV, AVI, WEBM) のみアップロードできます')
    ])
    
    submit = SubmitField('更新')

class CommentForm(FlaskForm):
    """コメント投稿用のフォームクラス (匿名投稿対応)"""
    name = StringField('ニックネーム', 
                        validators=[DataRequired(message='ニックネームは必須です。'), 
                                     Length(min=1, max=50, message='ニックネームは1文字以上50文字以内で入力してください。')])
    content = TextAreaField('コメント', validators=[DataRequired(message='コメント内容は必須です。')])
    submit = SubmitField('コメントを送信')

class RequestResetForm(FlaskForm):
    """パスワードリセット要求用のフォームクラス"""
    username = StringField('ユーザー名', validators=[DataRequired()])
    submit = SubmitField('パスワードリセットに進む') 

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
        'get_cloudinary_url': get_safe_cloudinary_url,      # 画像専用ヘルパー関数を注入
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
    # 実際には、ここで _id などを使って、
    # ユーザーがそのファイルをダウンロードする権限があるかを確認するロジックが必要です。
    # 例:  = .query.filter_by(public_id=public_id).first()
    # if not  or .author != current_user:
    #     flash('このファイルをダウンロードする権限がありません。', 'danger')
    #     return redirect(url_for('admin'))
    
    if not CLOUDINARY_AVAILABLE:
        flash('ファイルストレージサービスが利用できません。', 'danger')
        return redirect(url_for('admin'))
    
    try:
        # 1. Cloudinary APIを使用してファイルの情報を取得
        # Cloudinary APIのインポートを冒頭で修正済み
        resource_info = cloudinary.api.resource(public_id, all=True)
        
        if not resource_info or 'url' not in resource_info:
            flash('指定されたファイルが見つかりません。', 'danger')
            return redirect(url_for('admin'))

        file_url = resource_info['url']
        
        # オリジナルファイル名を取得。タグがない場合は public_id の最後の部分を使用
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

# -----------------------------------------------
# 公開ページ
# -----------------------------------------------

@app.route("/")
@app.route("/index")
def index():
    """ブログ記事一覧ページ (全ユーザーの最新記事、検索、ページネーション)"""
    
    page = request.args.get('page', 1, type=int)
    query_text = request.args.get('q', '').strip()
    per_page = 5  # 1ページあたりの表示件数

    # 1. 初期クエリ: 全ての記事を新しい順に取得 (★修正されたクエリ構文)
    select_stmt = db.select(Post).order_by(Post.created_at.desc())
    
    # 2. 検索クエリがある場合、フィルタリングを追加
    if query_text:
        search_filter = or_(
            Post.title.contains(query_text),
            Post.content.contains(query_text)
        )
        select_stmt = select_stmt.where(search_filter)

    # 3. ページネーションを実行
    pagination = db.paginate(select_stmt, page=page, per_page=per_page, error_out=False)
    
    # テンプレートには 'posts' (記事リスト) と 'pagination' (ページ情報) を渡す
    return render_template(
        'index.html', 
        title='ホーム', 
        posts=pagination.items, 
        pagination=pagination
    )


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

    # 修正: .created_at.desc() に変更
    s = db.session.execute(
        db.select()
        .filter_by(user_id=target_user.id)
        .order_by(.created_at.desc())
    ).scalars().all()

    return render_template('user_blog.html',
                            title=f'{username} のブログ',
                            target_user=target_user,
                            s=s)

@app.route('/view/<int:_id>')
def view(_id):
    """
    記事の詳細ビュー。（エンドポイント名: view）
    """
    # 実際のアプリケーションではここでデータベースから記事を取得する
    #  = db.get__by_id(_id) 
    # public_id = .video_public_id # view.html で使用される変数
    
    # エラー回避のためのダミー値 (実際のアプリケーションでは不要)
    public_id = 'example_video_public_id' 
    
    # FIX: /view ルートでも config をテンプレートに渡します。
    return render_template('view.html',
                            post=post,
                            config=current_app.config
    )

@app.route('/comment/<int:_id>', methods=[''])
def _comment(_id):
    """コメント投稿処理"""
     = db.session.get(, _id)
    if not :
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
            return redirect(url_for('view', _id=_id))

        new_comment = Comment(
            _id=_id,
            author_id=author_id,
            name=comment_name,
            content=comment_content,
            created_at=now()
        )
        
        db.session.add(new_comment)
        db.session.commit()
        
        flash('コメントが正常に投稿されました。', 'success')
        # コメント欄までスクロールさせるためにフラグメントを設定
        return redirect(url_for('view', _id=_id) + '#comments')

    # バリデーションエラーがあった場合、フォームデータを保持して記事ページに戻る
    flash('コメントの投稿に失敗しました。すべての必須フィールドが入力されているか確認してください。', 'danger')
    return redirect(url_for('view', _id=_id))


@app.route('/delete_comment/<int:comment_id>', methods=[''])
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
    if comment..user_id == current_user.id:
        # 記事の作成者
        can_delete = True
    elif comment.author_id == current_user.id:
        # コメントの作成者
        can_delete = True
        
    if not can_delete and not current_user.is_admin:
        flash('このコメントを削除する権限がありません。', 'danger')
        abort(403)
        
    _id = comment._id # リダイレクト用に取得
    
    db.session.delete(comment)
    db.session.commit()
    
    flash('コメントが削除されました。', 'success')
    return redirect(url_for('view', _id=_id) + '#comments')


# -----------------------------------------------
# 認証関連のルーティング
# -----------------------------------------------

@app.route('/login', methods=['GET', ''])
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
        
        # フラッシュメッセージの制御用
        upload_image_success = False
        upload_video_success = False

        # 画像アップロード処理
        if image_file and image_file.filename != '' and CLOUDINARY_AVAILABLE:
            try:
                upload_result = cloudinary.uploader.upload(
                    image_file, 
                    folder=f"flask_blog_images/{current_user.username}", 
                    resource_type="image"
                )
                image_public_id = upload_result.get('public_id')
                upload_image_success = True
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
                upload_video_success = True
            except Exception as e:
                flash(f'動画のアップロード中にエラーが発生しました: {e}', 'danger')
                print(f"Cloudinary video upload error: {e}", file=sys.stderr)

        # 総合的な成功メッセージ
        if upload_image_success or upload_video_success:
             media_type = []
             if upload_image_success:
                 media_type.append('画像')
             if upload_video_success:
                 media_type.append('動画')
             flash(f'新しい記事とメディア({", ".join(media_type)})が正常に投稿されました。', 'success')
        else:
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
        # 画像削除がチェックされておらず、新しい画像ファイルが提供された場合
        if not delete_image and image_file and image_file.filename != '' and CLOUDINARY_AVAILABLE:
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
        # 動画削除がチェックされておらず、新しい動画ファイルが提供された場合
        if not delete_video and video_file and video_file.filename != '' and CLOUDINARY_AVAILABLE:
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
    # ★修正: ここでコードが途切れていた部分を完成させる
    current_image_url = get_safe_cloudinary_url(post.image_public_id) if post.image_public_id else None
    current_video_url = get_safe_cloudinary_video_url(post.video_public_id) if post.video_public_id else None
    
    # create.html を流用して編集フォームをレンダリング
    return render_template('create.html', 
                            title=f'記事の編集: {post.title}', 
                            form=form, 
                            post=post, # 既存の記事情報をテンプレートに渡す
                            current_image_url=current_image_url, # 現在の画像URL
                            current_video_url=current_video_url, # 現在の動画URL
                            is_edit=True) # 編集モードであることをテンプレートに伝える
                            
@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    """記事削除処理 (画像と動画の削除も含む)"""
    post = db.session.get(Post, post_id)

    # 記事の作成者、または管理者のみ削除可能
    if not post or (post.user_id != current_user.id and not current_user.is_admin):
        flash('削除権限がありません、または記事が見つかりません。', 'danger')
        abort(403)

    # Cloudinaryメディアの削除
    media_deleted = False
    if post.image_public_id:
        if delete_cloudinary_media(post.image_public_id, resource_type="image"):
            media_deleted = True
        
    if post.video_public_id:
        if delete_cloudinary_media(post.video_public_id, resource_type="video"):
            media_deleted = True

    # 記事と関連するコメントを削除
    db.session.delete(post)
    db.session.commit()

    if media_deleted:
        flash(f'記事 "{post.title}" と関連するメディアが正常に削除されました。', 'success')
    else:
        flash(f'記事 "{post.title}" が正常に削除されました。', 'success')

    return redirect(url_for('admin'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    # account.html をレンダリング
    return render_template('account.html', title='アカウント設定')
# -----------------------------------------------
# 管理・ダッシュボード
# -----------------------------------------------

@app.route('/admin')
@login_required
def admin():
    """コンテンツ管理ダッシュボード: 自分の記事の一覧を表示"""
    
    # --- START REAL DATABASE LOGIC ---
    # ログインユーザーの記事を最新順に取得
    # NOTE: Userモデルにid, Postモデルにuser_idとcreated_at, Commentモデルにidとpost_idが存在することを前提とする。
    posts = db.session.execute(
        db.select(Post)
        .filter_by(user_id=current_user.id)
        .order_by(Post.created_at.desc())
    ).scalars().all()

    # 各記事のコメント数を取得
    post_data = []
    for post in posts:
        # コメント数を効率的に取得
        comment_count = db.session.execute(
            db.select(db.func.count(Comment.id))
            .filter_by(post_id=post.id)
        ).scalar_one()
        post_data.append((post, comment_count))

    title = 'コンテンツ管理'
    
    total_users = 0
    total_posts = 0
    total_comments = 0
    
    # is_admin属性があることを仮定
    is_admin_user = current_user.is_admin 

    if is_admin_user:
        # 管理者権限の場合、全体の統計情報を取得
        try:
            total_users = db.session.execute(db.select(db.func.count(User.id))).scalar_one()
            total_posts = db.session.execute(db.select(db.func.count(Post.id))).scalar_one()
            total_comments = db.session.execute(db.select(db.func.count(Comment.id))).scalar_one()
        except Exception as e:
            # データベース接続やモデルが見つからないエラーの際は0を保持
            print(f"Error fetching admin stats: {e}", file=sys.stderr)
            flash('管理者統計情報の取得中にエラーが発生しました。', 'warning')
            pass
    # --- END REAL DATABASE LOGIC ---
    
    # -----------------------------------------------------------------
    # FIX: テンプレートで app.config にアクセスできるように、
    # 'config=current_app.config' を追加します。（これは以前の修正です）
    # -----------------------------------------------------------------
    return render_template('admin.html',
                            title=title,
                            post_data=post_data, # (Postオブジェクト, コメント数) のタプルリスト
                            total_users=total_users,
                            total_posts=total_posts,
                            total_comments=total_comments,
                            config=current_app.config  
    )
    

# -----------------------------------------------
# エラーハンドリング
# -----------------------------------------------

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html', title='ページが見つかりません'), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html', title='アクセス禁止'), 403

@app.errorhandler(413) # Payload Too Large
def payload_too_large_error(error):
    flash('アップロードされたファイルが大きすぎます。ファイルサイズの上限は100MBです。', 'danger')
    # 可能な限りアップロードを試みたページに戻る
    return redirect(request.referrer or url_for('admin'))

# -----------------------------------------------
# アプリケーションの初期化と実行
# -----------------------------------------------

# データベースの初期設定と管理者ユーザーの作成（開発環境でのみ推奨）
# 本番環境ではmigrateで対応
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

if __name__ == '__main__':
    # 開発環境で実行する場合
    print("Application is running. Navigate to /admin or /view/1 to test the link.")
    app.run(debug=True)


