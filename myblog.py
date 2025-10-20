import os
import sys
import time
from io import BytesIO
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, Response, render_template_string, current_app,send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from sqlalchemy.orm import relationship
from sqlalchemy import func, select, or_
from sqlalchemy.sql import text
from datetime import datetime, timedelta, timezone
import requests

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_wtf.file import FileField, FileAllowed

# --- Cloudinary設定と依存性チェック ---
CLOUD_NAME = os.environ.get('CLOUDINARY_CLOUD_NAME')
API_KEY = os.environ.get('CLOUDINARY_API_KEY')
API_SECRET = os.environ.get('CLOUDINARY_API_SECRET')

CLOUDINARY_AVAILABLE = False
cloudinary = None
try:
    if CLOUD_NAME and API_KEY and API_SECRET:
        import cloudinary as actual_cloudinary
        import cloudinary.uploader
        import cloudinary.utils
        import cloudinary.api
        actual_cloudinary.config(
            cloud_name=CLOUD_NAME,
            api_key=API_KEY,
            api_secret=API_SECRET,
            secure=True
        )
        cloudinary = actual_cloudinary
        CLOUDINARY_AVAILABLE = True
        print("Cloudinary configuration successful.")
    else:
        print("Cloudinary environment variables are not fully set. Image features disabled.", file=sys.stderr)
except ImportError:
    print("Cloudinary module not installed. Image features disabled.", file=sys.stderr)
except Exception as e:
    print(f"Cloudinary configuration failed: {e}. Image features disabled.", file=sys.stderr)

# --- 画像URL生成の安全なヘルパー関数 ---
def get_safe_cloudinary_url(public_id, **kwargs):
    if not public_id or not CLOUDINARY_AVAILABLE:
        return ""
    kwargs.setdefault('width', 600)
    kwargs.setdefault('crop', 'limit')
    kwargs.setdefault('fetch_format', 'auto')
    kwargs.setdefault('quality', 'auto')
    return cloudinary.utils.cloudinary_url(public_id, resource_type="image", **kwargs)[0]

def get_safe_cloudinary_video_url(public_id, **kwargs):
    if not public_id or not CLOUDINARY_AVAILABLE:
        return ""
    kwargs.setdefault('format', 'mp4')
    kwargs.setdefault('resource_type', 'video')
    kwargs.setdefault('type', 'upload')
    kwargs.setdefault('secure', True)
    kwargs.setdefault('transformation', [
        {'quality': 'auto:best'},
        {'fetch_format': 'auto'},
        {'flags': 'streaming'}
    ])
    return cloudinary.utils.cloudinary_url(public_id, **kwargs)[0]
    
def get_safe_cloudinary_video_thumbnail(public_id):
    if not public_id or not CLOUDINARY_AVAILABLE:
        return ""
    try:
        return cloudinary.utils.cloudinary_url(
            public_id,
            resource_type="video",
            format="jpg",
            transformation=[
                {'width': 400, 'crop': 'fill', 'gravity': 'auto'}
            ]
        )[0]
    except Exception as e:
        print(f"Video thumbnail generation failed: {e}", file=sys.stderr)
        return ""
    
def delete_cloudinary_media(public_id, resource_type="image"):
    if CLOUDINARY_AVAILABLE and public_id:
        try:
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

# Flask app
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.config['CLOUDINARY_CLOUD_NAME'] = 'your_cloudinary_cloud_name'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'my_default_secret_key')

# DB URL fix-up (Heroku -> SQLAlchemy)
uri = os.environ.get('DATABASE_URL')
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri if uri else 'sqlite:///myblog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

SESSION_INACTIVITY_TIMEOUT = timedelta(minutes=30)
app.config['PERMANENT_SESSION_LIFETIME'] = SESSION_INACTIVITY_TIMEOUT

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()

app.secret_key = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_blog')

db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)
csrf.init_app(app)
migrate.init_app(app, db)

login_manager.login_view = 'login'
login_manager.login_message = 'このページにアクセスするにはログインが必要です。'
login_manager.login_message_category = 'info'

# --- Time helpers ---
def now():
    return datetime.now(timezone(timedelta(hours=9)))

def datetimeformat(value, format_string='%Y年%m月%d日 %H:%M'):
    if value is None:
        return "日付なし"
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        jst = timezone(timedelta(hours=9))
        try:
            value = value.replace(tzinfo=jst)
        except Exception:
            pass
    return value.strftime(format_string)

app.jinja_env.filters['datetimeformat'] = datetimeformat

# --- Models ---
class User(UserMixin, db.Model):
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
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.username}', '{self.id}', admin={self.is_admin})"

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_public_id = db.Column(db.String(100), nullable=True)
    video_public_id = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now)
    user_id = db.Column(db.Integer, db.ForeignKey('blog_users.id'), nullable=False)
    comments = relationship('Comment', backref='post', lazy='dynamic', cascade="all, delete-orphan")

    def __repr__(self):
        return f"('{self.title}', '{self.created_at}')"

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('blog_users.id'), nullable=True)
    name = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now)

    def __repr__(self):
        return f"Comment('{self.name}', Post ID: {self.post_id}, User ID: {self.author_id})"

# --- Forms ---
class RegistrationForm(FlaskForm):
    username = StringField('ユーザー名', validators=[DataRequired(message='ユーザー名は必須です。'), Length(min=2, max=20)])
    password = PasswordField('パスワード', validators=[DataRequired(message='パスワードは必須です。'), Length(min=6)])
    confirm_password = PasswordField('パスワード（確認用）', validators=[DataRequired(), EqualTo('password', message='パスワードが一致しません。')])
    submit = SubmitField('サインアップ')

    def validate_username(self, username):
        user = db.session.execute(db.select(User).filter_by(username=username.data)).scalar_one_or_none()
        if user:
            raise ValidationError('そのユーザー名はすでに使用されています。')

class LoginForm(FlaskForm):
    username = StringField('ユーザー名', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('パスワード', validators=[DataRequired()])
    remember_me = BooleanField('ログイン状態を維持する')
    submit = SubmitField('ログイン')

class PostForm(FlaskForm):
    title = StringField('タイトル', validators=[DataRequired(), Length(min=1, max=100)])
    content = TextAreaField('本文', validators=[DataRequired()])
    image = FileField('画像をアップロード (任意)', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif'])])
    video = FileField('動画をアップロード (任意)', validators=[FileAllowed(['mp4', 'mov', 'avi', 'webm'])])
    submit = SubmitField('更新')

class CommentForm(FlaskForm):
    name = StringField('ニックネーム', validators=[DataRequired(), Length(min=1, max=50)])
    content = TextAreaField('コメント', validators=[DataRequired()])
    submit = SubmitField('コメントを送信')

class RequestResetForm(FlaskForm):
    username = StringField('ユーザー名', validators=[DataRequired()])
    submit = SubmitField('パスワードリセットに進む')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('新しいパスワード', validators=[DataRequired()])
    confirm_password = PasswordField('パスワード（確認用）', validators=[DataRequired(), EqualTo('password', message='パスワードが一致しません')])
    submit = SubmitField('パスワードをリセット')

# --- Context processor & user loader ---
@app.context_processor
def inject_globals():
    return {
        'now': now,
        'CLOUDINARY_AVAILABLE': CLOUDINARY_AVAILABLE,
        'get_cloudinary_url': get_safe_cloudinary_url,
        'get_cloudinary_video_url': get_safe_cloudinary_video_url,
        'CLOUD_NAME': CLOUD_NAME, 
        'config': current_app.config
    }

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

# --- Download route (Cloudinary) ---
@app.route('/download/<path:public_id>', methods=['GET'])
@login_required
def download_file(public_id):
    if not CLOUDINARY_AVAILABLE:
        flash('ファイルストレージサービスが利用できません。', 'danger')
        return redirect(url_for('admin'))

    try:
        resource_info = cloudinary.api.resource(public_id, all=True)
        if not resource_info or 'url' not in resource_info:
            flash('指定されたファイルが見つかりません。', 'danger')
            return redirect(url_for('admin'))

        file_url = resource_info['url']
        original_filename = resource_info.get('original_filename', public_id.split('/')[-1])
        content_format = resource_info.get('format', None)
        if content_format and not original_filename.lower().endswith(f".{content_format.lower()}"):
            original_filename = f"{original_filename}.{content_format}"

        response = requests.get(file_url, stream=True)
        if response.status_code != 200:
            flash('ファイルの取得中にエラーが発生しました。', 'danger')
            return redirect(url_for('admin'))

        def generate():
            for chunk in response.iter_content(chunk_size=4096):
                if chunk:
                    yield chunk

        return Response(
            generate(),
            mimetype=response.headers.get('Content-Type', 'application/octet-stream'),
            headers={
                "Content-Disposition": f"attachment; filename=\"{original_filename}\"",
                "Content-Length": response.headers.get('Content-Length')
            }
        )
    except Exception as e:
        # Cloudinary's NotFound may raise different exceptions depending on SDK version
        print(f"ファイルダウンロードエラー: {e}", file=sys.stderr)
        flash('ファイルダウンロード中に予期せぬエラーが発生しました。', 'danger')
        return redirect(url_for('admin'))

# --- Session inactivity handling ---
@app.before_request
def before_request_session_check():
    if current_user.is_authenticated:
        current_time = now()
        last_activity_str = session.get('last_activity')
        if last_activity_str:
            try:
                last_activity = datetime.fromisoformat(last_activity_str)
            except Exception:
                last_activity = current_time
            if (current_time - last_activity) > SESSION_INACTIVITY_TIMEOUT:
                logout_user()
                session.pop('last_activity', None)
                flash('非アクティブな状態が続いたため、自動的にログアウトしました。', 'info')
                return redirect(url_for('login', next=request.path))
        session['last_activity'] = current_time.isoformat()
    elif 'last_activity' in session:
        session.pop('last_activity', None)

# --- Decorator ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, "is_admin", False):
            flash('この操作には管理者権限が必要です。', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- Public pages ---
@app.route("/")
@app.route("/index")
def index():
    page = request.args.get('page', 1, type=int)
    query_text = request.args.get('q', '').strip()
    per_page = 5

    select_stmt = db.select(Post).order_by(Post.created_at.desc())
    if query_text:
        search_filter = or_(
            Post.title.contains(query_text),
            Post.content.contains(query_text)
        )
        select_stmt = select_stmt.where(search_filter)

    pagination = db.paginate(select_stmt, page=page, per_page=per_page, error_out=False)
    return render_template('index.html', title='ホーム', posts=pagination.items, pagination=pagination, query_text=query_text,config=current_app.config)

@app.route("/blog/<username>")
def user_blog(username):
    target_user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
    if not target_user:
        flash(f'ユーザー "{username}" は見つかりませんでした。', 'danger')
        return redirect(url_for('index'))

    posts = db.session.execute(
        db.select(Post)
        .filter_by(user_id=target_user.id)
        .order_by(Post.created_at.desc())
    ).scalars().all()

    return render_template('user_blog.html', title=f'{username} のブログ', target_user=target_user, posts=posts)

@app.route('/view/<int:post_id>')
def view(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)
    post.image_url = get_safe_cloudinary_url(post.image_public_id) if post.image_public_id else None
    post.video_url = get_safe_cloudinary_video_url(post.video_public_id) if post.video_public_id else None
    comments = db.session.execute(
        db.select(Comment).filter_by(post_id=post_id).order_by(Comment.created_at.asc())
    ).scalars().all()

    form = CommentForm()
    return render_template('view.html', post=post, comments=comments, form=form, config=current_app.config)
    
@app.route('/download/video/<int:post_id>', methods=['GET'])
@login_required # ログインが必須
def download_video(post_id):
    post = db.session.get(Post, post_id)
    if not post or not post.video_url:
        flash('ダウンロード可能な動画ファイルが見つかりませんでした。', 'danger')
        return redirect(url_for('view', post_id=post_id))
    if not current_user.is_admin:
        flash('動画をダウンロードする権限がありません。', 'danger')
        abort(403) 
    return redirect(post.video_url)

@app.route('/comment/<int:post_id>', methods=['POST'])
def comment(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)

    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(
            post_id=post_id,
            author_id=current_user.id if current_user.is_authenticated else None,
            name=form.name.data,
            content=form.content.data,
            created_at=now()
        )
        db.session.add(comment)
        db.session.commit()
        flash('コメントを投稿しました。', 'success')
        return redirect(url_for('view', _id=post_id) + '#comments')

    flash('コメント送信に失敗しました。', 'danger')
    return redirect(url_for('view', _id=post_id))

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = db.session.get(Comment, comment_id)
    if not comment:
        flash('コメントが見つかりませんでした。', 'danger')
        return redirect(request.referrer or url_for('index'))

    # permission: post owner, comment author, or admin
    try:
        post_owner_id = comment.post.user_id
    except Exception:
        post_owner_id = None

    can_delete = (
        post_owner_id == current_user.id or
        comment.author_id == current_user.id or
        getattr(current_user, "is_admin", False)
    )

    if not can_delete:
        flash('削除権限がありません。', 'danger')
        abort(403)

    post_id = comment.post_id
    db.session.delete(comment)
    db.session.commit()
    flash('コメントを削除しました。', 'success')
    return redirect(url_for('view', _id=post_id) + '#comments')

# --- Auth routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin'))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
        if user and user.check_password(password):
            login_user(user, remember=form.remember_me.data)
            session['last_activity'] = now().isoformat()
            next_page = request.args.get('next')
            flash(f'ログインに成功しました！ようこそ、{user.username}さん。', 'success')
            return redirect(next_page or url_for('admin'))
        else:
            flash('ユーザー名またはパスワードが正しくありません。', 'danger')

    return render_template('login.html', title='ログイン', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('admin'))

    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        new_user = User(username=username)
        new_user.set_password(password)
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
    logout_user()
    session.pop('last_activity', None)
    flash('ログアウトしました。', 'info')
    return redirect(url_for('index'))

# --- Password reset ---
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('admin'))

    form = RequestResetForm()
    if form.validate_on_submit():
        user = db.session.execute(db.select(User).filter_by(username=form.username.data)).scalar_one_or_none()
        if user:
            flash(f'ユーザー "{user.username}" のパスワードをリセットします。新しいパスワードを設定してください。', 'info')
            return redirect(url_for('reset_password_immediate', user_id=user.id))
        else:
            flash('ユーザー名が見つかりませんでした。', 'danger')
    return render_template('forgot_password.html', title='パスワードを忘れた場合', form=form)

@app.route('/reset_password_immediate/<int:user_id>', methods=['GET', 'POST'])
def reset_password_immediate(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('無効なユーザーIDです。', 'danger')
        return redirect(url_for('login'))

    if current_user.is_authenticated and current_user.id != user_id:
        flash('別のアカウントのパスワードをリセットすることはできません。', 'danger')
        return redirect(url_for('admin'))

    if current_user.is_authenticated:
        logout_user()

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.reset_token = None
        user.reset_token_expires = None
        db.session.commit()
        flash('パスワードが正常にリセットされました。新しいパスワードでログインしてください。', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', title=f'{user.username} のパスワードリセット', form=form, user_id=user_id, user_name=user.username)

# --- Create / Update / Delete posts ---
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        image_file = request.files.get(form.image.name)
        video_file = request.files.get(form.video.name)
        image_public_id = None
        video_public_id = None
        upload_image_success = False
        upload_video_success = False

        if image_file and image_file.filename != '' and CLOUDINARY_AVAILABLE:
            try:
                upload_result = cloudinary.uploader.upload(image_file, folder=f"flask_blog_images/{current_user.username}", resource_type="image")
                image_public_id = upload_result.get('public_id')
                upload_image_success = True
            except Exception as e:
                flash(f'画像のアップロード中にエラーが発生しました: {e}', 'danger')
                print(f"Cloudinary image upload error: {e}", file=sys.stderr)

        if video_file and video_file.filename != '' and CLOUDINARY_AVAILABLE:
            try:
                upload_result = cloudinary.uploader.upload(video_file, folder=f"flask_blog_videos/{current_user.username}", resource_type="video")
                video_public_id = upload_result.get('public_id')
                upload_video_success = True
            except Exception as e:
                flash(f'動画のアップロード中にエラーが発生しました: {e}', 'danger')
                print(f"Cloudinary video upload error: {e}", file=sys.stderr)

        if upload_image_success or upload_video_success:
            media_type = []
            if upload_image_success:
                media_type.append('画像')
            if upload_video_success:
                media_type.append('動画')
            flash(f'新しい記事とメディア({", ".join(media_type)})が正常に投稿されました。', 'success')
        else:
            flash('新しい記事が正常に投稿されました。', 'success')

        new_post = Post(title=title, content=content, user_id=current_user.id, image_public_id=image_public_id, video_public_id=video_public_id, created_at=now())
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('admin'))
    return render_template('create.html', title='新規投稿', form=form)

@app.route('/update/<int:post_id>', methods=['GET', 'POST'])
@login_required
def update(post_id):
    post = db.session.get(Post, post_id)
    if not post or (post.user_id != current_user.id and not getattr(current_user, "is_admin", False)):
        flash('編集権限がありません、または記事が見つかりません。', 'danger')
        abort(403)

    form = PostForm(obj=post)
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        delete_image = request.form.get('delete_image') == 'on'
        delete_video = request.form.get('delete_video') == 'on'
        image_file = request.files.get(form.image.name)
        video_file = request.files.get(form.video.name)
        media_action_performed = False

        if delete_image and post.image_public_id and CLOUDINARY_AVAILABLE:
            if delete_cloudinary_media(post.image_public_id, resource_type="image"):
                post.image_public_id = None
                flash('画像が削除されました。', 'info')
            else:
                flash('画像の削除に失敗しました。', 'danger')
            media_action_performed = True

        if delete_video and post.video_public_id and CLOUDINARY_AVAILABLE:
            if delete_cloudinary_media(post.video_public_id, resource_type="video"):
                post.video_public_id = None
                flash('動画が削除されました。', 'info')
            else:
                flash('動画の削除に失敗しました。', 'danger')
            media_action_performed = True

        if not delete_image and image_file and image_file.filename != '' and CLOUDINARY_AVAILABLE:
            if post.image_public_id:
                delete_cloudinary_media(post.image_public_id, resource_type="image")
            try:
                upload_result = cloudinary.uploader.upload(image_file, folder=f"flask_blog_images/{current_user.username}", resource_type="image")
                post.image_public_id = upload_result.get('public_id')
                flash('新しい画像が正常にアップロードされました。', 'success')
            except Exception as e:
                flash(f'新しい画像のアップロード中にエラーが発生しました: {e}', 'danger')
                print(f"Cloudinary image upload error: {e}", file=sys.stderr)
            media_action_performed = True

        if not delete_video and video_file and video_file.filename != '' and CLOUDINARY_AVAILABLE:
            if post.video_public_id:
                delete_cloudinary_media(post.video_public_id, resource_type="video")
            try:
                upload_result = cloudinary.uploader.upload(video_file, folder=f"flask_blog_videos/{current_user.username}", resource_type="video")
                post.video_public_id = upload_result.get('public_id')
                flash('新しい動画が正常にアップロードされました。', 'success')
            except Exception as e:
                flash(f'新しい動画のアップロード中にエラーが発生しました: {e}', 'danger')
                print(f"Cloudinary video upload error: {e}", file=sys.stderr)
            media_action_performed = True

        if not media_action_performed:
            flash('記事が正常に更新されました。', 'success')
        db.session.commit()
        return redirect(url_for('admin'))

    current_image_url = get_safe_cloudinary_url(post.image_public_id) if post.image_public_id else None
    current_video_url = get_safe_cloudinary_video_url(post.video_public_id) if post.video_public_id else None
    return render_template('update.html', title=f'記事の編集: {post.title}', form=form, post=post, current_image_url=current_image_url, current_video_url=current_video_url, is_edit=True)

@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = db.session.get(Post, post_id)
    if not post or (post.user_id != current_user.id and not getattr(current_user, "is_admin", False)):
        flash('削除権限がありません、または記事が見つかりません。', 'danger')
        abort(403)

    media_deleted = False
    if post.image_public_id:
        if delete_cloudinary_media(post.image_public_id, resource_type="image"):
            media_deleted = True
    if post.video_public_id:
        if delete_cloudinary_media(post.video_public_id, resource_type="video"):
            media_deleted = True

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
    return render_template('account.html', title='アカウント設定')

@app.route('/admin')
@login_required
def admin():
    """コンテンツ管理ダッシュボード: 自分の記事の一覧を表示"""
    
    posts = db.session.execute(
        db.select(Post)
        .filter_by(user_id=current_user.id)
        .order_by(Post.created_at.desc())
    ).scalars().all()

    post_data = []
    for post in posts:
        comment_count = db.session.execute(
            db.select(db.func.count(Comment.id)).filter_by(post_id=post.id)
        ).scalar_one()
        post_data.append((post, comment_count))

    title = 'コンテンツ管理'
    is_admin_user = current_user.is_admin
    total_users = 0
    total_posts = 0
    total_comments = 0

    if is_admin_user:
        try:
            total_users = db.session.execute(db.select(func.count(User.id))).scalar_one()
            total_posts = db.session.execute(db.select(func.count(Post.id))).scalar_one()
            total_comments = db.session.execute(db.select(func.count(Comment.id))).scalar_one()
        except Exception as e:
            print(f"統計情報の取得エラー: {e}", file=sys.stderr)
            flash('統計情報の取得中にエラーが発生しました。', 'danger')

    return render_template('admin.html', title=title, post_data=post_data, total_users=total_users, total_posts=total_posts, total_comments=total_comments, is_admin_user=is_admin_user, config=current_app.config)

# --- Error handlers ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html', title='ページが見つかりません'), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html', title='アクセス禁止'), 403

@app.errorhandler(413)
def payload_too_large_error(error):
    flash('アップロードされたファイルが大きすぎます。ファイルサイズの上限は100MBです。', 'danger')
    return redirect(request.referrer or url_for('admin'))

# --- DB clear (dev only) ---
@app.route("/db_clear", methods=["GET"])
def db_clear_data():
    try:
        with app.app_context():
            db.session.close()
            db.session.execute(text("DROP TABLE IF EXISTS comments CASCADE;"))
            db.session.execute(text("DROP TABLE IF EXISTS posts CASCADE;"))
            db.session.execute(text("DROP TABLE IF EXISTS blog_users CASCADE;"))
            db.session.execute(text("DROP TABLE IF EXISTS alembic_version CASCADE;"))
            db.session.commit()
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
    print("Application is running. Navigate to /admin or /view/1 to test the link.")
    app.run(debug=True)
