import os
import sys
import urllib.parse
from io import BytesIO
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, abort, Response
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    current_user, login_required
)
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from sqlalchemy.orm import relationship
from sqlalchemy import func, or_
from datetime import datetime, timedelta, timezone

from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SubmitField,
    BooleanField, TextAreaField
)
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_wtf.file import FileField, FileAllowed

# -------------------------------------------------------
#  Cloudinary Setup
# -------------------------------------------------------
CLOUD_NAME = os.environ.get("CLOUDINARY_CLOUD_NAME")
API_KEY = os.environ.get("CLOUDINARY_API_KEY")
API_SECRET = os.environ.get("CLOUDINARY_API_SECRET")

CLOUDINARY_AVAILABLE = False
cloudinary = None

try:
    if CLOUD_NAME and API_KEY and API_SECRET:
        import cloudinary as actual_cloudinary
        import cloudinary.uploader
        import cloudinary.utils

        actual_cloudinary.config(
            cloud_name=CLOUD_NAME,
            api_key=API_KEY,
            api_secret=API_SECRET,
            secure=True
        )
        cloudinary = actual_cloudinary
        CLOUDINARY_AVAILABLE = True
except Exception as e:
    print(f"Cloudinary setup failed: {e}", file=sys.stderr)


def get_safe_cloudinary_url(public_id, **kwargs):
    if not public_id or not CLOUDINARY_AVAILABLE:
        return ""
    kwargs.setdefault("width", 600)
    kwargs.setdefault("crop", "limit")
    kwargs.setdefault("fetch_format", "auto")
    kwargs.setdefault("quality", "auto")
    try:
        encoded = urllib.parse.quote(public_id, safe="/")
        return cloudinary.utils.cloudinary_url(encoded, resource_type="image", **kwargs)[0]
    except Exception:
        return ""


def get_safe_cloudinary_video_url(public_id):
    if not public_id or not CLOUDINARY_AVAILABLE:
        return ""
    try:
        encoded_public_id = urllib.parse.quote(public_id, safe="/")
        video_url, _ = cloudinary.utils.cloudinary_url(
            encoded_public_id,
            resource_type="video",
            format="mp4",
            secure=True
        )
        return video_url
    except Exception:
        return ""


# -------------------------------------------------------
# Flask App Setup
# -------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "my_secret_key")

db_url = os.environ.get("DATABASE_URL", "sqlite:///myblog.db")
db_url = db_url.replace("postgres://", "postgresql://")
app.config["SQLALCHEMY_DATABASE_URI"] = db_url

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
csrf = CSRFProtect()
migrate = Migrate()

db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)
csrf.init_app(app)
migrate.init_app(app, db)

login_manager.login_view = "login"


def now():
    return datetime.now(timezone(timedelta(hours=9)))


# -------------------------------------------------------
# Models
# -------------------------------------------------------
class User(UserMixin, db.Model):
    __tablename__ = "blog_users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now)

    posts = relationship("Post", backref="author", lazy="dynamic")

    def set_password(self, pw):
        self.password_hash = bcrypt.generate_password_hash(pw).decode("utf-8")

    def check_password(self, pw):
        return bcrypt.check_password_hash(self.password_hash, pw)


class Post(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)

    image_public_id = db.Column(db.String(150))
    video_public_id = db.Column(db.String(150))

    created_at = db.Column(db.DateTime, default=now)
    user_id = db.Column(db.Integer, db.ForeignKey("blog_users.id"), nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("blog_users.id"))

    name = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=now)

# -------------------------------------------------------
# DB 初期化
# -------------------------------------------------------
db_initialized = False

@app.before_request
def initialize_db_once():
    global db_initialized
    if not db_initialized:
        with app.app_context():
            db.create_all()
        db_initialized = True


# -------------------------------------------------------
# Forms
# -------------------------------------------------------
class RegistrationForm(FlaskForm):
    username = StringField("ユーザー名", validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField("パスワード", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("パスワード(確認)", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("サインアップ")


class LoginForm(FlaskForm):
    username = StringField("ユーザー名", validators=[DataRequired()])
    password = PasswordField("パスワード", validators=[DataRequired()])
    remember_me = BooleanField("保持する")
    submit = SubmitField("ログイン")


class PostForm(FlaskForm):
    title = StringField("タイトル", validators=[DataRequired()])
    content = TextAreaField("内容", validators=[DataRequired()])
    image = FileField("画像", validators=[FileAllowed(["jpg", "png", "jpeg", "gif"])])
    video = FileField("動画", validators=[FileAllowed(["mp4", "mov", "webm"])])
    submit = SubmitField("投稿")


class CommentForm(FlaskForm):
    name = StringField("名前", validators=[DataRequired()])
    content = TextAreaField("コメント")


# -------------------------------------------------------
# Password Reset用のForm
# -------------------------------------------------------
class PasswordResetRequestForm(FlaskForm):
    username = StringField("ユーザー名", validators=[DataRequired()])
    submit = SubmitField("次へ")


class PasswordResetForm(FlaskForm):
    password = PasswordField("新しいパスワード", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("パスワード確認", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("パスワードを更新")


# -------------------------------------------------------
# Password Reset Routes
# -------------------------------------------------------
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = db.session.execute(
            db.select(User).filter_by(username=form.username.data)
        ).scalar_one_or_none()

        if not user:
            flash("ユーザーが存在しません。", "danger")
            return redirect(url_for("forgot_password"))

        flash("ユーザー確認成功。パスワード再設定へ進んでください。", "success")
        return redirect(url_for("reset_password", user_id=user.id))

    return render_template("forgot_password.html", form=form, title="パスワードリセット")


@app.route("/reset_password/<int:user_id>", methods=["GET", "POST"])
def reset_password(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("ユーザーが見つかりません。", "danger")
        return redirect(url_for("forgot_password"))

    form = PasswordResetForm()

    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()

        flash("パスワードを更新しました。ログインしてください。", "success")
        return redirect(url_for("login"))

    return render_template(
        "reset_password.html",
        form=form,
        user_id=user_id,
        user_name=user.username,
        title="パスワードリセット"
    )


# -------------------------------------------------------
# ここから先は投稿機能など元のルート
# -------------------------------------------------------

@app.route("/")
@app.route("/index")
def index():
    page = request.args.get("page", 1, type=int)
    query = request.args.get("q", "").strip()

    stmt = db.select(Post).order_by(Post.created_at.desc())
    if query:
        stmt = stmt.where(
            or_(Post.title.contains(query), Post.content.contains(query))
        )

    pagination = db.paginate(stmt, page=page, per_page=5, error_out=False)

    return render_template(
        "index.html",
        posts=pagination.items,
        pagination=pagination,
        query_text=query,
    )

@app.template_filter("datetimeformat")
def datetimeformat(value, format="%Y-%m-%d %H:%M"):
    if not value:
        return ""
    return value.strftime(format)

@app.context_processor
def inject_now():
    return {"now": datetime.utcnow()}

@app.route("/view/<int:post_id>")
def view(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)

    post.image_url = get_safe_cloudinary_url(post.image_public_id)
    post.video_url = get_safe_cloudinary_video_url(post.video_public_id)

    comments = db.session.execute(
        db.select(Comment).filter_by(post_id=post_id).order_by(Comment.created_at.asc())
    ).scalars().all()

    form = CommentForm()
    return render_template("view.html", post=post, comments=comments, form=form)

# -------------------------------------------------------
# Admin Dashboard
# -------------------------------------------------------
@app.route("/admin")
@login_required
def admin():
    # 現在ログイン中ユーザーの投稿を取得
    posts = (
        db.session.execute(
            db.select(Post)
            .filter_by(user_id=current_user.id)
            .order_by(Post.created_at.desc())
        ).scalars().all()
    )

    # コメント数を一緒に集計
    post_data = []
    for p in posts:
        count = db.session.execute(
            db.select(func.count(Comment.id)).filter_by(post_id=p.id)
        ).scalar_one()
        post_data.append((p, count))

    return render_template(
        "admin.html",
        post_data=post_data,
        is_admin=current_user.is_admin
    )


# -------------------------------------------------------
# Login / Logout / Signup
# -------------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = LoginForm()

    if form.validate_on_submit():
        user = db.session.execute(
            db.select(User).filter_by(username=form.username.data)
        ).scalar_one_or_none()

        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            flash("ログイン成功！", "success")
            return redirect(url_for("index"))

        flash("ユーザー名またはパスワードが間違っています。", "danger")

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("ログアウトしました。", "info")
    return redirect(url_for("index"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = RegistrationForm()

    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)

        db.session.add(user)
        db.session.commit()

        flash("ユーザー登録が完了しました！ログインしてください。", "success")
        return redirect(url_for("login"))

    return render_template("signup.html", form=form)


# -------------------------------------------------------
# Error Pages
# -------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error_page.html", title="404 ページが見つかりません", message="指定されたページは存在しません。"), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template("error_page.html", title="403 アクセス拒否", message="このページにアクセスする権限がありません。"), 403


@app.errorhandler(413)
def too_large(e):
    flash("ファイルサイズが大きすぎます（100MB制限）", "danger")
    return redirect(request.referrer or url_for("admin"))


# -------------------------------------------------------
# Local
# -------------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
