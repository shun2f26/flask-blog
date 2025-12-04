import os
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate

from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SubmitField,
    BooleanField, TextAreaField
)
from wtforms.validators import DataRequired, Length, EqualTo
from flask_wtf.file import FileField, FileAllowed

from sqlalchemy.orm import relationship
from sqlalchemy import func, or_

# ======================================================
# Cloudinary Setup（安全な初期化）
# ======================================================
CLOUD_NAME = os.environ.get("CLOUDINARY_CLOUD_NAME")
API_KEY = os.environ.get("CLOUDINARY_API_KEY")
API_SECRET = os.environ.get("CLOUDINARY_API_SECRET")

cloudinary = None
CLOUDINARY_AVAILABLE = False

try:
    if CLOUD_NAME and API_KEY and API_SECRET:
        import cloudinary as cloud
        import cloudinary.uploader
        import cloudinary.utils
        cloud.config(
            cloud_name=CLOUD_NAME,
            api_key=API_KEY,
            api_secret=API_SECRET,
            secure=True
        )
        cloudinary = cloud
        CLOUDINARY_AVAILABLE = True
except Exception as e:
    print("Cloudinary setup failed:", e, file=sys.stderr)


def safe_img_url(public_id):
    if not public_id or not CLOUDINARY_AVAILABLE:
        return ""
    try:
        encoded = urllib.parse.quote(public_id, safe="/")
        url, _ = cloudinary.utils.cloudinary_url(
            encoded,
            width=600,
            crop="limit",
            fetch_format="auto",
            quality="auto"
        )
        return url
    except:
        return ""


def safe_video_url(public_id):
    if not public_id or not CLOUDINARY_AVAILABLE:
        return ""
    try:
        encoded = urllib.parse.quote(public_id, safe="/")
        url, _ = cloudinary.utils.cloudinary_url(
            encoded,
            resource_type="video",
            format="mp4",
            secure=True
        )
        return url
    except:
        return ""

# ======================================================
# Flask Application
# ======================================================
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "mysecretkey")

db_url = os.environ.get("DATABASE_URL", "sqlite:///myblog.db")
db_url = db_url.replace("postgres://", "postgresql://")
app.config["SQLALCHEMY_DATABASE_URI"] = db_url

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

db = SQLAlchemy()
bcrypt = Bcrypt()
csrf = CSRFProtect()
login_manager = LoginManager()
migrate = Migrate()

db.init_app(app)
bcrypt.init_app(app)
csrf.init_app(app)
login_manager.init_app(app)
migrate.init_app(app, db)

login_manager.login_view = "login"

# ======================================================
# Helper
# ======================================================
def now():
    return datetime.now(timezone(timedelta(hours=9)))


@app.template_filter("datetimeformat")
def datetimeformat(value, format="%Y-%m-%d %H:%M"):
    if not value:
        return ""
    return value.strftime(format)


@app.context_processor
def inject_now():
    return {"now": datetime.utcnow()}

# ======================================================
# Models
# ======================================================
class User(UserMixin, db.Model):
    __tablename__ = "blog_users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now)

    posts = relationship("Post", backref="author", lazy="dynamic")

    def set_password(self, pw):
        self.password_hash = bcrypt.generate_password_hash(pw).decode()

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

    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"))
    author_id = db.Column(db.Integer, db.ForeignKey("blog_users.id"))

    name = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=now)

# ======================================================
# Forms
# ======================================================
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


class PasswordResetRequestForm(FlaskForm):
    username = StringField("ユーザー名", validators=[DataRequired()])
    submit = SubmitField("次へ")


class PasswordResetForm(FlaskForm):
    password = PasswordField("新パスワード", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("パスワード確認", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("更新")

# ======================================================
# Password Reset
# ======================================================
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

        flash("ユーザー確認成功。新しいパスワードを設定してください。", "success")
        return redirect(url_for("reset_password", user_id=user.id))

    return render_template("forgot_password.html", form=form)


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

        flash("パスワードを変更しました。ログインしてください。", "success")
        return redirect(url_for("login"))

    return render_template(
        "reset_password.html",
        form=form,
        user_id=user_id,
        user_name=user.username
    )

# ======================================================
# Index
# ======================================================
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

# ======================================================
# Post View
# ======================================================
@app.route("/view/<int:post_id>")
def view(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)

    post.image_url = safe_img_url(post.image_public_id)
    post.video_url = safe_video_url(post.video_public_id)

    comments = db.session.execute(
        db.select(Comment).filter_by(post_id=post_id).order_by(Comment.created_at.asc())
    ).scalars().all()

    form = CommentForm()

    return render_template(
        "view.html",
        post=post,
        comments=comments,
        form=form
    )

# ======================================================
# Create Post
# ======================================================
@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    form = PostForm()

    if form.validate_on_submit():
        img_id = None
        vid_id = None

        # 画像
        image = form.image.data
        if image and CLOUDINARY_AVAILABLE:
            result = cloudinary.uploader.upload(
                image,
                folder=f"blog/{current_user.username}",
                resource_type="image"
            )
            img_id = result.get("public_id")

        # 動画
        video = form.video.data
        if video and CLOUDINARY_AVAILABLE:
            result = cloudinary.uploader.upload(
                video,
                folder=f"blog/{current_user.username}",
                resource_type="video"
            )
            vid_id = result.get("public_id")

        post = Post(
            title=form.title.data,
            content=form.content.data,
            user_id=current_user.id,
            image_public_id=img_id,
            video_public_id=vid_id,
        )

        db.session.add(post)
        db.session.commit()

        flash("記事を投稿しました！", "success")
        return redirect(url_for("dashboard"))

    return render_template("create.html", form=form)

# ======================================================
# Update Post
# ======================================================
@app.route("/update/<int:post_id>", methods=["GET", "POST"])
@login_required
def update(post_id):
    post = db.session.get(Post, post_id)

    if not post or post.user_id != current_user.id:
        abort(403)

    form = PostForm(obj=post)

    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data

        img = form.image.data
        vid = form.video.data

        # 画像更新
        if img and CLOUDINARY_AVAILABLE:
            if post.image_public_id:
                cloudinary.uploader.destroy(post.image_public_id, resource_type="image")
            result = cloudinary.uploader.upload(
                img, folder=f"blog/{current_user.username}", resource_type="image")
            post.image_public_id = result.get("public_id")

        # 動画更新
        if vid and CLOUDINARY_AVAILABLE:
            if post.video_public_id:
                cloudinary.uploader.destroy(post.video_public_id, resource_type="video")
            result = cloudinary.uploader.upload(
                vid, folder=f"blog/{current_user.username}", resource_type="video")
            post.video_public_id = result.get("public_id")

        db.session.commit()
        flash("記事を更新しました！", "success")
        return redirect(url_for("dashboard"))

    return render_template("update.html", form=form, post=post)

# ======================================================
# Delete Post
# ======================================================
@app.route("/delete/<int:post_id>", methods=["POST"])
@login_required
def delete(post_id):
    post = db.session.get(Post, post_id)

    if not post or post.user_id != current_user.id:
        abort(403)

    # Cloudinary削除
    if post.image_public_id:
        cloudinary.uploader.destroy(post.image_public_id, resource_type="image")
    if post.video_public_id:
        cloudinary.uploader.destroy(post.video_public_id, resource_type="video")

    db.session.delete(post)
    db.session.commit()

    flash("記事を削除しました。", "info")
    return redirect(url_for("dashboard"))

# ======================================================
# Dashboard（記事一覧画面）
# ======================================================
@app.route("/dashboard")
@login_required
def dashboard():
    posts = db.session.execute(
        db.select(Post)
        .filter_by(user_id=current_user.id)
        .order_by(Post.created_at.desc())
    ).scalars().all()

    for p in posts:
        p.image_url = safe_img_url(p.image_public_id)

    return render_template("dashboard.html", posts=posts, title="ダッシュボード")

# ======================================================
# Login / Logout / Signup
# ======================================================
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
            return redirect(url_for("dashboard"))

        flash("ユーザー名またはパスワードが違います。", "danger")

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
        new_user = User(username=form.username.data)
        new_user.set_password(form.password.data)

        db.session.add(new_user)
        db.session.commit()

        flash("登録完了！ログインしてください。", "success")
        return redirect(url_for("login"))

    return render_template("signup.html", form=form)

# ======================================================
# Error Pages
# ======================================================
@app.errorhandler(404)
def not_found(e):
    return render_template(
        "error_page.html",
        title="404 ページが見つかりません",
        message="指定されたページは存在しません。"
    ), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template(
        "error_page.html",
        title="403 アクセス拒否",
        message="このページにはアクセスできません。"
    ), 403


@app.errorhandler(413)
def too_large(e):
    flash("アップロードファイルが大きすぎます（100MB制限）", "danger")
    return redirect(url_for("dashboard"))

# ======================================================
# Run Local
# ======================================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
