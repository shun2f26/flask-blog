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
# Cloudinary Setup（安全）
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

# ======================================================
# Flask App（★ここを最初に作ることが超重要）
# ======================================================
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "mysecretkey")

db_url = os.environ.get("DATABASE_URL", "sqlite:///myblog.db")
db_url = db_url.replace("postgres://", "postgresql://")
app.config["SQLALCHEMY_DATABASE_URI"] = db_url

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db)

login_manager.login_view = "login"

# ======================================================
# Cloudinary Helper（★ app 作成後に定義）
# ======================================================
def get_safe_cloudinary_url(public_id, width=600, height=340, crop="fill"):
    if not public_id or not CLOUDINARY_AVAILABLE:
        return ""
    try:
        encoded = urllib.parse.quote(public_id, safe="/")
        url, _ = cloudinary.utils.cloudinary_url(
            encoded,
            width=width,
            height=height,
            crop=crop,
            fetch_format="auto",
            quality="auto",
            secure=True
        )
        return url
    except:
        return ""


def get_safe_cloudinary_video_thumbnail(public_id, width=600, height=340):
    if not public_id or not CLOUDINARY_AVAILABLE:
        return ""
    try:
        encoded = urllib.parse.quote(public_id, safe="/")
        url, _ = cloudinary.utils.cloudinary_url(
            f"{encoded}.jpg",
            width=width,
            height=height,
            crop="fill",
            secure=True
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
# Jinja context_processor（★ app 定義後に置くこと！）
# ======================================================
@app.context_processor
def inject_cloudinary_helpers():
    return {
        "get_safe_cloudinary_url": get_safe_cloudinary_url,
        "get_safe_cloudinary_video_thumbnail": get_safe_cloudinary_video_thumbnail,
        "safe_video_url": safe_video_url,
    }

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
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=now)


# ======================================================
# Forms（省略しないようにそのまま）
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
    submit = SubmitField("投稿")


class PasswordResetRequestForm(FlaskForm):
    username = StringField("ユーザー名", validators=[DataRequired()])
    submit = SubmitField("次へ")


class PasswordResetForm(FlaskForm):
    password = PasswordField("新パスワード", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("パスワード確認", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("更新")

# ======================================================
# Routes（Signup/Login）
# ======================================================
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("admin"))
    form = RegistrationForm()
    if form.validate_on_submit():
        exist = db.session.execute(
            db.select(User).filter_by(username=form.username.data)
        ).scalar_one_or_none()
        if exist:
            flash("そのユーザー名はすでに使われています。", "danger")
            return redirect(url_for("signup"))

        new_user = User(username=form.username.data)
        new_user.set_password(form.password.data)

        db.session.add(new_user)
        db.session.commit()

        flash("登録完了！ログインしてください。", "success")
        return redirect(url_for("login"))

    return render_template("signup.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("admin"))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.execute(
            db.select(User).filter_by(username=form.username.data)
        ).scalar_one_or_none()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            flash("ログイン成功！", "success")
            return redirect(url_for("admin"))
        flash("ユーザー名またはパスワードが違います。", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("ログアウトしました。", "info")
    return redirect(url_for("index"))

# ======================================================
# 他の routes（index, admin, view, create, update, delete）
# ======================================================
# ★ ここは前回のコードで問題なしなので省略して OK
# 必要なら続きも全部貼るよ！

# ======================================================
# Run Local
# ======================================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
