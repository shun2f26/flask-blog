import os
import sys
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from sqlalchemy.orm import relationship
from sqlalchemy.sql import text
from sqlalchemy_utils import database_exists, create_database
from datetime import datetime, timedelta, timezone

# WTForms関連のインポートをここに追加
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError

# Cloudinaryは今回は未使用のためコメントアウト/省略
# 🚨 警告: 実際のデプロイではCLOUDINARY_*環境変数を設定してください
try:
    import cloudinary
    import cloudinary.uploader
    import cloudinary.utils
    cloudinary.config(
        cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'),
        api_key=os.environ.get('CLOUDINARY_API_KEY'),
        api_secret=os.environ.get('CLOUDINARY_API_SECRET'),
        secure=True
    )
except ImportError:
    print("Cloudinaryがインストールされていないか、設定がスキップされました。", file=sys.stderr)
except Exception as e:
    print(f"Cloudinary config error (set CLOUDINARY_* env vars): {e}", file=sys.stderr)


# Flaskアプリのインスタンス作成
app = Flask(__name__)

# --- アプリ設定 ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'my_default_secret_key')

# Heroku / Render 互換性のためのURL修正ロジック
uri = os.environ.get('DATABASE_URL')
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = uri if uri else 'sqlite:///myblog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- SQLAlchemy/Migrate / WTF の遅延初期化 (Lazy Init) ---
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()

db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)
csrf.init_app(app) # CSRFを有効化
migrate.init_app(app, db) # Migrateの初期化

login_manager.login_view = 'login'
login_manager.login_message = 'このページにアクセスするにはログインが必要です。'
login_manager.login_message_category = 'info'


# -------------------------------------------------------------------
# データベース初期化
# -------------------------------------------------------------------
@app.before_request
def create_tables():
    """最初のHTTPリクエストが来る前にデータベーステーブルが存在することを確認する。"""
    if not hasattr(app, 'tables_created'):
        try:
            with app.app_context():
                # SQLiteの場合、ファイルがなければ作成される
                # PostgreSQLの場合、Render/Heroku側でDBインスタンスは存在している前提
                if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgresql'):
                    # PostgreSQLのテーブル作成が失敗した場合、通常はマイグレーションが必要だが、
                    # ここでは簡単な create_all() で対応
                    pass

                db.create_all()
                app.tables_created = True
                print("db.create_all()を実行し、テーブル初期化を完了しました。", file=sys.stderr)

        except Exception as e:
            print(f"データベースの初期化中にエラーが発生しました: {e}", file=sys.stderr)
            pass
# -------------------------------------------------------------------


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
        return f"User('{self.username}', '{self.id}')"

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


# --- フォーム定義 (forms.py から統合) ---

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
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('そのユーザー名はすでに使用されています。')

class LoginForm(FlaskForm):
    """ログイン用のフォームクラス"""
    username = StringField('ユーザー名', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('パスワード', validators=[DataRequired()])
    remember_me = BooleanField('ログイン状態を維持する')
    submit = SubmitField('ログイン')

class PostForm(FlaskForm):
    """記事投稿・編集用のフォームクラス"""
    title = StringField('タイトル', validators=[DataRequired(), Length(min=1, max=100)])
    content = TextAreaField('本文', validators=[DataRequired()])
    submit = SubmitField('投稿')

# (省略されていたリセット関連のフォームも念のため再統合)
class RequestResetForm(FlaskForm):
    username = StringField('ユーザー名', validators=[DataRequired()])
    submit = SubmitField('リセットリンクを送信')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('新しいパスワード', validators=[DataRequired()])
    confirm_password = PasswordField('パスワード（確認用）', validators=[DataRequired(), EqualTo('password', message='パスワードが一致しません')])
    submit = SubmitField('パスワードをリセット')

# --- ユーザーローダー ---

@login_manager.user_loader
def load_user(user_id):
    """Flask-LoginがセッションからユーザーIDをロードするためのコールバック"""
    return db.session.get(User, int(user_id))


# --- ルーティング ---

@app.route("/")
@app.route("/index")
def index():
    """ブログ記事一覧ページ"""
    posts = db.session.execute(db.select(Post).order_by(Post.create_at.desc())).scalars().all()
    return render_template('index.html', title='ホーム', posts=posts)


@app.route("/db_reset", methods=["GET", "POST"])
def db_reset():
    """データベーステーブルのリセット（開発用）"""
    if request.method == 'POST':
        try:
            with app.app_context():
                # データベース接続をクローズ
                db.session.close()

                # PostgreSQLの場合、テーブルを明示的にドロップ
                if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgresql'):
                    db.session.execute(text("DROP TABLE IF EXISTS posts CASCADE;"))
                    db.session.execute(text("DROP TABLE IF EXISTS blog_users CASCADE;"))
                    db.session.execute(text("DROP TABLE IF EXISTS alembic_version CASCADE;"))
                    db.session.commit()

                # SQLiteの場合、drop_all()を使用
                else:
                    db.drop_all()

                # テーブルを再作成
                db.create_all()
                db.session.commit()
                flash("データベースのテーブルが正常に削除・再作成されました。サインアップをお試しください。", 'success')
                return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            print(f"データベースリセット中にエラーが発生しました: {e}", file=sys.stderr)
            flash(f"データベースリセット中にエラーが発生しました: {e}", 'danger')
            return redirect(url_for('index'))

    # リセット確認画面の表示
    return render_template("db_reset_confirm.html", title='DBリセット確認')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """ログインページ"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    # LoginFormインスタンスを作成
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()

        if user and user.check_password(password):
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            flash('ログインに成功しました！', 'success')
            return redirect(next_page or url_for('index'))
        else:
            flash('ユーザー名またはパスワードが正しくありません。', 'danger')

    return render_template('login.html', title='ログイン', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """新規ユーザー登録ページ"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    # RegistrationFormインスタンスを作成
    form = RegistrationForm()

    if form.validate_on_submit():
        # validate_username() で重複チェックは既にされている
        username = form.username.data
        password = form.password.data

        new_user = User(username=username)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash(f'アカウントが作成されました: {username}! ログインしてください。', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html', title='サインアップ', form=form)


@app.route('/logout')
@login_required
def logout():
    """ログアウト処理"""
    logout_user()
    flash('ログアウトしました。', 'info')
    return redirect(url_for('index'))


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """新規記事投稿ページ (WTFormsに準拠)"""
    form = PostForm()
    
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        
        # 💡 画像アップロードロジックはWTFormsとは別に処理（file fieldがPostFormにないため）
        image_file = request.files.get('image')
        public_id = None

        # Cloudinaryに画像をアップロード
        if image_file and image_file.filename != '':
            try:
                upload_result = cloudinary.uploader.upload(image_file, folder="flask_blog_images")
                public_id = upload_result.get('public_id')
                # flash('画像が正常にアップロードされました。', 'success') # 成功時は記事投稿成功メッセージに統合
            except Exception as e:
                flash(f'画像のアップロード中にエラーが発生しました: {e}', 'danger')
                return render_template('create.html', title='新規投稿', form=form) # エラーの場合再表示

        # データベースに記事を保存
        new_post = Post(title=title,
                        content=content,
                        user_id=current_user.id,
                        public_id=public_id,
                        create_at=now())
        db.session.add(new_post)
        db.session.commit()
        flash('新しい記事が正常に投稿されました。', 'success')
        return redirect(url_for('index'))

    return render_template('create.html', title='新規投稿', form=form)


# 記事詳細
@app.route('/post/<int:post_id>')
def view(post_id):
    """記事詳細ページ"""
    post = db.session.get(Post, post_id)
    if not post:
        return render_template('404.html', title="404 記事が見つかりません"), 404

    # 画像URLを生成 (Cloudinaryが設定されている場合)
    image_url = None
    if post.public_id and 'cloudinary' in sys.modules:
        image_url = cloudinary.utils.cloudinary_url(post.public_id, fetch_format="auto", quality="auto")[0]

    return render_template('view.html', post=post, image_url=image_url, title=post.title)


# 記事編集
@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
def update(post_id):
    """記事編集ページ (WTFormsに準拠)"""
    post = db.session.get(Post, post_id)
    
    if not post or post.user_id != current_user.id:
        flash('編集権限がありません、または記事が見つかりません。', 'danger')
        return redirect(url_for('index'))

    form = PostForm(obj=post) # 既存の記事データでフォームを初期化

    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        
        image_file = request.files.get('image')
        delete_image = request.form.get('delete_image')

        # 画像削除処理
        if delete_image == 'on' and post.public_id and 'cloudinary' in sys.modules:
            try:
                cloudinary.uploader.destroy(post.public_id)
                post.public_id = None
                flash('画像を削除しました。', 'success')
            except Exception as e:
                flash(f'画像の削除中にエラーが発生しました: {e}', 'danger')

        # 新規画像アップロード処理
        if image_file and image_file.filename != '' and 'cloudinary' in sys.modules:
            try:
                # 古い画像があれば削除
                if post.public_id:
                    cloudinary.uploader.destroy(post.public_id)

                upload_result = cloudinary.uploader.upload(image_file, folder="flask_blog_images")
                post.public_id = upload_result.get('public_id')
                flash('新しい画像が正常にアップロードされました。', 'success')
            except Exception as e:
                flash(f'画像のアップロード中にエラーが発生しました: {e}', 'danger')
        
        db.session.commit()
        flash('記事が正常に更新されました。', 'success')
        return redirect(url_for('view', post_id=post.id))
    
    # GETリクエスト時の画像URL
    current_image_url = None
    if post.public_id and 'cloudinary' in sys.modules:
        current_image_url = cloudinary.utils.cloudinary_url(post.public_id, fetch_format="auto", quality="auto", width=200, crop="scale")[0]

    return render_template('update.html', post=post, title='記事編集', form=form, current_image_url=current_image_url)


# 記事削除
@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required
def delete(post_id):
    """記事削除処理"""
    post = db.session.get(Post, post_id)

    if not post or post.user_id != current_user.id:
        flash('削除権限がありません、または記事が見つかりません。', 'danger')
        return redirect(url_for('index'))

    # Cloudinaryから画像を削除
    if post.public_id and 'cloudinary' in sys.modules:
        try:
            cloudinary.uploader.destroy(post.public_id)
        except Exception as e:
            print(f"Cloudinary delete error: {e}", file=sys.stderr)

    # データベースから記事を削除
    db.session.delete(post)
    db.session.commit()
    flash('記事が正常に削除されました。', 'success')
    return redirect(url_for('index'))


# 管理画面
@app.route('/admin')
@login_required
def admin():
    """管理画面（自分の記事一覧）"""
    posts = db.session.execute(
        db.select(Post).filter_by(user_id=current_user.id).order_by(Post.create_at.desc())
    ).scalars().all()
    return render_template('admin.html', posts=posts, title='管理者ダッシュボード')

# アカウント設定 (未実装)
@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    flash("アカウント設定ページは現在未実装です。", 'info')
    return redirect(url_for('admin'))

# パスワードリセット (未実装)
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    flash("パスワードリセット機能は現在未実装です。", 'info')
    return redirect(url_for('login'))

@app.route('/reset_password/<path:token>', methods=['GET', 'POST'])
def reset_password(token):
    flash("パスワードリセット機能は現在未実装です。", 'info')
    return redirect(url_for('login'))


# --- エラーハンドリング ---

@app.errorhandler(404)
def not_found_error(error):
    """404エラーハンドラ"""
    return render_template('404.html', title='404 Not Found'), 404

if __name__ == '__main__':
    # ローカル開発環境でのみ実行
    with app.app_context():
        if not hasattr(app, 'tables_created'):
            try:
                db.create_all()
                app.tables_created = True
            except Exception as e:
                print(f"Local db.create_all() error: {e}", file=sys.stderr)

    app.run(debug=True)
