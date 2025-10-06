import os
import sys
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from sqlalchemy.orm import relationship, aliased
from sqlalchemy import func, select 
from sqlalchemy.sql import text
from datetime import datetime, timedelta, timezone

# WTForms関連のインポート
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError

# Cloudinaryは今回は未使用のためコメントアウト/省略 (環境変数が設定されていれば動作)
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
# SSLMODE=requireの追加
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
    if '?' not in uri:
        uri += '?sslmode=require'
    elif 'sslmode' not in uri:
        uri += '&sslmode=require'


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
# @app.before_request ブロックを削除し、Render環境での競合を避けます。
# テーブル作成はローカル実行時(if __name__ == '__main__':)または
# /db_reset ルート、または render-build.sh にて行われます。
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
    is_admin = db.Column(db.Boolean, default=False, nullable=False) # 管理者ステータスを追加
    created_at = db.Column(db.DateTime, nullable=False, default=now) # 登録日時を追加
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

class RequestResetForm(FlaskForm):
    """パスワードリセット要求用のフォームクラス"""
    # ユーザー名を入力してもらい、そのユーザーが存在するか確認する
    username = StringField('ユーザー名', validators=[DataRequired()])
    submit = SubmitField('リセットリンクを送信')

class ResetPasswordForm(FlaskForm):
    """パスワードリセット（新しいパスワード設定）用のフォームクラス"""
    password = PasswordField('新しいパスワード', validators=[DataRequired()])
    confirm_password = PasswordField('パスワード（確認用）', validators=[DataRequired(), EqualTo('password', message='パスワードが一致しません')])
    submit = SubmitField('パスワードをリセット')

# --- ユーザーローダー ---

@app.context_processor
def inject_now():
    """Jinja2テンプレートにdatetime.datetime.now()関数を 'now' として提供する。"""
    # テンプレート内で {{ now().year }} のように呼び出すと、現在の年が取得可能になる
    return {'now': datetime.now}

@login_manager.user_loader
def load_user(user_id):
    """Flask-LoginがセッションからユーザーIDをロードするためのコールバック"""
    return db.session.get(User, int(user_id))

# --- デコレータ ---

def admin_required(f):
    """管理者権限が必要なルートのためのデコレータ"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # ログインしていること、かつ管理者(is_admin=True)であることを確認
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
# 公開ブログ閲覧ページ (変更なし)
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
    """パスワードリセット要求ページ (forgot_password.htmlをレンダリング)"""
    # 実際にはここでメールアドレスを受け取り、リセットトークンを発行する
    form = RequestResetForm()
    
    if form.validate_on_submit():
        # ダミー処理：ユーザー名を確認した体でメッセージを表示
        flash(f'ユーザー名 "{form.username.data}" にリセットリンクを送信しました。(※ダミー)', 'info')
        return redirect(url_for('login'))
        
    return render_template('forgot_password.html', title='パスワードを忘れた場合', form=form)


@app.route('/reset_password/<path:token>', methods=['GET', 'POST'])
def reset_password(token):
    """パスワードリセット実行ページ (reset_password.htmlをレンダリング)"""
    # 実際にはここでトークンを検証し、パスワードを更新する
    form = ResetPasswordForm()
    
    if form.validate_on_submit():
        # ダミー処理：パスワードを更新した体でメッセージを表示
        flash('パスワードが正常にリセットされました。新しいパスワードでログインしてください。(※ダミー)', 'success')
        return redirect(url_for('login'))
    
    # トークン情報 (デバッグ用)
    print(f"Received reset token: {token}", file=sys.stderr)
    
    return render_template('reset_password.html', title='パスワードリセット', form=form)


# -----------------------------------------------
# ユーザー専用管理画面 (変更なし)
# -----------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    """ログインユーザー専用の記事管理画面"""
    # ログインユーザーの記事のみを取得
    posts = db.session.execute(
        db.select(Post)
        .filter_by(user_id=current_user.id)
        .order_by(Post.create_at.desc())
    ).scalars().all()
    
    return render_template('dashboard.html', 
                           title=f'{current_user.username} のダッシュボード', 
                           posts=posts)


# -----------------------------------------------
# 記事作成・編集・削除 (統合されたルーティング)
# -----------------------------------------------

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """新規記事投稿ページ (統合テンプレートを使用)"""
    post = Post(title='', content='') # ダミーオブジェクト
    form = PostForm()
    
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        
        image_file = request.files.get('image')
        public_id = None

        if image_file and image_file.filename != '' and 'cloudinary' in sys.modules:
            try:
                upload_result = cloudinary.uploader.upload(image_file, folder="flask_blog_images")
                public_id = upload_result.get('public_id')
                flash('画像付きで記事が正常に投稿されました。', 'success') 
            except Exception as e:
                flash(f'画像のアップロード中にエラーが発生しました: {e}', 'danger')
                return render_template('create_update.html', title='新規投稿', form=form, post=post)

        new_post = Post(title=title,
                         content=content,
                         user_id=current_user.id,
                         public_id=public_id,
                         create_at=now())
        db.session.add(new_post)
        db.session.commit()
        flash('新しい記事が正常に投稿されました。', 'success')
        return redirect(url_for('dashboard'))

    # post=None を渡すことで「新規作成」モードであることをテンプレートに伝える
    return render_template('create_update.html', title='新規投稿', form=form, post=None)


@app.route('/update/<int:post_id>', methods=['GET', 'POST'])
@login_required
def update(post_id):
    """記事編集ページ (統合テンプレートを使用)"""
    post = db.session.get(Post, post_id)
    
    # 権限チェック: 自分の記事または管理者
    if not post or (post.user_id != current_user.id and not current_user.is_admin):
        flash('編集権限がありません、または記事が見つかりません。', 'danger')
        abort(403)

    form = PostForm(obj=post)

    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        
        image_file = request.files.get('image')
        delete_image = request.form.get('delete_image')

        # 画像削除・アップロード処理 (省略)
        if delete_image == 'on' and post.public_id and 'cloudinary' in sys.modules:
            try:
                cloudinary.uploader.destroy(post.public_id)
                post.public_id = None
                flash('画像を削除しました。', 'success')
            except Exception as e:
                flash(f'画像の削除中にエラーが発生しました: {e}', 'danger')

        if image_file and image_file.filename != '' and 'cloudinary' in sys.modules:
            try:
                if post.public_id: cloudinary.uploader.destroy(post.public_id)
                upload_result = cloudinary.uploader.upload(image_file, folder="flask_blog_images")
                post.public_id = upload_result.get('public_id')
                flash('新しい画像が正常にアップロードされました。', 'success')
            except Exception as e:
                flash(f'画像のアップロード中にエラーが発生しました: {e}', 'danger')
        
        db.session.commit()
        flash('記事が正常に更新されました。', 'success')
        
        if current_user.is_admin and post.user_id != current_user.id:
              return redirect(url_for('admin'))
        else:
              return redirect(url_for('dashboard'))
    
    current_image_url = None
    if post.public_id and 'cloudinary' in sys.modules:
        # 編集時のみ、現在の画像URLを生成
        current_image_url = cloudinary.utils.cloudinary_url(post.public_id, fetch_format="auto", quality="auto", width=200, crop="scale")[0]

    # postオブジェクトと現在の画像URLをテンプレートに渡す
    return render_template('create_update.html', 
                           post=post, 
                           title='記事編集', 
                           form=form, 
                           current_image_url=current_image_url)


@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required
def delete(post_id):
    """記事削除処理 (変更なし)"""
    post = db.session.get(Post, post_id)
    
    target_redirect = 'dashboard'

    if not post or (post.user_id != current_user.id and not current_user.is_admin):
        flash('削除権限がありません、または記事が見つかりません。', 'danger')
        abort(403)
        
    if current_user.is_admin and post.user_id != current_user.id:
        target_redirect = 'admin'

    if post.public_id and 'cloudinary' in sys.modules:
        try:
            cloudinary.uploader.destroy(post.public_id)
        except Exception as e:
            print(f"Cloudinary delete error: {e}", file=sys.stderr)

    db.session.delete(post)
    db.session.commit()
    flash('記事が正常に削除されました。', 'success')
    
    return redirect(url_for(target_redirect))


# -----------------------------------------------
# 管理者機能関連のルーティング (変更なし)
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
        user_posts = db.session.execute(
            db.select(Post).filter_by(user_id=user_obj.id).order_by(Post.create_at.desc())
        ).scalars().all()

        users.append({
            'user': user_obj,
            'post_count': post_count or 0,
            'posts': user_posts
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
    """データベーステーブルのリセット（開発用）"""
    # POSTリクエストまたは ?confirm=yes パラメータで実行を許可
    if request.method == 'POST' or request.args.get('confirm') == 'yes':
        try:
            with app.app_context():
                db.session.close()
                db.drop_all() # 全テーブルを削除
                db.create_all() # 最新のモデル定義で再作成
                if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgresql'):
                    # PostgreSQLではマイグレーション履歴テーブルもクリア
                    db.session.execute(text("DROP TABLE IF EXISTS alembic_version CASCADE;"))
                    db.session.commit()
                flash("データベースのテーブルが正常に削除・再作成されました。サインアップで管理者アカウントを作成してください。", 'success')
                return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            print(f"データベースリセット中にエラーが発生しました: {e}", file=sys.stderr)
            flash(f"データベースリセット中にエラーが発生しました: {e}", 'danger')
            return redirect(url_for('index'))
    # 実行が許可されていない場合は警告メッセージを表示
    flash("データベースリセットを実行するには、POSTリクエストまたはURLに ?confirm=yes をつけてください。", 'danger')
    return redirect(url_for('index'))


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    # account.html をレンダリング
    return render_template('account.html', title='アカウント設定') 

# カスタムエラーハンドラはエラーテンプレートをレンダリングするように変更

@app.errorhandler(404)
def not_found_error(error):
    """404エラーハンドラ"""
    return render_template('404.html', title='404 Not Found'), 404

@app.errorhandler(403)
def forbidden_error(error):
    """403エラーハンドラ (権限なし)"""
    flash('アクセス権限がありません。', 'danger')
    # 警告はフラッシュメッセージで表示し、error_page.htmlへは飛ばさず、indexへリダイレクト
    return redirect(url_for('index'))
    
@app.errorhandler(500)
def internal_error(error):
    """500エラーハンドラ (内部サーバーエラー)"""
    db.session.rollback() # データベース操作中のエラーの場合はロールバック
    return render_template('error_page.html', title='サーバーエラー', error_code=500, message='サーバー内部でエラーが発生しました。しばらくしてからお試しください。'), 500


if __name__ == '__main__':
    # ローカル開発環境でのみ実行
    with app.app_context():
        # ローカルでのみテーブル作成を試みる
        try:
            db.create_all()
        except Exception as e:
            print(f"Local db.create_all() error: {e}", file=sys.stderr)

    app.run(debug=True)
