from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_wtf.file import FileField, FileAllowed # ファイルアップロードに必要なインポート

class RegistrationForm(FlaskForm):
    """
    新規ユーザー登録用のフォームクラス。
    signup.html テンプレートで使用されます。
    """
    # ユーザー名フィールド
    # DataRequired: 必須入力
    # Length: 最小2文字、最大20文字
    username = StringField('ユーザー名', 
                           validators=[DataRequired(message='ユーザー名は必須です。'), 
                                       Length(min=2, max=20, message='ユーザー名は2文字以上20文字以内で入力してください。')])
    
    # パスワードフィールド
    # DataRequired: 必須入力
    password = PasswordField('パスワード', 
                             validators=[DataRequired(message='パスワードは必須です。'),
                                         Length(min=6, message='パスワードは6文字以上で設定してください。')])
    
    # パスワード確認フィールド
    # EqualTo: 上の 'password' フィールドの値と一致することを検証
    confirm_password = PasswordField('パスワード（確認用）', 
                                     validators=[DataRequired(message='パスワード確認は必須です。'), 
                                                 EqualTo('password', message='パスワードが一致しません。')])
    
    # 登録ボタン
    submit = SubmitField('サインアップ')


class PostForm(FlaskForm):
    """
    新規記事投稿および記事編集用のフォームクラス。
    create.html および edit.html テンプレートで使用されます。
    """
    # タイトルフィールド (create.htmlの name="title" に対応)
    title = StringField('タイトル', 
                        validators=[DataRequired(message='タイトルは必須です。'), 
                                    Length(min=2, max=100, message='タイトルは2文字以上100文字以内で入力してください。')])
    
    # コンテンツフィールド (create.htmlの name="content" に対応)
    content = TextAreaField('コンテンツ', 
                            validators=[DataRequired(message='コンテンツは必須です。')])
    
    # 画像ファイルフィールド (create.htmlの name="image_file" に対応)
    # myblog.py側で request.files.get(form.image_file.name) で取得するため、フィールド名は 'image_file' に統一
    image_file = FileField('サムネイル画像 (任意)', 
                           validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif'], 'アップロードできるのは画像ファイル (JPG, PNG, GIF) のみです。')]) 
    
    # 投稿/更新ボタン
    submit = SubmitField('記事を投稿')
