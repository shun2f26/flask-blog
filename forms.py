from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo

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
