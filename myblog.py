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
# Cloudinary Setup
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
# Cloudinary Safe Helpers
# ======================================================
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
        encoded = urllib.parse.quote(public_id, safe="/"_
