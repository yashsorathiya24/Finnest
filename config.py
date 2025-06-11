import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv("DB_URI")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    EMAIL_USER = os.getenv("EMAIL_USER")
    EMAIL_PASS = os.getenv("EMAIL_PASS")
    SECRET_KEY = os.getenv("SECRET_KEY")
    UPLOAD_FOLDER = 'pdf_uploads'  # Folder for temporary PDF storage
    ALLOWED_EXTENSIONS = {'pdf'}
