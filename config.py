import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    def __init__(self):
        required_vars = ['DB_URI', 'EMAIL_USER', 'EMAIL_PASS', 'SECRET_KEY']
        missing = [var for var in required_vars if not os.getenv(var)]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv("DB_URI")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Email
    EMAIL_USER = os.getenv("EMAIL_USER")
    EMAIL_PASS = os.getenv("EMAIL_PASS")
    
    # Security
    SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_EXPIRATION_HOURS = 24
    OTP_EXPIRATION_MINUTES = 10
    MAX_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCK_TIME = 30  # minutes
    
    # File Uploads
    UPLOAD_FOLDER = 'pdf_uploads'
    ALLOWED_EXTENSIONS = {'pdf'}
    MAX_PDF_SIZE = 5 * 1024 * 1024  # 5MB
    ALLOWED_PDF_MAGIC_NUMBERS = [b'%PDF']