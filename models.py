from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class OTPRequest(db.Model):
    __tablename__ = 'otp_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.Index('idx_otp_email', 'email'),
        db.Index('idx_otp_created', 'created_at'),
    )

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.Index('idx_user_email', 'email'),
    )

class MutualFundItem(db.Model):
    __tablename__ = 'mutual_fund_items'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    folio_number = db.Column(db.String(50), nullable=False)
    fund_name = db.Column(db.String(255), nullable=False)
    isin = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.Index('idx_mf_email', 'email'),
        db.Index('idx_mf_isin', 'isin'),
    )