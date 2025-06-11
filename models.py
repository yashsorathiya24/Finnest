from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class OTPRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class MutualFundItem(db.Model):
    __tablename__ = 'mutual_fund_items'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    folio_number = db.Column(db.String(50), nullable=False)  # New field
    fund_name = db.Column(db.String(255), nullable=False)
    isin = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
