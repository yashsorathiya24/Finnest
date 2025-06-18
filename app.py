from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from config import Config
from models import db, User, OTPRequest, MutualFundItem
import random
import smtplib
from email.mime.text import MIMEText
from passlib.hash import sha256_crypt
from datetime import datetime, timedelta
import re
import jwt as pyjwt
from functools import wraps
import PyPDF2
import io
import os
from werkzeug.utils import secure_filename
from datetime import timezone
import logging
from logging.handlers import RotatingFileHandler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config.from_object(Config())
db.init_app(app)

# Rate Limiter - More lenient settings for development
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["5000 per day", "1000 per hour"] if app.debug else ["200 per day", "50 per hour"]
)

# Logging Setup
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Finnest startup')

with app.app_context():
    db.create_all()

# Helper Functions
def send_otp_email(email, otp):
    msg = MIMEText(f"Your OTP for registration is: {otp}")
    msg['Subject'] = 'Your OTP Code'
    msg['From'] = Config.EMAIL_USER
    msg['To'] = email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(Config.EMAIL_USER, Config.EMAIL_PASS)
            smtp.send_message(msg)
    except Exception as e:
        app.logger.error(f"Failed to send email: {str(e)}")

def is_valid_email(email):
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(email_regex, email) is not None

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def generate_token(user):
    try:
        payload = {
            'user_id': user.id,
            'email': user.email,
            'exp': datetime.now(timezone.utc) + timedelta(hours=Config.JWT_EXPIRATION_HOURS)
        }
        token = pyjwt.encode(payload, Config.SECRET_KEY, algorithm='HS256')
        return token
    except Exception as e:
        app.logger.error(f"Token generation error: {str(e)}")
        raise

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({'message': 'Token is missing!'}), 401
            
        try:
            token = auth_header.split(" ")[1]
        except IndexError:
            return jsonify({'message': 'Bearer token malformed!'}), 401

        try:
            data = pyjwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
        except pyjwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except pyjwt.InvalidTokenError as e:
            app.logger.error(f"Invalid token error: {str(e)}")
            return jsonify({'message': 'Invalid token!'}), 401
        except Exception as e:
            app.logger.error(f"Token validation error: {str(e)}")
            return jsonify({'message': 'Token validation failed!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# Routes
@app.route('/request-otp', methods=['POST'])
@limiter.limit("10 per minute")  # Increased from 5 to 10
def request_otp():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email format"}), 400

    otp = str(random.randint(100000, 999999))
    record = OTPRequest.query.filter_by(email=email).first()
    if record:
        record.otp = otp
        record.verified = False
        record.created_at = datetime.utcnow()
    else:
        db.session.add(OTPRequest(email=email, otp=otp, verified=False))

    try:
        db.session.commit()
        send_otp_email(email, otp)
        return jsonify({"message": "OTP sent to your email"}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Database error: {str(e)}")
        return jsonify({"error": "Failed to process request"}), 500

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({"error": "Email and OTP are required"}), 400

    record = OTPRequest.query.filter_by(email=email).first()
    if not record or record.otp != otp:
        return jsonify({"error": "Invalid OTP"}), 400
    if datetime.utcnow() - record.created_at > timedelta(minutes=Config.OTP_EXPIRATION_MINUTES):
        return jsonify({"error": "OTP expired"}), 400

    record.verified = True
    db.session.commit()
    return jsonify({"message": "OTP verified successfully"}), 200

@app.route('/set-password', methods=['POST'])
def set_password():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and Password are required"}), 400

    if not is_strong_password(password):
        return jsonify({
            "error": "Password must be 8+ chars with uppercase, lowercase, number and special character"
        }), 400

    otp = OTPRequest.query.filter_by(email=email).first()
    if not otp or not otp.verified:
        return jsonify({"error": "OTP verification required"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "User already exists"}), 400

    hashed_password = sha256_crypt.hash(password)
    user = User(email=email, password=hashed_password)
    db.session.add(user)
    db.session.delete(otp)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401  # Generic message for security

    if user.locked_until and user.locked_until > datetime.utcnow():
        remaining_time = (user.locked_until - datetime.utcnow()).seconds // 60
        return jsonify({
            "error": f"Account locked. Try again in {remaining_time} minutes"
        }), 403

    if not sha256_crypt.verify(password, user.password):
        user.login_attempts += 1
        if user.login_attempts >= Config.MAX_LOGIN_ATTEMPTS:
            user.locked_until = datetime.utcnow() + timedelta(minutes=Config.ACCOUNT_LOCK_TIME)
            db.session.commit()
            return jsonify({
                "error": "Account locked due to too many failed attempts"
            }), 403
        
        db.session.commit()
        return jsonify({
            "error": "Invalid credentials"
        }), 401  # Generic message for security

    user.login_attempts = 0
    user.locked_until = None  # Clear any previous lock
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    try:
        token = generate_token(user)
        return jsonify({
            "message": "Login successful",
            "token": token,
            "user": {
                "id": user.id,
                "email": user.email
            }
        }), 200
    except Exception as e:
        app.logger.error(f"Token generation failed: {str(e)}")
        return jsonify({"error": "Login failed"}), 500

@app.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({
        "id": current_user.id,
        "email": current_user.email,
        "last_login": current_user.last_login.isoformat() if current_user.last_login else None
    })

@app.route('/upload-pdf', methods=['POST'])
@token_required
@limiter.limit("20 per hour")  # Increased from 10 to 20
def upload_pdf(current_user):
    if 'pdf' not in request.files:
        return jsonify({"error": "No PDF file provided"}), 400
    
    pdf_file = request.files['pdf']
    password = request.form.get('password')
    
    if not pdf_file or pdf_file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    if not pdf_file.filename.lower().endswith('.pdf'):
        return jsonify({"error": "Only PDF files are allowed"}), 400
    
    try:
        pdf_file.seek(0, os.SEEK_END)
        file_size = pdf_file.tell()
        pdf_file.seek(0)
        
        if file_size > Config.MAX_PDF_SIZE:
            return jsonify({
                "error": f"PDF too large. Max size is {Config.MAX_PDF_SIZE//(1024*1024)}MB"
            }), 400
        
        magic_number = pdf_file.read(4)
        pdf_file.seek(0)
        if magic_number not in Config.ALLOWED_PDF_MAGIC_NUMBERS:
            return jsonify({"error": "Invalid PDF file"}), 400

        pdf_content = io.BytesIO(pdf_file.read())
        pdf_reader = PyPDF2.PdfReader(pdf_content)

        if pdf_reader.is_encrypted:
            if not password:
                return jsonify({"error": "PDF is password protected but no password provided"}), 400
            if not pdf_reader.decrypt(password):
                return jsonify({"error": "Incorrect PDF password"}), 400

        full_text = "\n".join([page.extract_text() or "" for page in pdf_reader.pages])
        normalized_text = re.sub(r'\s+', ' ', full_text)
        fund_blocks = re.split(r'(?=[A-Z][A-Za-z ]+? Mutual Fund)', normalized_text)

        policies = []
        for block in fund_blocks:
            try:
                if 'Total Cost Value' not in block:
                    continue

                fund_house_match = re.search(r'([A-Z][A-Za-z ]+? Mutual Fund)', block)
                fund_house = fund_house_match.group(1).strip() if fund_house_match else "N/A"

                folio_match = re.search(r'Folio No[:\s]*([0-9/ ]+)', block)
                folio_number = folio_match.group(1).strip() if folio_match else "N/A"

                scheme_match = re.search(r'-([A-Za-z0-9 \-]+)- ISIN', block)
                scheme_name = scheme_match.group(1).strip() if scheme_match else "N/A"

                isin_match = re.search(r'ISIN[:\s]*([A-Z0-9]+)', block)
                isin = isin_match.group(1).strip() if isin_match else "N/A"

                invest_match = re.search(r'Total Cost Value[:\s]*([\d,]+\.\d+)', block)
                investment_amount = float(invest_match.group(1).replace(',', '')) if invest_match else 0.0

                current_val_match = re.search(r'Market Value .*?[:\s]*INR\s*([\d,]+\.\d+)', block)
                current_value = float(current_val_match.group(1).replace(',', '')) if current_val_match else 0.0

                gain_loss_amount = current_value - investment_amount
                gain_loss_percentage = (gain_loss_amount / investment_amount) * 100 if investment_amount else 0

                policies.append({
                    "fund_house": fund_house,
                    "folio_number": folio_number,
                    "scheme_name": scheme_name,
                    "isin": isin,
                    "investment_amount": investment_amount,
                    "current_value": current_value,
                    "gain_loss_amount": round(gain_loss_amount, 2),
                    "gain_loss_percentage": round(gain_loss_percentage, 4)
                })

            except Exception as inner_e:
                app.logger.error(f"Block parsing failed: {str(inner_e)}")
                continue

        if not policies:
            return jsonify({
                "error": "No mutual fund data found",
                "suggestion": "PDF format may be non-standard or unsupported."
            }), 400

        return jsonify({
            "success": True,
            "count": len(policies),
            "policies": policies
        }), 200

    except PyPDF2.errors.PdfReadError as e:
        return jsonify({"error": f"PDF Read Error: {str(e)}"}), 400
    except Exception as e:
        app.logger.error(f"PDF processing error: {str(e)}")
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)