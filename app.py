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

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

with app.app_context():
    db.create_all()

# 🔹 Send OTP email
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
        print("Failed to send email:", e)

# 🔹 Email validation
def is_valid_email(email):
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(email_regex, email) is not None

# 🔹 JWT token generation
def generate_token(user):
    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.now(timezone.utc) + timedelta(days=1)
    }
    token = pyjwt.encode(payload, Config.SECRET_KEY, algorithm='HS256')

    # Ensure string output in Python 3.13+
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

# 🔹 JWT token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = pyjwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except pyjwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except pyjwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# 🔹 1. Request OTP
@app.route('/request-otp', methods=['POST'])
def request_otp():
    data = request.json
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

    db.session.commit()
    send_otp_email(email, otp)
    return jsonify({"message": "OTP sent to your email"}), 200

# 🔹 2. Verify OTP
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({"error": "Email and OTP are required"}), 400

    record = OTPRequest.query.filter_by(email=email).first()
    if not record or record.otp != otp:
        return jsonify({"error": "Invalid OTP"}), 400
    if datetime.utcnow() - record.created_at > timedelta(minutes=10):
        return jsonify({"error": "OTP expired"}), 400

    record.verified = True
    db.session.commit()
    return jsonify({"message": "OTP verified successfully"}), 200

# 🔹 3. Set Password (Registration)
@app.route('/set-password', methods=['POST'])
def set_password():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and Password are required"}), 400

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

# 🔹 4. Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # 1. Check both missing
    if not email and not password:
        return jsonify({"error": "Email and password are required"}), 400

    # 2. Check email missing
    if not email:
        return jsonify({"error": "Email is required"}), 400

    # 3. Check password missing
    if not password:
        return jsonify({"error": "Password is required"}), 400

    # 4. Check if user exists
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Invalid email"}), 401

    # 5. Check password
    if not sha256_crypt.verify(password, user.password):
        return jsonify({"error": "Invalid password"}), 401

    # 6. Generate token and return success response
    token = generate_token(user)
    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user.id,
            "email": user.email
        }
    }), 200

# 🔹 5. Protected route
@app.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({
        "id": current_user.id,
        "email": current_user.email
    })

# 🔹 6. Upload pdf 
@app.route('/upload-pdf', methods=['POST'])
@token_required
def upload_pdf(current_user):
    if 'pdf' not in request.files:
        return jsonify({"error": "No PDF file provided"}), 400

    pdf_file = request.files['pdf']
    password = request.form.get('password')

    try:
        pdf_content = io.BytesIO(pdf_file.read())
        pdf_reader = PyPDF2.PdfReader(pdf_content)

        if pdf_reader.is_encrypted:
            if not password:
                return jsonify({"error": "PDF is password protected but no password provided"}), 400
            if not pdf_reader.decrypt(password):
                return jsonify({"error": "Incorrect PDF password"}), 400

        # Extract and normalize text
        full_text = "\n".join([page.extract_text() or "" for page in pdf_reader.pages])
        print("======= PDF TEXT START =======")
        print(full_text[:3000])
        print("======= PDF TEXT END =======")

        # Make it easier for regex to work
        normalized_text = re.sub(r'\s+', ' ', full_text)

        # Extract blocks for each mutual fund (Edelweiss, Invesco, etc.)
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
                print("Block parsing failed:", inner_e)
                continue  # skip bad blocks

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
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
