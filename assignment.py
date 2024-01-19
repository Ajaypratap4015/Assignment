from flask import Flask, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer as Serializer
import secrets
from flask_mail import Mail,Message

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # Use SMTP port
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ajgamer509@gmail.com'
app.config['MAIL_PASSWORD'] = 'iobtdyimjdhmhjut'
app.config['MAIL_DEFAULT_SENDER'] = 'ajgamer509@gmail.com'  # Sender email address
app.config['MAIL_SUPPRESS_SEND'] = False  # Set to True to suppress email sending in development

mail = Mail(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_ops_user = db.Column(db.Boolean, default=False)
    token = db.Column(db.String(100), unique=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    file_type = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('files', lazy=True))

# Helper function for token generation
def generate_token(user_id):
    s = Serializer(app.config['SECRET_KEY'])
    return s.dumps({'user_id': user_id})

# Routes
@app.route('/ops-login', methods=['POST'])
def ops_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username, is_ops_user=True).first()
    print(user)
    if user and bcrypt.check_password_hash(user.password, password):
        token = generate_token(user.id)
        return jsonify({'token': token, 'message': 'success'})
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/ops-upload-file', methods=['POST'])
def ops_upload_file():
    data = request.get_json()
    token = data.get('token')
    filename = data.get('filename')
    file_type = data.get('file_type')

    try:
        payload = Serializer(app.config['SECRET_KEY']).loads(token)
        user_id = payload['user_id']
        user = User.query.get(user_id)

        if user and user.is_ops_user and file_type in ['pptx', 'docx', 'xlsx']:
            new_file = File(filename=filename, file_type=file_type, user=user)
            db.session.add(new_file)
            db.session.commit()
            return jsonify({'message': 'File uploaded successfully'})
        else:
            return jsonify({'message': 'Invalid token or file type'}), 401

    except Exception as e:
        print(e)
        return jsonify({'message': 'Invalid token'}), 401

@app.route('/client-signup', methods=['POST'])
def client_signup():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    print(username)

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(username=username, email=email, password=hashed_password)
    db.session.add(user)
    db.session.commit()

    token = generate_token(user.id) 
    verification_link = url_for('client_email_verify', token=token, _external=True)
    msg = Message('Email Verification', recipients=[email])
    msg.body = f'Click the following link to verify your email: {verification_link}'
    mail.send(msg)
    return jsonify({'token': token, 'message': 'success'})

@app.route('/client-email-verify/<token>', methods=['GET'])
def client_email_verify(token):
    try:
        payload = Serializer(app.config['SECRET_KEY']).loads(token)
        user_id = payload['user_id']
        user = User.query.get(user_id)

        if user:
            user.token = None
            db.session.commit()
            return jsonify({'message': 'Email verified successfully'})
        else:
            return jsonify({'message': 'Invalid token'}), 401

    except Exception as e:
        print(e)
        return jsonify({'message': 'Invalid token'}), 401

@app.route('/client-login', methods=['POST'])
def client_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if user and bcrypt.check_password_hash(user.password, password):
        token = generate_token(user.id)
        return jsonify({'token': token, 'message': 'success'})
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/download-file/<int:file_id>', methods=['GET'])
def download_file(file_id):
    data = request.get_json()
    token = data.get('token')

    try:
        payload = Serializer(app.config['SECRET_KEY']).loads(token)
        user_id = payload['user_id']
        user = User.query.get(user_id)

        if user:
            file = File.query.get(file_id)

            if file:
                # Generate a secure URL for file download
                secure_url = url_for('download_file', file_id=file_id, _external=True)
                return jsonify({'download_link': secure_url, 'message': 'success'})
            else:
                return jsonify({'message': 'Invalid file or user'}), 401
        else:
            return jsonify({'message': 'Invalid user'}), 401

    except Exception as e:
        print(e)
        return jsonify({'message': 'Invalid token'}), 401

@app.route('/list-uploaded-files', methods=['GET'])
def list_uploaded_files():
    data = request.get_json()
    token = data.get('token')

    try:
        payload = Serializer(app.config['SECRET_KEY']).loads(token)
        user_id = payload['user_id']
        user = User.query.get(user_id)

        if user:
            files = File.query.all()
            file_list = [{'filename': f.filename, 'file_type': f.file_type} for f in files]
            return jsonify({'files': file_list, 'message': 'success'})
        else:
            return jsonify({'message': 'Invalid user'}), 401

    except Exception as e:
        print(e)
        return jsonify({'message': 'Invalid token'}), 401

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
