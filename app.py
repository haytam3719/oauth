from flask import Flask, request, jsonify
from itsdangerous import URLSafeSerializer, BadSignature, SignatureExpired
import uuid
import time
from datetime import datetime, timedelta
import firebase_admin
from firebase_admin import credentials, auth
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config['OAUTH2_PROVIDER_TOKEN_EXPIRES_IN'] = 3600  
app.config['OAUTH2_PROVIDER_REFRESH_TOKEN_EXPIRES_IN'] = 86400  

# Use environment variable for the database URI
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///oauth.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(50), unique=True, nullable=False)
    client_secret = db.Column(db.String(100), nullable=False)

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(300), unique=True, nullable=False)
    issued_at = db.Column(db.DateTime, nullable=False)
    expiration_time = db.Column(db.DateTime, nullable=False)
    client_id = db.Column(db.String(50), nullable=False)

SECRET_KEY = 'haytam123'

def generate_token():
    s = URLSafeSerializer(SECRET_KEY)
    return s.dumps({'token': str(uuid.uuid4()), 'issued_at': int(time.time())})

def generate_refresh_token():
    s = URLSafeSerializer(SECRET_KEY)
    return s.dumps({'token': str(uuid.uuid4()), 'issued_at': int(time.time())})

def verify_token(token, max_age=None):
    s = URLSafeSerializer(SECRET_KEY)
    try:
        data = s.loads(token, max_age=max_age)
    except SignatureExpired:
        return None  # Token expired
    except BadSignature:
        return None  # Invalid token
    return data['token']

@app.route('/oauth/token', methods=['POST'])
def access_token():
    grant_type = request.form.get('grant_type')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    
    if grant_type == 'client_credentials':
        client = Client.query.filter_by(client_id=client_id, client_secret=client_secret).first()
        if client:
            access_token = generate_token()
            refresh_token = generate_refresh_token()

            issued_at = datetime.now()
            expiration_time = issued_at + timedelta(seconds=3600)

            new_token = Token(token=access_token, issued_at=issued_at, expiration_time=expiration_time, client_id=client_id)
            db.session.add(new_token)
            db.session.commit()

            return jsonify(access_token=access_token, refresh_token=refresh_token)
        else:
            client = Client(client_id=client_id, client_secret=client_secret)
            db.session.add(client)
            db.session.commit()

            access_token = generate_token()
            refresh_token = generate_refresh_token()

            issued_at = datetime.now()
            expiration_time = issued_at + timedelta(seconds=3600)

            new_token = Token(token=access_token, issued_at=issued_at, expiration_time=expiration_time, client_id=client_id)
            db.session.add(new_token)
            db.session.commit()

            return jsonify(access_token=access_token, refresh_token=refresh_token)
    
    elif grant_type == 'refresh_token':
        refresh_token = request.form.get('refresh_token')
        token_data = Token.query.filter_by(token=refresh_token).first()
        if token_data:
            access_token = generate_token()

            token_data.token = access_token
            token_data.issued_at = datetime.now()
            db.session.commit()

            return jsonify(access_token=access_token)
        return jsonify(error='invalid_refresh_token'), 401
    else:
        return jsonify(error='unsupported_grant_type'), 400

@app.route('/oauth/refresh_token', methods=['POST'])
def refresh_token():
    refresh_token = request.form.get('refresh_token')
    if not refresh_token:
        return jsonify(error='missing_refresh_token'), 400

    token_data = Token.query.filter_by(token=refresh_token).first()
    if token_data:
        if token_data.expiration_time < datetime.now():
            return jsonify(error='refresh_token_expired'), 401

        access_token = generate_token()

        token_data.token = access_token
        token_data.issued_at = datetime.now()
        db.session.commit()

        return jsonify(access_token=access_token)
    
    return jsonify(error='invalid_refresh_token'), 401

if __name__ == '__main__':
    app.run(debug=True)
