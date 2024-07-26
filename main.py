from flask import Flask, jsonify, request, redirect, url_for, render_template, session, abort
import os
from dotenv import load_dotenv
import requests
from authlib.integrations.flask_client import OAuth
import json


# Import and initialize extensions
from templates.database.extensions import db, migrate, bcrypt, jwt
# Import the blueprints after app initialization
from templates.misc.misc_routes import misc_bp
from templates.auth.auth_routes import auth_bp
from templates.auth.google_routes import google_auth_bp
from templates.payment.stripe_routes import payment_bp

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Set up PostgreSQL database
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Set up JWT
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')
app.secret_key = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')
# Set up OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    meta_url=os.getenv('OAUTH2_META_URL'),
    # access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    client_kwargs={
        "scope": "openid profile email",
        # 'code_challenge_method': 'S256'  # enable PKCE
    },

    server_metadata_url=os.getenv('OAUTH2_META_URL'),
)



db.init_app(app)
migrate.init_app(app, db)
bcrypt.init_app(app)
jwt.init_app(app)

@app.route('/check')
def check():
    client_id=os.getenv('GOOGLE_CLIENT_ID', 'b')
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET', 'a')
    jwt_secret = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')
    print(f"client: {client_id}")
    print(f"secret: {client_secret}")
    print(f"jwt: {jwt_secret}")
    return jsonify({"message": "Connection secured."})

@app.route('/')
def home():
    return "Welcome to the Flask Microservice, General Backend!"

@app.route("/home")
def homepage():
    print(session)
    return render_template("home.html", session=session.get("user"),
                           pretty=json.dumps(session.get("user"), indent=4))



# Register the misc blueprint
app.register_blueprint(misc_bp, url_prefix='/api')

# Register Oauth and auth blueprints
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(google_auth_bp, url_prefix='/api/auth2')

# Register payment blueprint
app.register_blueprint(payment_bp, url_prefix='/api/pay')

# Google OAuth2 login
@app.route('/api/login/google', methods=['GET', 'POST'])
def login_google():
    if "user" in session:
        abort(404)
    print("Google login")

    return oauth.google.authorize_redirect(redirect_uri = url_for("authorize_google", _external=True))

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("homepage"))

@app.route('/api/authorize/google', methods=['GET', 'POST'])
def authorize_google():
    if request.method == 'POST':
        # Handle POST request if needed
        pass

    print("Google authorization")
    token = google.authorize_access_token()
    print("Google authorization")

    # fetch user data with access token
    personDataUrl = "https://people.googleapis.com/v1/people/me?personFields=genders,birthdays"
    personData = requests.get(personDataUrl, headers={
        "Authorization": f"Bearer {token['access_token']}"
    }).json()
    token["personData"] = personData
    # set complete user information in the session
    session["user"] = token
    return redirect(url_for("homepage"))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
