import click
from flask import Flask, jsonify, request, redirect, url_for, render_template, session, abort, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from sqlalchemy.orm import relationship
from sqlalchemy import Table, Column, Integer, ForeignKey

import os
from dotenv import load_dotenv
import requests
from authlib.integrations.flask_client import OAuth
import json
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import Select
import time
from datetime import datetime

# Import and initialize extensions
from templates.database.extensions import db, migrate, bcrypt, jwt
# Import the blueprints after app initialization
from templates.misc.misc_routes import misc_bp
# from templates.auth.auth_routes import auth_bp
from templates.auth.google_routes import google_auth_bp
from templates.payment.stripe_routes import payment_bp

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Set up PostgreSQL database
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Set up PostgreSQL models

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    __tablename__ = 'users'  # Explicitly set the table name
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=False, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))  # Increased from 128 to 255
    is_google_account = db.Column(db.Boolean, default=False)
    google_id = db.Column(db.String(128), unique=True, nullable=True)
    # notes = db.relationship('Note', back_populates='user', lazy='dynamic')  # Changed 'user' to 'author'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def get_or_create(email, username=None, password=None, is_google_account=False, google_id=None):
        user = User.query.filter_by(email=email).first()
        if user:
            return user, False
        else:
            if is_google_account:
                # For Google accounts, don't set a username
                username = None
            else:
                # For normal registration, username is required
                if not username:
                    raise ValueError("Username is required for normal registration")

            user = User(email=email, username=username, is_google_account=is_google_account, google_id=google_id)
            if password:
                user.set_password(password)
            db.session.add(user)
            db.session.commit()
            return user, True


# Set up JWT
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')
app.secret_key = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')
# Set up OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)



# db.init_app(app)
migrate.init_app(app, db)
bcrypt.init_app(app)
jwt.init_app(app)


# Setup Selenium WebDriver
def get_driver():
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument('--ignore-certificate-errors')
    chrome_options.add_argument('--ignore-ssl-errors')
    service = webdriver.ChromeService()
    driver = webdriver.Chrome()
    return driver


# Route to load and display the website
@app.route('/load', methods=['POST'])
def load_website():
    url = request.json['url']
    driver = get_driver()
    driver.get(url)
    time.sleep(2)  # Wait for the page to load

    # Extract relevant elements: input, button, select, etc.
    elements = driver.find_elements(By.CSS_SELECTOR, 'input, button, a, select')
    elements_data = []
    for element in elements:
        element_data = {
            'tag': element.tag_name,
            'id': element.get_attribute('id'),
            'text': element.text,
            'type': element.get_attribute('type'),
        }

        # For file inputs, allow file selection
        if element_data['tag'] == 'input' and element_data['type'] == 'file':
            element_data['action'] = 'file'

        # For other inputs, suggest a sample value that can be inserted
        elif element_data['tag'] == 'input':
            element_data['action'] = 'input'
            element_data['placeholder'] = element.get_attribute('placeholder')

        # For select elements, list available options
        elif element_data['tag'] == 'select':
            element_data['action'] = 'select'
            options = element.find_elements(By.TAG_NAME, 'option')
            element_data['options'] = [option.text for option in options]

        # For buttons and links, set up click action
        elif element_data['tag'] in ['button', 'a']:
            element_data['action'] = 'click'

        elements_data.append(element_data)

    driver.quit()
    return jsonify(elements_data)

# Route to interact with elements based on queued instructions
@app.route('/interact', methods=['POST'])
def interact_with_element():
    url = request.json['url']
    instructions = request.json['instructions']  # List of actions

    driver = get_driver()
    driver.get(url)
    time.sleep(10)  # Wait for the page to load

    results = []
    for instruction in instructions:
        element_id = instruction['element_id']
        action = instruction['action']
        value = instruction.get('value', '')

        try:
            element = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.ID, element_id))
            )

            # Perform actions based on the element's type and interaction required
            if action == 'click':
                element.click()
                results.append(f"Clicked on {element_id}.")
            elif action == 'input':
                element.clear()
                element.send_keys(value)
                results.append(f"Inserted '{value}' into {element_id}.")
            if action == 'select':
                # Ensure the element is visible and enabled
                WebDriverWait(driver, 10).until(
                    EC.element_to_be_clickable((By.ID, element_id))
                )
                select = Select(element)
                select.select_by_visible_text(value)  # or select_by_value(value)
                print(f"Selected '{value}' from {element_id}.")
            elif action == 'file':
                # Upload the file by setting its path to the file input element
                element.send_keys(value)
                results.append(f"Uploaded file '{value}' to {element_id}.")
        except Exception as e:
            results.append(f"Failed to perform {action} on {element_id}: {str(e)}")

    driver.quit()
    return jsonify({"status": "completed", "results": results})

@app.route('/check')
def check():
    client_id=os.getenv('GOOGLE_CLIENT_ID', 'b')
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET', 'a')
    jwt_secret = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')
    print(f"client: {client_id}")
    print(f"secret: {client_secret}")
    print(f"jwt: {jwt_secret}")
    return jsonify({"message": "Connection secured."})

@app.route('/welcome')
def home():
    return "Welcome to the Flask Microservice, General Backend!"

# Route to render the main interface
@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route("/home")
def homepage():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template("login.html", session=session.get("user"),
                           pretty=json.dumps(session.get("user"), indent=4))

# Register the misc blueprint
app.register_blueprint(misc_bp, url_prefix='/api')

# Register Oauth and auth blueprints
# app.register_blueprint(auth_bp, url_prefix='/api/auth')
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
    session.clear()  # Clear the entire session instead of just popping 'user'
    return redirect(url_for("login"))

@app.route('/api/authorize/google', methods=['GET', 'POST'])
def authorize_google():
    try:
        token = google.authorize_access_token()
        resp = google.get('https://openidconnect.googleapis.com/v1/userinfo')
        userinfo = resp.json()
        user, created = User.get_or_create(
            email=userinfo['email'],
            is_google_account=True,
            google_id=userinfo['sub']
        )
        session['user'] = {'id': user.id, 'email': user.email}
        return redirect(url_for('dashboard'))
    except Exception as e:
        print(f"Error in authorize_google: {str(e)}")
        flash('An error occurred during Google authentication. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash('Please sign in to access the dashboard.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user']['id']
    current_user = User.query.get(user_id)
    display_name = current_user.username or current_user.email

    # Fetch all users
    all_users = User.query.all()

    return render_template('dashboard.html', current_user=current_user, display_name=display_name, all_users=all_users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        login_id = request.form.get('login_id')  # This can be either username or email
        password = request.form.get('password')

        # Check if the login_id is an email
        if '@' in login_id:
            user = User.query.filter_by(email=login_id).first()
        else:
            user = User.query.filter_by(username=login_id).first()

        if user and user.check_password(password):
            session['user'] = {'id': user.id, 'username': user.username, 'email': user.email}
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username/email or password', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if not username:
            flash('Username is required', 'error')
            return render_template('register.html')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            if existing_user.is_google_account:
                flash('This email is already associated with a Google account. Please use Google Sign-In.', 'warning')
            else:
                flash('An account with this email already exists. Please login.', 'warning')
            return redirect(url_for('login'))

        try:
            new_user, created = User.get_or_create(email=email, username=username, password=password)
            if created:
                flash('Registration successful. Please login.', 'success')
                return redirect(url_for('login'))
            else:
                flash('An error occurred during registration. Please try again.', 'error')
        except ValueError as e:
            flash(str(e), 'error')

    return render_template('register.html')




if __name__ == '__main__':
    with app.app_context():
        # db.create_all()
        app.run(host='0.0.0.0', port=5000, debug=True)
