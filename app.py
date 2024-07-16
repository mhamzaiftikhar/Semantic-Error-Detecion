from flask import Flask, request, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import os
import google.generativeai as genai
from functools import wraps
from dotenv import load_dotenv
from pymongo import MongoClient
from bson.objectid import ObjectId

load_dotenv()  # Load environment variables from .env file

# Configure the Gemini API
genai.configure(api_key=os.environ.get('GEMINI_API_KEY'))
model = genai.GenerativeModel('gemini-pro')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# MongoDB Configuration
client = MongoClient(os.environ.get('MONGO_URI'))
db = client.get_database("database")

try:
    client.server_info()  # Check MongoDB connection
    print("MongoDB connection successful!")
except Exception as e:
    print(f"MongoDB connection error: {str(e)}")

class User:
    def __init__(self, username, email, password_hash):
        self.username = username
        self.email = email
        self.password_hash = password_hash  # Store the hashed password

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/aboutus')
@login_required
def aboutus():
    return render_template('aboutus.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_data = db.users.find_one({'username': username})

        if user_data and User(user_data['username'], user_data['email'], user_data['password']).check_password(password):
            session['user_id'] = str(user_data['_id'])
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('signin.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('signup'))

        existing_user = db.users.find_one({'username': username})
        if existing_user:
            flash('Username already taken', 'error')
            return redirect(url_for('signup'))

        # Hash the password before storing
        hashed_password = generate_password_hash(password)

        db.users.insert_one({
            'username': username,
            'email': email,
            'password': hashed_password
        })
        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('signin'))

    return render_template('signup.html')

@app.route('/terms')
@login_required
def terms():
    return render_template('terms.html')

@app.route('/')
@login_required
def index():
    return render_template('index.html', result=None)

@app.route('/generate', methods=['POST'])
@login_required
def generate_content():
    text = request.form.get('text')
    if not text:
        return render_template('index.html', result='No text provided', generated_output=None)

    prompt = f"Correct the following sentence: {text}. Provide a concise one-liner with the corrected version."
    try:
        response = model.generate_content(prompt)
        generated_output = response.text.strip()
        return render_template('index.html', result=None, generated_output=generated_output, input_text=text)
    except Exception as e:
        return render_template('index.html', result=f'An error occurred: {str(e)}', generated_output=None, input_text=text)

port = int(os.environ.get("PORT", 5000))
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=port)
