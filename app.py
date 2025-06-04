from flask import Flask, request, redirect, url_for, render_template, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymongo import MongoClient
from bson.objectid import ObjectId
from bson.binary import Binary
from config import Config
from werkzeug.security import generate_password_hash, check_password_hash
import zlib
import datetime
from functools import wraps
from flask import abort
import os

app = Flask(__name__)
app.config.from_object(Config)
# Replace with a secure secret key in production
app.secret_key = 'your-secret-key-here'

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# MongoDB setup
client = MongoClient(app.config['MONGO_URI'])
db = client["blogdb"]
posts_collection = db["posts"]
users_collection = db["users"]

# User class for Flask-Login


class User(UserMixin):
    def __init__(self, user_data):
        self.user_data = user_data

    def get_id(self):
        return str(self.user_data['_id'])

    @property
    def is_admin(self):
        return self.user_data.get('is_admin', False)


@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user_data:
        return None
    return User(user_data)

# Compression helpers


def compress_text(text):
    if text:
        return Binary(zlib.compress(text.encode('utf-8')))
    return None


def decompress_text(compressed):
    if isinstance(compressed, str):
        return compressed
    return zlib.decompress(compressed).decode('utf-8') if compressed else ""


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403
# Auth routes


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if users_collection.find_one({'username': username}):
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        users_collection.insert_one({
            'username': username,
            'password': hashed_password,
            'is_admin': False,
            'created_at': datetime.datetime.utcnow()
        })
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_data = users_collection.find_one({'username': username})
        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data)
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Public route


@app.route('/')
@login_required
def index():
    posts = list(posts_collection.find().sort("_id", -1))
    for post in posts:
        if 'content' in post:
            post['content'] = decompress_text(post['content'])[:150] + '...'
    return render_template('index.html', posts=posts)


@app.route('/post/<post_id>')
def post(post_id):
    post = posts_collection.find_one({"_id": ObjectId(post_id)})
    if post and 'content' in post:
        post['content'] = decompress_text(post['content'])
    return render_template('post.html', post=post)

# Protected routes


@app.route('/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create():
    if request.method == 'POST':
        post_data = {
            'title': request.form['title'],
            'content': compress_text(request.form['content']),
            'image_url': request.form.get('image_url'),
            'author': current_user.user_data['username'],
            'date_created': datetime.datetime.utcnow()
        }
        posts_collection.insert_one(post_data)
        return redirect(url_for('index'))
    return render_template('create.html')


@app.route('/edit/<post_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit(post_id):
    post = posts_collection.find_one({'_id': ObjectId(post_id)})
    if request.method == 'POST':
        updated_data = {
            'title': request.form['title'],
            'content': compress_text(request.form['content']),
            'image_url': request.form.get('image_url')
        }
        posts_collection.update_one(
            {'_id': ObjectId(post_id)}, {'$set': updated_data})
        return redirect(url_for('post', post_id=post_id))
    if post and 'content' in post:
        post['content'] = decompress_text(post['content'])
    return render_template('edit.html', post=post)


@app.route('/delete/<post_id>')
@login_required
@admin_required
def delete(post_id):
    posts_collection.delete_one({'_id': ObjectId(post_id)})
    return redirect(url_for('index'))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Get port from environment (Render provides it)
    app.run(host="0.0.0.0", port=port, debug=True)
