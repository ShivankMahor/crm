# app.py

import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# --- App and Database Configuration ---

app = Flask(__name__)
# Use an absolute path for the database to avoid issues
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'a-very-secret-key-that-you-should-change' # Change this!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'crm.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to login page if user is not authenticated

# --- Database Models ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Dealer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    current_outstanding = db.Column(db.Integer, nullable=False)
    credit_limit = db.Column(db.Integer, nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    base_price = db.Column(db.Integer, nullable=False)

# --- Flask-Login User Loader ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Admin-Required Decorator ---

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('dealers'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dealers'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dealers'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@login_required
@admin_required
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 'is_admin' in request.form

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'warning')
            return redirect(url_for('register'))

        new_user = User(username=username, is_admin=is_admin)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash(f'User {username} created successfully!', 'success')
        return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/')
@app.route('/dealers')
@login_required
def dealers():
    all_dealers = Dealer.query.all()
    return render_template('dealers.html', dealers=all_dealers)

@app.route('/products')
@login_required
def products():
    all_products = Product.query.all()
    return render_template('products.html', products=all_products)

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Create tables if they don't exist
    app.run(debug=True)