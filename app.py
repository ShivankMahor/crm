# app.py

import os
import click
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# --- App and Database Configuration ---

app = Flask(__name__)
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

# --- Admin-Required Decorator (Unchanged) ---

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
@app.route('/dealers', methods=['GET', 'POST'])
@login_required
def dealers():
    if request.method == 'POST':
        # Loop through all dealers to update them from the form
        for dealer in Dealer.query.all():
            dealer.name = request.form.get(f'name-{dealer.id}')
            dealer.current_outstanding = int(request.form.get(f'outstanding-{dealer.id}'))
            dealer.credit_limit = int(request.form.get(f'limit-{dealer.id}'))
        db.session.commit()
        flash('Dealer information updated successfully!', 'success')
        return redirect(url_for('dealers'))
    
    all_dealers = Dealer.query.order_by(Dealer.name).all()
    return render_template('dealers.html', dealers=all_dealers)

@app.route('/products', methods=['GET', 'POST'])
@login_required
def products():
    if request.method == 'POST':
        # Loop through all products to update them from the form
        for product in Product.query.all():
            product.name = request.form.get(f'name-{product.id}')
            product.stock = int(request.form.get(f'stock-{product.id}'))
            product.base_price = int(request.form.get(f'price-{product.id}'))
        db.session.commit()
        flash('Product information updated successfully!', 'success')
        return redirect(url_for('products'))

    all_products = Product.query.order_by(Product.name).all()
    return render_template('products.html', products=all_products)

# --- NEW: Route to reset data ---
@app.route('/reset-data', methods=['POST'])
@login_required
@admin_required
def reset_data():
    # Delete all existing data
    db.session.query(Dealer).delete()
    db.session.query(Product).delete()
    
    # Repopulate with original data
    populate_initial_data()
    
    db.session.commit()
    flash('All dealer and product data has been reset to the original values.', 'success')
    return redirect(url_for('dealers'))

# --- Helper function and CLI command for database initialization ---

def populate_initial_data():
    """Populates the database with the initial set of data."""
    dealers_data = [
        {'name': 'Stylish Bath', 'current_outstanding': 65000, 'credit_limit': 100000},
        {'name': 'Bath & Tiles', 'current_outstanding': 70000, 'credit_limit': 120000},
        {'name': 'Leonardo', 'current_outstanding': 55000, 'credit_limit': 90000},
        {'name': 'Sri Ceram', 'current_outstanding': 35000, 'credit_limit': 80000},
        {'name': 'Tiles World', 'current_outstanding': 60000, 'credit_limit': 110000},
        {'name': 'Sri Ceram 2', 'current_outstanding': 90000, 'credit_limit': 150000}
    ]
    for data in dealers_data:
        db.session.add(Dealer(**data))

    products_data = [
        {'name': '600x1200 Irish White A', 'stock': 1000, 'base_price': 85},
        {'name': '600x600 Dian White A', 'stock': 800, 'base_price': 100},
        {'name': '600x600 Irish White A', 'stock': 950, 'base_price': 65},
        {'name': '600x600 Lem White B', 'stock': 1200, 'base_price': 110},
        {'name': '600x300 Hyd White A', 'stock': 1500, 'base_price': 120}
    ]
    for data in products_data:
        db.session.add(Product(**data))
    print("Initial data populated.")

@app.cli.command('init-db')
def init_db_command():
    """Clears existing data and creates new tables and initial data."""
    db.drop_all()
    db.create_all()

    # Create admin user
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', is_admin=True)
        admin_user.set_password('admin123') # Set a default password
        db.session.add(admin_user)
        print("Admin user created with username 'admin' and password 'admin123'.")
    
    # Populate data
    populate_initial_data()
    
    db.session.commit()
    print('Initialized the database.')

if __name__ == '__main__':
    app.run(debug=True)