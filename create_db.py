from app import app, db, User, Dealer, Product

with app.app_context():
    # Create all database tables
    db.create_all()

    # --- Create the first admin user ---
    # Check if admin user already exists
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', is_admin=True)
        # IMPORTANT: Change 'your_strong_password' to a secure password
        admin_user.set_password('admin@123') 
        db.session.add(admin_user)
        print("Admin user created.")
    else:
        print("Admin user already exists.")

    # --- Populate Dealer Data ---
    # Check if dealers table is empty
    if Dealer.query.count() == 0:
        dealers_data = [
            {'name': 'Stylish Bath', 'current_outstanding': 65000, 'credit_limit': 100000},
            {'name': 'Bath & Tiles', 'current_outstanding': 70000, 'credit_limit': 120000},
            {'name': 'Leonardo', 'current_outstanding': 55000, 'credit_limit': 90000},
            # {'name': 'Sri Ceram', 'current_outstanding': 35000, 'credit_limit': 80000},
            {'name': 'Tiles World', 'current_outstanding': 60000, 'credit_limit': 110000},
            # The second 'Sri Ceram' is likely a typo in the PDF, but I'll add it as provided.
            # If it's a duplicate, you can remove it.
            {'name': 'Sri Ceram', 'current_outstanding': 90000, 'credit_limit': 150000}
        ]
        for data in dealers_data:
            db.session.add(Dealer(**data))
        print("Dealer data populated.")
    else:
        print("Dealer data already exists.")

    # --- Populate Product Data ---
    # Check if products table is empty
    if Product.query.count() == 0:
        products_data = [
            {'name': '600x1200 Irish White A', 'stock': 1000, 'base_price': 85},
            {'name': '600x600 Dian White A', 'stock': 800, 'base_price': 100},
            {'name': '600x600 Irish White A', 'stock': 950, 'base_price': 65},
            {'name': '600x600 Lem White B', 'stock': 1200, 'base_price': 110},
            {'name': '600x300 Hyd White A', 'stock': 1500, 'base_price': 120}
        ]
        for data in products_data:
            db.session.add(Product(**data))
        print("Product data populated.")
    else:
        print("Product data already exists.")

    # Commit all changes to the database
    db.session.commit()
    print("Database initialized and populated successfully.")

# Exit the python shell by typing exit()
exit()