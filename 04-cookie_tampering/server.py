from flask import Flask, request, render_template, make_response, redirect, url_for
import base64
import json
import logging
from functools import wraps

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    filename='cookie_challenge.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Sample product data
PRODUCTS = [
    {'id': 1, 'name': 'Basic Laptop', 'price': 999.99},
    {'id': 2, 'name': 'Premium Tablet', 'price': 499.99},
    {'id': 3, 'name': 'Standard Phone', 'price': 299.99},
    {'id': 4, 'name': 'Super Secret Hacking Tool', 'price': 9999.99}
]

with open('flag.txt') as f:
    flag = f.read().strip()
with open('password1.txt', 'r') as f:
    user_password = f.read().strip()
with open('password2.txt', 'r') as f:
    admin_password = f.read().strip()

# User database (in memory for demonstration)
USERS = {
    'student': {
        'password': user_password,
        'role': 'user',
        'balance': 1000.00
    },
    'admin': {
        'password': admin_password,
        'role': 'admin',
        'balance': 99999.99
    }
}

def create_user_cookie(username, role):
    """Create an easily tamperable cookie"""
    data = {
        'username': username,
        'role': role
    }
    # Intentionally using base64 encoding without signing
    return base64.b64encode(json.dumps(data).encode()).decode()

def get_user_from_cookie():
    """Decode the user cookie without verification"""
    try:
        cookie = request.cookies.get('user_data')
        if not cookie:
            return None
        
        # Intentionally vulnerable cookie parsing
        data = json.loads(base64.b64decode(cookie))
        return data
    except Exception as e:
        logging.error(f"Error decoding cookie: {e}")
        return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_data = get_user_from_cookie()
        if not user_data:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_data = get_user_from_cookie()
        if not user_data or user_data.get('role') != 'admin':
            return "Access Denied - Admin Only", 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    user_data = get_user_from_cookie()
    return render_template('store.html', 
                         products=PRODUCTS, 
                         user_data=user_data)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = USERS.get(username)
        print(user)
        print(user['password'])
        if user and user['password'] == password:
            response = make_response(redirect(url_for('home')))
            cookie = create_user_cookie(username, user['role'])
            response.set_cookie('user_data', cookie)
            return response
            
        return "Invalid credentials", 401
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('home')))
    response.delete_cookie('user_data')
    return response

@app.route('/purchase/<int:product_id>')
@login_required
def purchase_product(product_id):
    user_data = get_user_from_cookie()
    username = user_data.get('username')
    user = USERS.get(username)
    
    product = next((p for p in PRODUCTS if p['id'] == product_id), None)
    if not product:
        return "Product not found", 404
        
    if user['balance'] >= product['price']:
        user['balance'] -= product['price']
        return f"Successfully purchased {product['name']}" \
          + "\nTry navigating to /admin" if product["name"] == "Super Secret Hacking Tool" else ""
    else:
        return "Insufficient funds!", 402

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html', users=USERS, flag=flag)

if __name__ == '__main__':
    print("""
    ⚠️ WARNING ⚠️
    This server has intentionally vulnerable cookie authentication.
    FOR EDUCATIONAL PURPOSES ONLY.
    DO NOT deploy on public networks or use real credentials.
    For classroom use only.
    """)
    
    app.run(debug=True, host='0.0.0.0', port=5003)