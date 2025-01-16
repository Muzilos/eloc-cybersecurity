from flask import Flask, request, jsonify, render_template
from functools import wraps
import time
import logging
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__,)

# Configure logging
logging.basicConfig(
    filename='ctf_challenge.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Obtain flag and password from hidden files
with open('password.txt', 'r') as f:
    password_from_file = f.read().strip()
with open('flag.txt', 'r') as f:
    flag_from_file = f.read().strip()

# Vulnerable user database - FOR EDUCATIONAL PURPOSES ONLY
users = {
    'admin': {
        # Weak password intentionally used for educational purposes
        'password': password_from_file,
        'flag': flag_from_file
    }
}

# Rate limiting configuration
RATE_LIMIT = 100  # Maximum attempts per window
RATE_WINDOW = 5  # Window in seconds
attempt_tracker = {}

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        current_time = time.time()
        
        # Clean up old attempts
        attempt_tracker[ip] = [t for t in attempt_tracker.get(ip, [])
                             if current_time - t < RATE_WINDOW]
        
        # Check if rate limit is exceeded
        if len(attempt_tracker.get(ip, [])) >= RATE_LIMIT:
            logging.warning(f"Rate limit exceeded for IP: {ip}")
            return jsonify({
                'error': 'Too many attempts. Please wait 5 minutes.'
            }), 429
        
        # Add new attempt
        attempt_tracker.setdefault(ip, []).append(current_time)
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
@rate_limit
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Log attempt (excluding password)
    logging.info(f"Login attempt for username: {username} from IP: {request.remote_addr}")
    
    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400
    
    user = users.get(username)
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if password == user['password']:  # Intentionally vulnerable comparison
        return jsonify({
            'success': True,
            'flag': user['flag']
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/stats')
def stats():
    """Endpoint for instructors to monitor challenge progress"""
    total_attempts = sum(len(attempts) for attempts in attempt_tracker.values())
    unique_ips = len(attempt_tracker)
    
    return jsonify({
        'total_attempts': total_attempts,
        'unique_ips': unique_ips,
        'rate_limit': RATE_LIMIT,
        'window_seconds': RATE_WINDOW
    })

if __name__ == '__main__':
    # Warning banner
    print("""
    ⚠️ WARNING ⚠️
    This server is intentionally vulnerable for educational purposes.
    DO NOT deploy on public networks or use real credentials.
    For classroom use only.
    """)
    
    # Run in development mode only
    app.run(debug=True, host='0.0.0.0', port=5000)