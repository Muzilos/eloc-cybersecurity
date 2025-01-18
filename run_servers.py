import os
import glob
import importlib.util
from flask import Flask, Response, request, redirect, render_template_string, session
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from functools import wraps
import sqlite3
import hashlib
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import base64
import typing

# Database initialization
def init_db():
    conn = sqlite3.connect('students.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            verifier TEXT NOT NULL
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS completions (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            challenge_name TEXT NOT NULL,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(username, challenge_name),
            FOREIGN KEY (username) REFERENCES students(username)
        )
    ''')
    conn.commit()
    conn.close()

# Quantum-resistant key derivation using scrypt
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**16,  # CPU/memory cost parameter
        r=8,      # Block size parameter
        p=1,      # Parallelization parameter
    )
    return kdf.derive(password.encode())

# Encrypt data using AES-GCM with quantum-resistant key
def encrypt_data(key: bytes, data: str) -> typing.Tuple[str, str]:
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
    return (
        base64.b64encode(nonce).decode('utf-8'),
        base64.b64encode(ciphertext).decode('utf-8')
    )

# Decrypt data using AES-GCM
def decrypt_data(key: bytes, nonce: str, ciphertext: str) -> str:
    aesgcm = AESGCM(key)
    nonce_bytes = base64.b64decode(nonce.encode('utf-8'))
    ciphertext_bytes = base64.b64decode(ciphertext.encode('utf-8'))
    plaintext = aesgcm.decrypt(nonce_bytes, ciphertext_bytes, None)
    return plaintext.decode('utf-8')

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# Navigation buttons CSS and JavaScript
NAV_STYLES = """
<style>
    .challenge-nav {
        position: fixed;
        bottom: 20px;
        right: 20px;
        display: flex;
        gap: 10px;
        z-index: 1000;
    }
    .challenge-nav a {
        padding: 8px 16px;
        background: #0066cc;
        color: white;
        text-decoration: none;
        border-radius: 4px;
        font-family: system-ui, -apple-system, sans-serif;
        transition: background 0.2s;
    }
    .challenge-nav a:hover {
        background: #0052a3;
    }
    .challenge-nav a.disabled {
        background: #ccc;
        pointer-events: none;
    }
    .github-link {
        background: #333 !important;
    }
    .github-link:hover {
        background: #222 !important;
    }
</style>
"""

def create_nav_buttons(current_dir, all_dirs, github_url):
    """Create navigation buttons HTML based on current directory"""
    sorted_dirs = sorted(all_dirs)
    current_idx = sorted_dirs.index(current_dir)
    
    prev_link = ''
    next_link = ''
    
    if current_idx > 0:
        prev_dir = sorted_dirs[current_idx - 1]
        prev_link = f'<a href="/{prev_dir}">← Previous Challenge</a>'
    
    if current_idx < len(sorted_dirs) - 1:
        next_dir = sorted_dirs[current_idx + 1]
        next_link = f'<a href="/{next_dir}">Next Challenge →</a>'
    
    github_link = f'<a href="{github_url}/tree/main/{current_dir}" class="github-link" target="_blank">View on GitHub</a>'
    
    return f'<div class="challenge-nav">{prev_link}{github_link}{next_link}</div>'

def get_prefix_and_nav_js(current_dir, all_dirs, github_url):
    return f"""
{NAV_STYLES}
<script>
    // Store the original fetch function
    const originalFetch = window.fetch;
    
    // Get the app prefix from the current URL path
    const appPrefix = window.location.pathname.split('/')[1];
    
    // Override fetch to automatically add the prefix
    window.fetch = function(url, options) {{
        if (url.startsWith('/') && !url.startsWith(`/${{appPrefix}}/`)) {{
            url = `/${{appPrefix}}${{url}}`;
        }}
        return originalFetch(url, options);
    }};
</script>
{create_nav_buttons(current_dir, all_dirs, github_url)}
"""

def wrap_app_with_prefix_handler(app, prefix, all_dirs):
    """Wrap a Flask app with middleware to inject the prefix handler JS and nav buttons"""
    
    @app.after_request
    def inject_prefix_handler(response: Response):
        if response.content_type and 'text/html' in response.content_type.lower():
            content = response.get_data(as_text=True)
            
            # Create the combined JS and nav buttons for this specific directory
            inject_content = get_prefix_and_nav_js(prefix, all_dirs, 
                                                   github_url='https://github.com/Muzilos/eloc-cybersecurity')
            
            # Insert our content just before the closing </body> tag
            if '</body>' in content:
                content = content.replace('</body>', f'{inject_content}</body>')
            else:
                content += inject_content
                
            response.set_data(content)
        return response
    
    return app

def import_server_module(server_path):
    """Import a server.py file as a module properly."""
    dir_name = os.path.basename(os.path.dirname(server_path))
    module_name = f"server_{dir_name}"
    
    spec = importlib.util.spec_from_file_location(module_name, server_path)
    module = importlib.util.module_from_spec(spec)
    
    try:
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        print(f"Error loading {server_path}: {e}")
        return None

# Create main app with secret key for sessions
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a secure secret key

# Login page template
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Student Login</title>
    <style>
        body {
            font-family: system-ui, -apple-system, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
        }
        .login-form {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .form-group {
            margin-bottom: 1rem;
        }
        input {
            width: 100%;
            padding: 0.5rem;
            margin-top: 0.25rem;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button {
            width: 100%;
            padding: 0.75rem;
            background: #0066cc;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background: #0052a3;
        }
        .error {
            color: red;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <div class="login-form">
        <h2>Student Login</h2>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

# Add routes for authentication
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('students.db')
        c = conn.cursor()
        
        try:
            # Check if user exists
            c.execute('SELECT salt, verifier FROM students WHERE username = ?', (username,))
            result = c.fetchone()
            
            if result:
                # Existing user - verify password
                salt, stored_verifier = result
                salt_bytes = base64.b64decode(salt.encode('utf-8'))
                key = derive_key(password, salt_bytes)
                verifier = base64.b64encode(hashlib.sha256(key).digest()).decode('utf-8')
                
                if verifier == stored_verifier:
                    session['username'] = username
                    return redirect('/')
                else:
                    return render_template_string(LOGIN_TEMPLATE, error='Invalid password')
            else:
                # New user - create account
                salt = secrets.token_bytes(16)
                key = derive_key(password, salt)
                verifier = base64.b64encode(hashlib.sha256(key).digest()).decode('utf-8')
                
                try:
                    c.execute(
                        'INSERT INTO students (username, salt, verifier) VALUES (?, ?, ?)',
                        (username, base64.b64encode(salt).decode('utf-8'), verifier)
                    )
                    conn.commit()
                except sqlite3.IntegrityError:
                    # If we get here, the username was taken between our check and insert
                    return render_template_string(LOGIN_TEMPLATE, error='Username already taken')
                except Exception as e:
                    print(f"Error creating user: {e}")
                    return render_template_string(LOGIN_TEMPLATE, error='Error creating account')
                conn.commit()
                
                # Log in the new user
                session['username'] = username
                return redirect('/')
                
        except sqlite3.IntegrityError:
            # Handle race condition where username was created between check and insert
            return render_template_string(LOGIN_TEMPLATE, error='Username already taken')
        except Exception as e:
            print(f"Error during login/registration: {e}")
            return render_template_string(LOGIN_TEMPLATE, error='An error occurred')
        finally:
            conn.close()
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

# Route to validate and submit a flag
@app.route('/submit_flag/<challenge_name>', methods=['POST'])
@login_required
def submit_flag(challenge_name):
    if challenge_name not in all_dirs:
        return 'Challenge not found', 404
        
    submitted_flag = request.form.get('flag', '').strip()
    flag_file = os.path.join(base_dir, challenge_name, 'flag.txt')
    
    try:
        with open(flag_file, 'r') as f:
            correct_flag = f.read().strip()
            
        if submitted_flag == correct_flag:
            # Mark as complete in database
            conn = sqlite3.connect('students.db')
            c = conn.cursor()
            try:
                c.execute(
                    'INSERT OR IGNORE INTO completions (username, challenge_name) VALUES (?, ?)',
                    (session['username'], challenge_name)
                )
                conn.commit()
                return 'correct', 200
            finally:
                conn.close()
        else:
            return 'incorrect', 400
    except FileNotFoundError:
        print(f"Flag file not found for challenge: {challenge_name}")
        return 'Flag file not found', 500
    except Exception as e:
        print(f"Error validating flag: {e}")
        return 'Error validating flag', 500

# Add login check to the homepage
@app.route('/')
@login_required
def home():
    # Get list of completed challenges for current user
    conn = sqlite3.connect('students.db')
    c = conn.cursor()
    c.execute(
        'SELECT challenge_name, completed_at FROM completions WHERE username = ?',
        (session['username'],)
    )
    completed_challenges = {row[0]: row[1] for row in c.fetchall()}
    conn.close()
    
    # Create HTML for challenge list
    challenges_html = []
    for dir_name in sorted(all_dirs):
        is_completed = dir_name in completed_challenges
        completion_status = (
            f'<span style="color: #28a745">✓ Completed on {completed_challenges[dir_name]}</span>'
            if is_completed else
            '<span style="color: #dc3545">Not completed</span>'
        )
        challenges_html.append(f'''
            <li class="challenge-item">
                <div class="challenge-header">
                    <h3><a href="/{dir_name}">{dir_name}</a></h3>
                    <div class="completion-status">{completion_status}</div>
                </div>
                <div class="flag-section collapsed" id="flag-section-{dir_name}">
                    <form id="flag-form-{dir_name}" class="flag-form">
                        <input 
                            type="text" 
                            class="flag-input" 
                            placeholder="Enter flag..." 
                            name="flag"
                            id="flag-input-{dir_name}"
                            {'disabled' if dir_name in completed_challenges else ''}
                        >
                        <button 
                            type="submit" 
                            class="submit-flag"
                            {'disabled' if dir_name in completed_challenges else ''}
                        >
                            Submit Flag
                        </button>
                    </form>
                    <div class="flag-result" id="flag-result-{dir_name}"></div>
                </div>
                <button 
                    class="toggle-flag" 
                    id="toggle-{dir_name}"
                    {'disabled' if dir_name in completed_challenges else ''}
                >
                    {f"Challenge completed!" if dir_name in completed_challenges else "Submit flag"}
                </button>
            </li>
        ''')
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Challenge Server</title>
        <style>
            body {{
                font-family: system-ui, -apple-system, sans-serif;
                max-width: 800px;
                margin: 0 auto;
                padding: 2rem;
                background-color: #f5f5f5;
            }}
            .header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 2rem;
            }}
            .logout-btn {{
                padding: 0.5rem 1rem;
                background-color: #dc3545;
                color: white;
                text-decoration: none;
                border-radius: 4px;
                transition: background-color 0.2s;
            }}
            .logout-btn:hover {{
                background-color: #c82333;
            }}
            .welcome-section {{
                background: white;
                padding: 1.5rem;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                margin-bottom: 2rem;
            }}
            .challenge-list {{
                list-style: none;
                padding: 0;
                margin: 0;
            }}
            .challenge-item {{
                background: white;
                margin-bottom: 1rem;
                padding: 1.5rem;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                transition: transform 0.2s;
            }}
            .challenge-item:hover {{
                transform: translateY(-2px);
            }}
            .challenge-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            .challenge-header h3 {{
                margin: 0;
            }}
            .challenge-header a {{
                color: #0066cc;
                text-decoration: none;
            }}
            .challenge-header a:hover {{
                text-decoration: underline;
            }}
            .completion-status {{
                font-size: 0.9rem;
            }}
            .flag-section {{
                margin-top: 1rem;
                overflow: hidden;
                transition: max-height 0.3s ease-out;
            }}
            .flag-section.collapsed {{
                max-height: 0;
            }}
            .flag-form {{
                display: flex;
                gap: 1rem;
                align-items: center;
            }}
            .flag-input {{
                flex: 1;
                padding: 0.5rem;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-family: monospace;
            }}
            .submit-flag {{
                padding: 0.5rem 1rem;
                background: #0066cc;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
            }}
            .submit-flag:hover {{
                background: #0052a3;
            }}
            .submit-flag:disabled {{
                background: #ccc;
                cursor: not-allowed;
            }}
            .toggle-flag {{
                background: none;
                border: none;
                color: #0066cc;
                cursor: pointer;
                padding: 0.5rem;
                font-size: 0.9rem;
            }}
            .toggle-flag:hover {{
                text-decoration: underline;
            }}
            .flag-result {{
                margin-top: 0.5rem;
                font-size: 0.9rem;
            }}
            .progress-summary {{
                background: #0066cc;
                color: white;
                padding: 1rem;
                border-radius: 8px;
                margin-bottom: 2rem;
                text-align: center;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Welcome to the Challenge Server</h1>
            <a href="/logout" class="logout-btn">Logout</a>
        </div>
        
        <div class="welcome-section">
            <h2>Welcome, {session['username']}!</h2>
            <p>Select a challenge from the list below to begin.</p>
        </div>
        
        <div class="progress-summary">
            Completed {len(completed_challenges)} out of {len(all_dirs)} challenges
        </div>
        
        <ul class="challenge-list">
            {''.join(challenges_html)}
        </ul>
        
<script>
            // Add support for marking challenges as complete
            window.markComplete = async function(challengeName) {{
                try {{
                    const response = await fetch(`/complete/${{challengeName}}`, {{
                        method: 'POST'
                    }});
                    if (response.ok) {{
                        window.location.reload();
                    }}
                }} catch (error) {{
                    console.error('Error marking challenge complete:', error);
                }}
            }}

            // Add toggle functionality for flag submission sections
            document.querySelectorAll('.toggle-flag').forEach(button => {{
                button.addEventListener('click', () => {{
                    const challengeName = button.id.replace('toggle-', '');
                    const flagSection = document.getElementById(`flag-section-${{challengeName}}`);
                    flagSection.classList.toggle('collapsed');
                }});
            }});

            // Add form submission handlers
            document.querySelectorAll('.flag-form').forEach(form => {{
                form.addEventListener('submit', async (e) => {{
                    e.preventDefault();
                    
                    const challengeName = form.id.replace('flag-form-', '');
                    const flagInput = form.querySelector('input[name="flag"]');
                    const resultDiv = document.getElementById(`flag-result-${{challengeName}}`);
                    
                    try {{
                        const response = await fetch(`/submit_flag/${{challengeName}}`, {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/x-www-form-urlencoded',
                            }},
                            body: `flag=${{encodeURIComponent(flagInput.value)}}`
                        }});
                        
                        if (response.ok) {{
                            resultDiv.style.color = '#28a745';
                            resultDiv.textContent = 'Correct flag! Challenge completed.';
                            
                            // Disable the form and button
                            flagInput.disabled = true;
                            form.querySelector('button').disabled = true;
                            document.getElementById(`toggle-${{challengeName}}`).disabled = true;
                            
                            // Reload the page after a short delay to update the completion status
                            setTimeout(() => {{
                                window.location.reload();
                            }}, 1500);
                        }} else {{
                            resultDiv.style.color = '#dc3545';
                            resultDiv.textContent = 'Incorrect flag. Try again.';
                        }}
                    }} catch (error) {{
                        console.error('Error submitting flag:', error);
                        resultDiv.style.color = '#dc3545';
                        resultDiv.textContent = 'Error submitting flag. Please try again.';
                    }}
                }});
            }});
        </script>
    </body>
    </html>
    '''

# Add this near your other route definitions

@app.route('/stats')
def stats():
    conn = sqlite3.connect('students.db')
    c = conn.cursor()
    
    # Get total number of users
    c.execute('SELECT COUNT(DISTINCT username) FROM students')
    total_users = c.fetchone()[0]
    
    # Get total number of challenges
    challenge_count = len(all_dirs)
    
    # Get completion counts for each challenge
    c.execute('''
        SELECT challenge_name, COUNT(*) as completion_count 
        FROM completions 
        GROUP BY challenge_name 
        ORDER BY completion_count DESC
    ''')
    challenge_stats = c.fetchall()
    
    # Get user completion stats (number of challenges completed by each user)
    c.execute('''
        SELECT 
            username,
            COUNT(*) as challenges_completed,
            MIN(completed_at) as first_completion,
            MAX(completed_at) as last_completion
        FROM completions 
        GROUP BY username 
        ORDER BY challenges_completed DESC, last_completion ASC
    ''')
    user_stats = c.fetchall()
    
    # Get first solver for each challenge
    c.execute('''
        SELECT c1.challenge_name, c1.username, c1.completed_at
        FROM completions c1
        INNER JOIN (
            SELECT challenge_name, MIN(completed_at) as first_completion
            FROM completions
            GROUP BY challenge_name
        ) c2 
        ON c1.challenge_name = c2.challenge_name 
        AND c1.completed_at = c2.first_completion
        ORDER BY c1.completed_at ASC
    ''')
    first_solves = c.fetchall()
    
    conn.close()
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Challenge Stats</title>
        <style>
            body {{
                font-family: system-ui, -apple-system, sans-serif;
                max-width: 1200px;
                margin: 0 auto;
                padding: 2rem;
                background-color: #f5f5f5;
            }}
            .stats-container {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
                gap: 2rem;
                margin-bottom: 2rem;
            }}
            .stats-card {{
                background: white;
                padding: 1.5rem;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            }}
            .stats-card h2 {{
                margin-top: 0;
                color: #333;
                border-bottom: 2px solid #eee;
                padding-bottom: 0.5rem;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 1rem;
            }}
            th, td {{
                padding: 0.75rem;
                text-align: left;
                border-bottom: 1px solid #eee;
            }}
            th {{
                background-color: #f8f9fa;
                font-weight: 600;
            }}
            tr:hover {{
                background-color: #f8f9fa;
            }}
            .highlight {{
                color: #0066cc;
                font-weight: 600;
            }}
            .progress-bar {{
                background: #e9ecef;
                border-radius: 4px;
                height: 20px;
                margin-top: 0.5rem;
                overflow: hidden;
            }}
            .progress-bar-fill {{
                background: #0066cc;
                height: 100%;
                transition: width 0.3s ease;
            }}
            .summary-stats {{
                background: #0066cc;
                color: white;
                padding: 1.5rem;
                border-radius: 8px;
                margin-bottom: 2rem;
                display: flex;
                justify-content: space-around;
                text-align: center;
            }}
            .summary-stat {{
                display: flex;
                flex-direction: column;
            }}
            .stat-value {{
                font-size: 2rem;
                font-weight: bold;
                margin-bottom: 0.5rem;
            }}
            .stat-label {{
                font-size: 0.9rem;
                opacity: 0.9;
            }}
        </style>
    </head>
    <body>
        <h1>Challenge Server Statistics</h1>
        
        <div class="summary-stats">
            <div class="summary-stat">
                <div class="stat-value">{total_users}</div>
                <div class="stat-label">Total Users</div>
            </div>
            <div class="summary-stat">
                <div class="stat-value">{challenge_count}</div>
                <div class="stat-label">Total Challenges</div>
            </div>
            <div class="summary-stat">
                <div class="stat-value">
                    {sum(1 for user in user_stats if user[1] == challenge_count)}
                </div>
                <div class="stat-label">Users Completed All</div>
            </div>
        </div>
        
        <div class="stats-container">
            <div class="stats-card">
                <h2>Challenge Completion Stats</h2>
                <table>
                    <tr>
                        <th>Challenge</th>
                        <th>Completion Rate</th>
                    </tr>
                    {''.join(
                        f"""
                        <tr>
                            <td>{challenge}</td>
                            <td>
                                {count} / {total_users} 
                                ({(count/total_users*100 if total_users else 0):.1f}%)
                                <div class="progress-bar">
                                    <div class="progress-bar-fill" 
                                         style="width: {(count/total_users*100 if total_users else 0)}%">
                                    </div>
                                </div>
                            </td>
                        </tr>
                        """
                        for challenge, count in challenge_stats
                    )}
                </table>
            </div>
            
            <div class="stats-card">
                <h2>User Leaderboard</h2>
                <table>
                    <tr>
                        <th>User</th>
                        <th>Challenges Completed</th>
                        <th>Last Completion</th>
                    </tr>
                    {''.join(
                        f"""
                        <tr>
                            <td>{username}</td>
                            <td>
                                {completed} / {challenge_count}
                                ({(completed/challenge_count*100):.1f}%)
                            </td>
                            <td>{last_completion}</td>
                        </tr>
                        """
                        for username, completed, _, last_completion in user_stats[:10]
                    )}
                </table>
            </div>
            
            <div class="stats-card">
                <h2>First Solves</h2>
                <table>
                    <tr>
                        <th>Challenge</th>
                        <th>First Solver</th>
                        <th>Timestamp</th>
                    </tr>
                    {''.join(
                        f"""
                        <tr>
                            <td>{challenge}</td>
                            <td class="highlight">{username}</td>
                            <td>{timestamp}</td>
                        </tr>
                        """
                        for challenge, username, timestamp in first_solves
                    )}
                </table>
            </div>
        </div>
    </body>
    </html>
    '''

# Initialize database
init_db()

# Find all server.py files and get their directory names
base_dir = os.path.dirname(os.path.abspath(__file__))
server_files = glob.glob(os.path.join(base_dir, '*/server.py'))
all_dirs = [os.path.basename(os.path.dirname(path)) for path in server_files]

# Dictionary to hold our mounted apps
mounts = {}

# Import and mount each app
for server_path in server_files:
    dir_name = os.path.basename(os.path.dirname(server_path))
    print(f"Loading {dir_name}...")
    
    # Change to server's directory before importing
    original_dir = os.getcwd()
    os.chdir(os.path.dirname(server_path))
    
    try:
        # Import the module properly
        module = import_server_module(server_path)
        if module and hasattr(module, 'app'):
            # Wrap the app with our prefix handler and navigation
            wrapped_app = wrap_app_with_prefix_handler(module.app, dir_name, all_dirs)
            mounts[f'/{dir_name}'] = wrapped_app
            print(f"Mounted /{dir_name}")
        else:
            print(f"Skipping {dir_name} - no Flask app found")
    except Exception as e:
        print(f"Error mounting {dir_name}: {e}")
    finally:
        # Always restore the original directory
        os.chdir(original_dir)

# Create the unified application with the main app as the default
application = DispatcherMiddleware(app, mounts)

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    print("\nStarting unified server...")
    print("Mounted routes:")
    for route in sorted(mounts.keys()):
        print(f"  {route}")
    run_simple('0.0.0.0', 5000, application, use_reloader=True)