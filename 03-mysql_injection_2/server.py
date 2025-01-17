from flask import Flask, request, render_template, jsonify
import sqlite3
import logging
from pathlib import Path
from os import path

app = Flask(__name__)
directory = path.dirname(__file__) 

with open('flag.txt', 'r') as f:
    flag = f.read().strip()

# Configure logging
logging.basicConfig(
    filename='sql_challenge.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def init_db():
    """Initialize the database with sample data"""
    conn = sqlite3.connect(f'{directory}/students.db')
    c = conn.cursor()
    
    # Create tables
    c.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY,
            name TEXT,
            grade TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS secret_flags (
            id INTEGER PRIMARY KEY,
            flag TEXT
        )
    ''')
    
    # Insert sample data
    c.execute('DELETE FROM students')
    c.execute('DELETE FROM secret_flags')
    
    students = [
        (1, 'Alice Johnson', 'A'),
        (2, 'Bob Smith', 'B'),
        (3, 'Charlie Davis', 'A-'),
        (4, 'Diana Wilson', 'B+')
    ]
    c.executemany('INSERT INTO students VALUES (?,?,?)', students)
    
    # Create additional tables to make discovery more interesting
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_data (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password_hash TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS school_info (
            id INTEGER PRIMARY KEY,
            name TEXT,
            location TEXT
        )
    ''')
    
    # Insert the secret flag with a less obvious table/column name
    c.execute('DROP TABLE IF EXISTS system_configuration')
    c.execute('''
        CREATE TABLE system_configuration (
            id INTEGER PRIMARY KEY,
            setting_key TEXT,
            setting_value TEXT
        )
    ''')
    
    # Insert some decoy data and hide the flag among it
    configs = [
        (1, 'school_name', 'Springfield High'),
        (2, 'semester', 'Fall 2024'),
        (3, 'maintenance_mode', 'false'),
        (4, 'secret_key', flag),
        (5, 'theme_color', '#007bff'),
        (6, 'max_students', '1000')
    ]
    c.executemany('INSERT INTO system_configuration VALUES (?,?,?)', configs)    
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template('student_search.html')

@app.route('/search', methods=['POST'])
def search_students():
    try:
        name = request.form.get('name', '')
        
        # Log the search attempt (for monitoring injection attempts)
        logging.info(f"Search attempt with name: {name}")
        
        # Intentionally vulnerable query
        query = f"SELECT * FROM students WHERE name LIKE '%{name}%'"
        
        conn = sqlite3.connect(f'{directory}/students.db')
        c = conn.cursor()
        
        # Execute the query and fetch results
        try:
            results = c.execute(query).fetchall()
            success = True
            error = None
        except sqlite3.Error as e:
            results = []
            success = False
            error = str(e)
            logging.warning(f"SQL Error: {error}")
        
        conn.close()
        
        # Format results for display
        students = [
            {'id': r[0], 'name': r[1], 'grade': r[2]}
            for r in results
        ]
        
        return jsonify({
            'success': success,
            'error': error,
            'students': students
        })
        
    except Exception as e:
        logging.error(f"Error processing request: {e}")
        return jsonify({
            'success': False,
            'error': 'An error occurred processing your request',
            'students': []
        })

@app.route('/reset')
def reset_db():
    """Reset the database to its initial state"""
    try:
        init_db()
        return jsonify({'success': True})
    except Exception as e:
        logging.error(f"Error resetting database: {e}")
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    # Create database directory if it doesn't exist
    Path(f'{directory}/students.db').parent.mkdir(exist_ok=True)
    
    # Initialize the database
    init_db()
    
    print("""
    ⚠️ WARNING ⚠️
    This server is intentionally vulnerable to SQL injection.
    FOR EDUCATIONAL PURPOSES ONLY.
    DO NOT deploy on public networks or use real data.
    For classroom use only.
    """)
    
    app.run(debug=True, host='0.0.0.0', port=5002)