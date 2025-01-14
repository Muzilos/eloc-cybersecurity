from flask import Flask, request, render_template, jsonify
import sqlite3
import logging
from pathlib import Path

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    filename='sql_challenge.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

with open('flag.txt', 'r') as f:
    flag = f.read().strip()

def init_db():
    """Initialize the database with sample data"""
    conn = sqlite3.connect('students.db')
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
    
    # Insert the secret flag
    c.execute('INSERT INTO secret_flags VALUES (1, ?)', 
              (flag,))
    
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
        
        conn = sqlite3.connect('students.db')
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
    Path('students.db').parent.mkdir(exist_ok=True)
    
    # Initialize the database
    init_db()
    
    print("""
    ⚠️ WARNING ⚠️
    This server is intentionally vulnerable to SQL injection.
    FOR EDUCATIONAL PURPOSES ONLY.
    DO NOT deploy on public networks or use real data.
    For classroom use only.
    """)
    
    app.run(debug=True, host='0.0.0.0', port=5001)