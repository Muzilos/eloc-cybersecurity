from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def level_zero():
    return render_template('level_zero.html')

if __name__ == '__main__':
    print("""
    ⚠️ Level 0 - Introduction Challenge
    This challenge helps students verify their setup and learn basic web inspection.
    """)
    app.run(debug=True, host='localhost', port=5000)