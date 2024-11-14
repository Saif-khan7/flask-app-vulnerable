from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)
app.config['DEBUG'] = True  # Insecure: Debug mode enabled

# Hardcoded database credentials (Insecure)
DATABASE = 'database.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    return conn

# Initialize the database
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return '''
        <h1>User List</h1>
        <form action="/add" method="post">
            Username: <input type="text" name="username"><br>
            Email: <input type="text" name="email"><br>
            <input type="submit" value="Add User">
        </form>
        <h2>Users:</h2>
        <ul>
            {% for user in users %}
                <li>{{ user[1] }} - {{ user[2] }}</li>
            {% endfor %}
        </ul>
    '''

@app.route('/add', methods=['POST'])
def add_user():
    username = request.form['username']
    email = request.form['email']
    conn = get_db_connection()
    cursor = conn.cursor()
    # Vulnerable to SQL Injection
    cursor.execute(f"INSERT INTO users (username, email) VALUES ('{username}', '{email}')")
    conn.commit()
    conn.close()
    return 'User added successfully!'

@app.route('/search')
def search():
    query = request.args.get('q', '')
    conn = get_db_connection()
    cursor = conn.cursor()
    # Vulnerable to SQL Injection
    cursor.execute(f"SELECT * FROM users WHERE username LIKE '%{query}%'")
    users = cursor.fetchall()
    conn.close()
    # Vulnerable to XSS
    return render_template_string('''
        <h1>Search Results</h1>
        <ul>
            {% for user in users %}
                <li>{{ user[1] }} - {{ user[2] }}</li>
            {% endfor %}
        </ul>
    ''', users=users)

if __name__ == '__main__':
    init_db()
    app.run()
