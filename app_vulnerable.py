from flask import Flask, request, render_template_string, send_from_directory
import sqlite3
import os
import pickle  # Insecure deserialization
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['DEBUG'] = True  # Insecure: Debug mode enabled
app.config['SECRET_KEY'] = 'supersecretkey'  # Hardcoded secret key (Insecure)
app.config['UPLOAD_FOLDER'] = 'uploads'

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
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    return render_template_string('''
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
    ''', users=users)

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

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        upload_folder = app.config['UPLOAD_FOLDER']
        # Ensure the upload folder exists
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        # Insecure file upload without validation
        filename = file.filename  # No sanitization
        file.save(os.path.join(upload_folder, filename))
        return 'File uploaded successfully!'
    return '''
        <h1>Upload File</h1>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file"><br>
            <input type="submit" value="Upload">
        </form>
    '''

@app.route('/download')
def download_file():
    filename = request.args.get('filename')
    if not filename:
        return 'Filename not provided.', 400
    # Vulnerable to Path Traversal
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/execute')
def execute():
    cmd = request.args.get('cmd', '')
    # Vulnerable to Command Injection
    os.system(cmd)
    return 'Command executed!'

@app.route('/deserialize')
def deserialize():
    data = request.args.get('data', '')
    if not data:
        return 'Data not provided.', 400
    # Insecure deserialization
    obj = pickle.loads(data)
    return f'Deserialized object: {obj}'

if __name__ == '__main__':
    init_db()
    app.run()
