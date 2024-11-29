from flask import Flask, render_template, request, redirect, url_for, flash, session
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Change this to a secure secret key

# MongoDB connection
client = MongoClient('mongodb://db:27017/')
db = client.userauth
users = db.users


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users.find_one({'username': username})

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if users.find_one({'username': username}):
            flash('Username already exists')
            return redirect(url_for('register'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users.insert_one({
            'username': username,
            'password': hashed_password
        })

        flash('Registration successful')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)