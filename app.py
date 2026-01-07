from flask import Flask, render_template, request, redirect, url_for, g, session, flash
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from urllib.parse import urlparse

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config['DATABASE'] = os.path.join(BASE_DIR, 'database.db')
app.secret_key = os.environ.get('FLASK_SECRET', 'dev-secret')
app.permanent_session_lifetime = timedelta(days=7)

# load environment variables from .env if present
load_dotenv()

# Initialize OAuth
oauth = OAuth(app)

# Admin emails (comma-separated) allowed to view admin pages
ADMIN_EMAILS = set([e.strip().lower() for e in os.environ.get('ADMIN_EMAILS', '').split(',') if e.strip()])

# Register providers (set these environment variables in your OS)
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
FACEBOOK_CLIENT_ID = os.environ.get('FACEBOOK_CLIENT_ID')
FACEBOOK_CLIENT_SECRET = os.environ.get('FACEBOOK_CLIENT_SECRET')

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )

if FACEBOOK_CLIENT_ID and FACEBOOK_CLIENT_SECRET:
    oauth.register(
        name='facebook',
        client_id=FACEBOOK_CLIENT_ID,
        client_secret=FACEBOOK_CLIENT_SECRET,
        access_token_url='https://graph.facebook.com/v10.0/oauth/access_token',
        authorize_url='https://www.facebook.com/v10.0/dialog/oauth',
        api_base_url='https://graph.facebook.com/v10.0/',
        client_kwargs={'scope': 'email'},
    )


def ensure_guests_table():
    # helper to get DB connection (defined before ensure_guests_table to avoid
    # NameError when ensure_guests_table is called at import time)
    def get_db():
        if 'db' not in g:
            g.db = sqlite3.connect(app.config['DATABASE'])
            g.db.row_factory = sqlite3.Row
        return g.db

    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS guests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    db.commit()


# ensure guests table exists on import
with app.app_context():
    ensure_guests_table()


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    guest_id = session.get('guest_id')
    if user_id is not None:
        db = get_db()
        g.user = db.execute('SELECT id, name, email FROM users WHERE id = ?', (user_id,)).fetchone()
    elif guest_id is not None:
        db = get_db()
        g.user = db.execute('SELECT id, name, email, created_at FROM guests WHERE id = ?', (guest_id,)).fetchone()
    else:
        g.user = None


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session.clear()
            session.permanent = True
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            return redirect(url_for('dashboard'))
        flash('Invalid email or password')
        return redirect(url_for('login'))
    return render_template('login.html')



@app.route('/login/<provider>')
def oauth_login(provider):
    if provider not in ('google', 'facebook'):
        flash('Unknown auth provider')
        return redirect(url_for('login'))
    oauth_client = oauth.create_client(provider)
    if not oauth_client:
        flash('Auth provider not configured')
        return redirect(url_for('login'))
    redirect_uri = url_for('oauth_callback', provider=provider, _external=True)
    return oauth_client.authorize_redirect(redirect_uri)


@app.route('/callback/<provider>')
def oauth_callback(provider):
    oauth_client = oauth.create_client(provider)
    if not oauth_client:
        flash('Auth provider not configured')
        return redirect(url_for('login'))
    token = oauth_client.authorize_access_token()
    if provider == 'google':
        userinfo = oauth_client.parse_id_token(token)
        email = userinfo.get('email')
        name = userinfo.get('name') or userinfo.get('email')
    else:
        # facebook
        resp = oauth_client.get('me?fields=id,name,email')
        data = resp.json()
        email = data.get('email')
        name = data.get('name')

    if not email:
        flash('Unable to get email from provider')
        return redirect(url_for('login'))

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    if not user:
        # create a user record
        db.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, ''))
        db.commit()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

    session.clear()
    session.permanent = True
    session['user_id'] = user['id']
    session['user_name'] = user['name']
    return redirect(url_for('dashboard'))


@app.route('/signin-guest', methods=['POST'])
def signin_guest():
    db = get_db()
    # create a guest entry; name/email optional
    cur = db.execute('INSERT INTO guests (name, email) VALUES (?, ?)', (None, None))
    db.commit()
    guest_id = cur.lastrowid
    guest = db.execute('SELECT id, name, email FROM guests WHERE id = ?', (guest_id,)).fetchone()
    session.clear()
    session.permanent = True
    session['guest_id'] = guest['id']
    session['user_name'] = f"Guest #{guest['id']}"
    return redirect(url_for('dashboard'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        if not (name and email and password):
            flash('All fields are required')
            return redirect(url_for('signup'))
        hashed = generate_password_hash(password)
        db = get_db()
        try:
            db.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, hashed))
            db.commit()
        except sqlite3.IntegrityError:
            flash('Email already registered')
            return redirect(url_for('signup'))
        return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/dashboard')
def dashboard():
    if g.user is None:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=g.user)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.route('/Contact')
def contact():
    return render_template('contact.html')


@app.route('/guests')
def guests():
    db = get_db()
    rows = db.execute('SELECT id, name, email, created_at FROM guests ORDER BY created_at DESC').fetchall()
    return render_template('guests.html', guests=rows)


