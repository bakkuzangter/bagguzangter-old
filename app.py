from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import time
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATABASE = 'database.db'
UPLOAD_FOLDER = 'static/uploads'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def get_db_connection(retries=5, delay=0.1, timeout=5.0):
    for i in range(retries):
        try:
            conn = sqlite3.connect(DATABASE, timeout=timeout)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.OperationalError as e:
            if 'database is locked' in str(e):
                time.sleep(delay)
            else:
                raise
    raise Exception('Failed to get database connection after several retries.')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def convert_path_to_url(path):
    return path.replace('\\', '/')

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('main'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['nickname'] = user['nickname']
            return redirect(url_for('main'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        nickname = request.form['nickname']
        
        hashed_password = generate_password_hash(password)
        
        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, password, nickname) VALUES (?, ?, ?)', (username, hashed_password, nickname))
        conn.commit()
        conn.close()
        
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/main')
def main():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    items = conn.execute('SELECT * FROM items ORDER BY created_at DESC').fetchall()
    conn.close()
    
    # convert image paths to URLs
    items = [dict(item) for item in items]
    nickname = session['nickname']
    for item in items:
        item['image_url'] = url_for('static', filename=convert_path_to_url(item['image_url']))
    
    return render_template('main.html', username=session['username'], items=items, nickname=nickname)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/post_item', methods=['GET', 'POST'])
def post_item():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        file = request.files['image']
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            image_url = os.path.join('uploads', filename)
            created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            nickname = session['nickname']
            conn = get_db_connection()
            conn.execute('INSERT INTO items (title, description, image_url, user_id, nickname, created_at) VALUES (?, ?, ?, ?, ?, ?)', 
                         (title, description, image_url, session['user_id'], nickname, created_at))
            conn.commit()
            conn.close()
            
            return redirect(url_for('main'))
        else:
            flash('Invalid file format. Please upload a PNG, JPG, JPEG, or GIF file.')
    
    return render_template('post_item.html')

@app.route('/item/<int:item_id>')
def item_detail(item_id):
    conn = get_db_connection()
    item = conn.execute('SELECT * FROM items WHERE id = ?', (item_id,)).fetchone()
    item = dict(item)  # sqlite3.Row 객체를 dict로 변환
    item['image_url'] = url_for('static', filename=convert_path_to_url(item['image_url']))
    
    bids = conn.execute('SELECT * FROM bids WHERE item_id = ?', (item_id,)).fetchall()
    bids = [dict(bid) for bid in bids]
    for bid in bids:
        bid['image_url'] = url_for('static', filename=convert_path_to_url(bid['image_url']))
    
    conn.close()
    return render_template('item_detail.html', item=item, bids=bids)

@app.route('/item/<int:item_id>/bid', methods=['GET', 'POST'])
def bid_item(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        file = request.files['image']
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            image_url = os.path.join('uploads', filename)
            created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            nickname = session['nickname']
            conn = get_db_connection()
            conn.execute('INSERT INTO bids (item_id, title, description, image_url, user_id, nickname, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)', 
                         (item_id, title, description, image_url, session['user_id'], nickname, created_at))
            conn.commit()
            conn.close()
            
            return redirect(url_for('item_detail', item_id=item_id))
        else:
            flash('Invalid file format. Please upload a PNG, JPG, JPEG, or GIF file.')
    
    return render_template('bid_item.html', item_id=item_id)

if __name__ == '__main__':
    app.run(debug=True)
