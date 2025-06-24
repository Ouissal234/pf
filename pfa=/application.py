from flask import Flask, render_template, request, redirect, session, send_from_directory, flash, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os
import uuid
import sqlite3
import requests
from werkzeug.utils import secure_filename
from PIL import Image
import re
from collections import Counter
from pdf2image import convert_from_path
import pytesseract
from dotenv import load_dotenv 
load_dotenv()    

from flask_apscheduler import APScheduler

os.environ['TESSDATA_PREFIX'] = r'C:\Program Files\Tesseract-OCR\tessdata'
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
scheduler = APScheduler()

@scheduler.task('interval', id='send_reminders_job', minutes=1)
def scheduled_send_reminders():
    with app.app_context():
        send_due_reminders()

from apscheduler.schedulers.background import BackgroundScheduler
scheduler = BackgroundScheduler()
def scheduled_send_reminders():
    print("Envoi automatique des rappels...")
    send_due_reminders()
app = Flask(__name__)

app.secret_key = 'secret_key_tres_forte'
app.permanent_session_lifetime = timedelta(days=30)
scheduler.add_job(scheduled_send_reminders, 'interval', minutes=5)
scheduler.start()

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
# Assure-toi que ce dossier existe bien
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
# --- Database helper ---
import os
import sqlite3
from dotenv import load_dotenv
load_dotenv()

def get_db():
    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row
    return conn
BREVO_API_KEY = os.getenv('SENDINBLUE_API_KEY')
SENDER_EMAIL = "akramououissal@gmail.com"  
SENDER_NAME = "arkivo"

def send_email(subject, html_content, to_email, to_name="Utilisateur"):
    url = "https://api.brevo.com/v3/smtp/email"
    payload = {
        "sender": {"name": SENDER_NAME, "email": SENDER_EMAIL},
        "to": [{"email": to_email, "name": to_name}],
        "subject": subject,
        "htmlContent": html_content
    }
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }
    try:
        response = requests.post(url, json=payload, headers=headers)
        print("Email sent:", response.status_code, response.text)
    except Exception as e:
        print("Erreur d'envoi:", e)

# --- Email Functions ---
def send_verification_email(email, token):
    link = url_for('verify_email', token=token, _external=True)
    html = f'<p>Merci de vous être inscrit. Cliquez ici pour vérifier : <a href="{link}">Vérifier</a></p>'
    send_email("Vérification de votre compte", html, email)

def send_password_reset_email(email, token):
    link = url_for('reset_password', token=token, _external=True)
    html = f'<p>Cliquez ici pour réinitialiser : <a href="{link}">Réinitialiser</a></p>'
    send_email("Réinitialisation du mot de passe", html, email)

# --- Routes ---

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/dashboard')
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    fullname = request.form['fullname']
    email = request.form['email']
    password = request.form['password']
    hashed = generate_password_hash(password)

    conn = get_db()
    cur = conn.cursor()

    # Vérifier si l'email est déjà utilisé
    cur.execute("SELECT id FROM users WHERE email=?", (email,))
    if cur.fetchone():
        flash("Email déjà utilisé.", "danger")
        conn.close()
        return redirect('/')

    # Créer l'utilisateur
    cur.execute("INSERT INTO users (fullname, email, password, is_verified) VALUES (?, ?, ?, ?)",
                (fullname, email, hashed, 0))
    user_id = cur.lastrowid

    # Créer le token de vérification
    token = str(uuid.uuid4())
    cur.execute("INSERT INTO email_verification (user_id, token) VALUES (?, ?)", (user_id, token))

    # 🔽 Créer les dossiers par défaut
    default_folders = ['Eau', 'Électricité', 'Assurance']
    for name in default_folders:
        cur.execute("INSERT INTO folders (name, user_id) VALUES (?, ?)", (name, user_id))

    # Commit & close
    conn.commit()
    conn.close()

    # Envoyer l'email de vérification
    send_verification_email(email, token)
    flash("Inscription réussie ! Vérifiez votre email.", "success")
    return redirect('/')


@app.route('/verify-email')
def verify_email():
    token = request.args.get('token')
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM email_verification WHERE token=?", (token,))
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE users SET is_verified=1 WHERE id=?", (row['user_id'],))
        cur.execute("DELETE FROM email_verification WHERE user_id=?", (row['user_id'],))
        conn.commit()
        flash("Email vérifié !", "success")
    else:
        flash("Lien invalide ou expiré.", "danger")
    conn.close()
    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cur.fetchone()
    conn.close()
    if user and check_password_hash(user['password'], password):
        if not user['is_verified']:
            flash("Vérifiez votre email d'abord.", "warning")
            return redirect('/')
        session['user_id'] = user['id']
        session['fullname'] = user['fullname']
        session['user_email'] = user['email']
        return redirect('/dashboard')
    flash("Identifiants invalides.", "danger")
    return redirect('/')
     

@app.route('/logout')
def logout():
    session.clear()
    flash("Déconnecté.", "info")
    return redirect('/')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email=?", (email,))
        user = cur.fetchone()
        if user:
            token = str(uuid.uuid4())
            cur.execute("DELETE FROM password_reset WHERE user_id=?", (user['id'],))
            cur.execute("INSERT INTO password_reset (user_id, token) VALUES (?, ?)", (user['id'], token))
            conn.commit()
            send_password_reset_email(email, token)
        flash("Si cet email existe, un lien a été envoyé.", "info")
        conn.close()
        return redirect('/')
    return render_template('forgot.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'GET':
        return render_template('reset_password.html', token=request.args.get('token'))

    token = request.form['token']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    # Vérifie si les deux mots de passe correspondent
    if password != confirm_password:
        flash("Mots de passe non indentiques.", "danger")
        return render_template('reset_password.html', token=token)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM password_reset WHERE token=?", (token,))
    row = cur.fetchone()

    if row:
        hashed = generate_password_hash(password)
        cur.execute("UPDATE users SET password=? WHERE id=?", (hashed, row['user_id']))
        cur.execute("DELETE FROM password_reset WHERE user_id=?", (row['user_id'],))
        conn.commit()
        flash("Mot de passe réinitialisé !", "success")
        conn.close()
        return redirect('/')
    else:
        flash("Lien invalide ou expiré.", "danger")
        conn.close()
        return redirect('/')

def add_notification(db, user_id, message, type, related_id, created_at):
    db.execute('''
        INSERT INTO notifications (user_id, message, type, related_id, is_read, created_at)
        VALUES (?, ?, ?, ?, 0, ?)
    ''', (user_id, message, type, related_id, created_at))

def time_since(dt):
    now = datetime.utcnow()
    diff = now - dt

    seconds = diff.total_seconds()
    minutes = int(seconds // 60)
    hours = int(minutes // 60)
    days = int(hours // 24)

    if seconds < 60:
        return "il y a quelques secondes"
    elif minutes < 60:
        return f"il y a {minutes} minute{'s' if minutes > 1 else ''}"
    elif hours < 24:
        return f"il y a {hours} heure{'s' if hours > 1 else ''}"
    else:
        return f"il y a {days} jour{'s' if days > 1 else ''}"

@app.route('/api/notifications')
def get_notifications():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    user_id = session['user_id']
    db = get_db()

    notifications = db.execute('''
        SELECT id, message, type, related_id, is_read, created_at
        FROM notifications
        WHERE user_id = ? AND is_read = 0
        ORDER BY created_at DESC
    ''', (user_id,)).fetchall()

    db.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0', (user_id,))
    db.commit()

    notif_list = [dict(row) for row in notifications]
    return jsonify(notif_list)

@app.route('/api/notifications/read', methods=['POST'])
def mark_notifications_read():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    db = get_db()
    db.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', (session['user_id'],))
    db.commit()

    return jsonify({'success': True})



@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    db = get_db()
    user_id = session['user_id']

    file_count = db.execute("SELECT COUNT(*) FROM files WHERE user_id = ?", (user_id,)).fetchone()[0]
    folder_count = db.execute("SELECT COUNT(*) FROM folders WHERE user_id = ?", (user_id,)).fetchone()[0]
    reminder_count = db.execute("SELECT COUNT(*) FROM reminders WHERE user_id = ?", (user_id,)).fetchone()[0]
    
    reminders = db.execute('''
        SELECT r.*, f.name AS file_name FROM reminders r
        LEFT JOIN files f ON r.file_id = f.id
        WHERE r.user_id = ?
        ORDER BY r.due_date ASC
        LIMIT 5
    ''', (user_id,)).fetchall()

    # 🧠 جلب الإشعارات
    notifications = db.execute('''
        SELECT * FROM notifications
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 10
    ''', (user_id,)).fetchall()

    notif_count = db.execute("SELECT COUNT(*) FROM notifications WHERE user_id = ?", (user_id,)).fetchone()[0]

    return render_template('dashboard.html',
                           file_count=file_count,
                           folder_count=folder_count,
                           reminder_count=reminder_count,
                           reminders=reminders,
                           notifications=notifications,
                           notif_count=notif_count)

from PIL import Image, ImageEnhance, ImageFilter
import pytesseract
import os
import fitz  # PyMuPDF
from werkzeug.utils import secure_filename
from io import BytesIO


basedir = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
from PIL import Image, ImageEnhance, ImageFilter
import pytesseract
import fitz  # PyMuPDF
from io import BytesIO

def preprocess_image(image):
    # تحويل لصورة رمادية
    image = image.convert('L')
    # رفع التباين
    enhancer = ImageEnhance.Contrast(image)
    image = enhancer.enhance(2)
    # إزالة التشويش بخاصية MedianFilter
    image = image.filter(ImageFilter.MedianFilter(size=3))
    # Thresholding: جرب تغير 120 حسب جودة الصورة
    image = image.point(lambda x: 0 if x < 120 else 255, '1')
    return image

def extract_text_from_image_file(file_stream):
    try:
        image = Image.open(file_stream)
        image = preprocess_image(image)
        # psm 6: assume a uniform block of text
        text = pytesseract.image_to_string(image, lang='fra', config='--psm 6 --oem 3')
        return text
    except Exception as e:
        print("❌ OCR Error:", e)
        return ""

def extract_text_from_file(path):
    ext = path.lower().split('.')[-1]
    if ext in ['jpeg', 'jpg', 'png']:
        try:
            image = Image.open(path)
            image = preprocess_image(image)
            text = pytesseract.image_to_string(image, lang='fra', config='--psm 6 --oem 3')
            return text
        except Exception as e:
            print("❌ OCR Image Error:", e)
            return ""
    elif ext == 'pdf':
        text = ""
        try:
            doc = fitz.open(path)
            for page in doc:
                pix = page.get_pixmap(dpi=400)  # رفع دقة الصورة
                img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                img = preprocess_image(img)
                page_text = pytesseract.image_to_string(img, lang='fra', config='--psm 6 --oem 3')
                text += page_text + "\n"
            return text
        except Exception as e:
            print("❌ OCR PDF Error:", e)
            return ""
    else:
        return ""


from utils_classifier import classify_document
# --- Files ---
@app.route('/files')
def files():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    db = get_db()
    user_id = session['user_id']
    files = db.execute('''
        SELECT f.*, fo.name AS folder_name FROM files f
        LEFT JOIN folders fo ON f.folder_id = fo.id
        WHERE f.user_id = ?
        ORDER BY f.created_at DESC
    ''', (user_id,)).fetchall()
    
    folders = db.execute("SELECT * FROM folders WHERE user_id = ?", (user_id,)).fetchall()
    notifications = db.execute('''
        SELECT * FROM notifications
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 10
    ''', (user_id,)).fetchall()

    notif_count = db.execute("SELECT COUNT(*) FROM notifications WHERE user_id = ?", (user_id,)).fetchone()[0]
    return render_template('folder.html', files=files, folders=folders,notifications=notifications,
                           notif_count=notif_count)
from flask import jsonify
import sqlite3

@app.route('/api/folder_files/<int:folder_id>')
def get_folder_files(folder_id):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT f.name
        FROM files f
        JOIN folders d ON f.folder_id = d.id
        WHERE d.id = ?
    ''', (folder_id,))
    
    files = [{'name': row[0]} for row in cursor.fetchall()]
    
    # Récupérer le nom du dossier pour l'afficher dans la modale
    cursor.execute('SELECT name FROM folders WHERE id = ?', (folder_id,))
    folder_name = cursor.fetchone()
    conn.close()
    
    return jsonify({
        'folder_name': folder_name[0] if folder_name else 'Dossier inconnu',
        'files': files
    })

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/delete_file/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    db = get_db()
    file = db.execute("SELECT * FROM files WHERE id = ? AND user_id = ?", (file_id, session['user_id'])).fetchone()
    if not file:
        flash("Fichier introuvable ou accès refusé.", "danger")
        return redirect(url_for('folders'))

    try:
        os.remove(file['path'])
    except FileNotFoundError:
        pass  # fichier déjà supprimé

    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
    flash("Fichier supprimé avec succès.", "success")
    return redirect(url_for('folders'))


def extract_text_from_file(filepath):
    if filepath.lower().endswith('.pdf'):
        images = convert_from_path(filepath)
        text = ''
        for img in images:
            text += pytesseract.image_to_string(img, lang='fra')
        return text
    elif filepath.lower().endswith(('.png', '.jpg', '.jpeg')):
        img = Image.open(filepath)
        return pytesseract.image_to_string(img, lang='fra')
    return ''

def extract_main_topic(text):
    text = text.lower()
    words = re.findall(r'\b[a-z]{4,}\b', text)
    common = set(["document", "facture", "page", "client", "nom", "date", "objet", "adresse"])
    filtered = [w for w in words if w not in common]

    if not filtered:
        return "Divers"
    top_word = Counter(filtered).most_common(1)[0][0]
    return top_word.capitalize()

def get_or_create_folder(db, user_id, folder_name):
    folder = db.execute("SELECT id FROM folders WHERE user_id = ? AND name = ?", (user_id, folder_name)).fetchone()
    if folder:
        return folder['id']
    db.execute("INSERT INTO folders (user_id, name) VALUES (?, ?)", (user_id, folder_name))
    db.commit()
    return db.execute("SELECT last_insert_rowid()").fetchone()[0]



import unicodedata

def normalize(text):
    """حيد التشكيل (accents) وبدل كلشي لحروف صغيرة"""
    return ''.join(
        c for c in unicodedata.normalize('NFD', text)
        if unicodedata.category(c) != 'Mn'
    ).lower()

import uuid

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    if 'file' not in request.files:
        flash('Aucun fichier sélectionné.', 'danger')
        return redirect(url_for('files'))

    file = request.files['file']
    if file.filename == '':
        flash('Nom de fichier invalide.', 'danger')
        return redirect(url_for('files'))

    original_filename = secure_filename(file.filename)
    ext = os.path.splitext(original_filename)[1].lower()

    # توليد اسم فريد لتفادي تعارض الملفات
    unique_filename = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

    if ext == '.pdf':
        file.save(path)
        size = os.path.getsize(path)
        text = extract_text_from_file(path)

    elif ext in ['.jpeg', '.jpg', '.png']:
        file_bytes = file.read()
        size = len(file_bytes)
        file_stream = BytesIO(file_bytes)
        text = extract_text_from_image_file(file_stream)

        file.seek(0)
        file.save(path)

    else:
        flash('Format de fichier non supporté.', 'danger')
        return redirect(url_for('files'))

    category = classify_document(text, original_filename)
    if not category:
        category = 'non_catégorisé'
    category_norm = normalize(category)

    db = get_db()
    folders = db.execute("SELECT id, name FROM folders WHERE user_id = ?", (session['user_id'],)).fetchall()

    folder_id = None
    for folder in folders:
        folder_name_norm = normalize(folder['name'])
        if folder_name_norm == category_norm:
            folder_id = folder['id']
            category = folder['name']
            break

    if folder_id is None:
        cursor = db.execute(
            "INSERT INTO folders (name, user_id) VALUES (?, ?)",
            (category, session['user_id'])
        )
        db.commit()
        folder_id = cursor.lastrowid

    db.execute('''
        INSERT INTO files (name, path, size, folder_id, user_id, category)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (original_filename, path, size, folder_id, session['user_id'], category))
    db.commit()

    flash(f'Fichier uploadé avec succès. Catégorie détectée : {category}', 'success')
    return redirect(url_for('folders'))





# --- Folders ---

@app.route('/folder')
def folders():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    db = get_db()
    user_id = session['user_id']

    # Notifications
    notifications = db.execute('''
        SELECT * FROM notifications
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 10
    ''', (user_id,)).fetchall()

    notif_count = db.execute("SELECT COUNT(*) FROM notifications WHERE user_id = ?", (user_id,)).fetchone()[0]

    # Dossiers + nombre de fichiers dans chaque dossier
    folders = db.execute('''
        SELECT folders.*, COUNT(files.id) AS file_count
        FROM folders
        LEFT JOIN files ON folders.id = files.folder_id
        WHERE folders.user_id = ?
        GROUP BY folders.id
    ''', (user_id,)).fetchall()

    return render_template('folder.html',
                           folders=folders,
                           notifications=notifications,
                           notif_count=notif_count)

# --- Add Folder ---
@app.route('/add_folder', methods=['POST'])
def add_folder():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    folder_name = request.form.get('folder_name')
    if not folder_name:
        flash("Le nom du dossier est requis.", "danger")
        return redirect(url_for('folders'))

    db = get_db()
    db.execute("INSERT INTO folders (name, user_id) VALUES (?, ?)", (folder_name, session['user_id']))
    db.commit()
    # بعد db.commit()
    folder_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    add_notification(db, session['user_id'], f'📂 Nouveau dossier "{folder_name}" créé.', 'folder', folder_id)
    db.commit()

    flash("Dossier ajouté avec succès.", "success")
    return redirect(url_for('folders'))
# --- Delete Folder ---
@app.route('/delete_folder/<int:folder_id>', methods=['POST'])
def delete_folder(folder_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))

    db = get_db()

    # تأكد أن dossier كيخص نفس المستخدم
    folder = db.execute("SELECT * FROM folders WHERE id = ? AND user_id = ?", (folder_id, session['user_id'])).fetchone()
    if folder is None:
        flash("Accès refusé ou dossier introuvable.", "danger")
        return redirect(url_for('folders'))

    # امسح جميع الملفات المرتبطة (اختياري، حسب منطق التطبيق)
    db.execute("DELETE FROM files WHERE folder_id = ? AND user_id = ?", (folder_id, session['user_id']))
    
    # امسح dossier
    db.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
    db.commit()

    flash("Dossier supprimé avec succès.", "success")
    return redirect(url_for('folders'))

# --- Reminders ---

@app.route('/reminders')
def reminders():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    send_due_reminders(session['user_id'])

    db = get_db()
    reminders = db.execute('''
        SELECT r.*, f.name AS file_name FROM reminders r
        LEFT JOIN files f ON r.file_id = f.id
        WHERE r.user_id = ?
        ORDER BY r.due_date ASC
    ''', (session['user_id'],)).fetchall()

    files = db.execute('SELECT * FROM files WHERE user_id = ?', (session['user_id'],)).fetchall()

    return render_template('reminders.html', reminders=reminders, files=files)


# -------------------- ADD REMINDER --------------------
from datetime import datetime

@app.route('/add_reminder', methods=['POST'])
def add_reminder():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    title = request.form.get('title', '').strip()
    date_part = request.form.get('due_date', '').strip()
    time_part = request.form.get('due_time', '').strip()
    file_id = request.form.get('file_id')

    if not title or not date_part:
        flash('Tous les champs sont obligatoires.', 'danger')
        return redirect(url_for('reminders'))

    if not time_part:
        time_part = '00:00'

    try:
        full_datetime_str = f"{date_part} {time_part}:00"  # Ex: "2025-06-14 15:30:00"
        due_date = datetime.strptime(full_datetime_str, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        flash("Format de date ou d'heure invalide.", "danger")
        return redirect(url_for('reminders'))

    if file_id == '':
        file_id = None

    db = get_db()
    db.execute('''
        INSERT INTO reminders (title, due_date, user_id, file_id, email_sent)
        VALUES (?, ?, ?, ?, 0)
    ''', (title, due_date.strftime('%Y-%m-%d %H:%M:%S'), session['user_id'], file_id))
    db.commit()
    # بعد db.commit()
    reminder_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    add_notification(db, session['user_id'], f'⏰ Nouveau rappel "{title}" ajouté.', 'reminder', reminder_id, created_at= datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    db.commit()

    flash('Rappel ajouté avec succès.', 'success')
    return redirect(url_for('reminders'))


# -------------------- DELETE REMINDER --------------------
@app.route('/delete_reminder/<int:reminder_id>', methods=['POST'])
def delete_reminder(reminder_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    

    db = get_db()
    # Vérifie que le rappel appartient bien à l'utilisateur
    reminder = db.execute('SELECT * FROM reminders WHERE id = ? AND user_id = ?', 
                          (reminder_id, session['user_id'])).fetchone()
    if not reminder:
        flash("Rappel introuvable ou accès refusé.", "danger")
        return redirect(url_for('reminders'))

    db.execute('DELETE FROM reminders WHERE id = ?', (reminder_id,))
    db.commit()

    flash("Rappel supprimé avec succès.", "success")
    return redirect(url_for('reminders'))

def send_email_reminder(to_email, subject, content):
    url = "https://api.brevo.com/v3/smtp/email"
    payload = {
        "sender": {"name": SENDER_NAME, "email": SENDER_EMAIL},
        "to": [{"email": to_email}],
        "subject": subject,
        "textContent": content
    }
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        print(f"Email sent to {to_email}, status code: {response.status_code}")
        if response.status_code >= 400:
            print("Error response:", response.text)
    except Exception as e:
        print(f"Error sending email to {to_email}: {e}")
import atexit

# الدالة اللي غادي تبعث التذكيرات
def send_due_reminders(job=None):
    print(f"[{datetime.now()}] Checking reminders...")
    db = get_db()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    reminders = db.execute('''
        SELECT * FROM reminders
        WHERE due_date <= ? AND email_sent = 0
    ''', (now,)).fetchall()

    for reminder in reminders:
        user = db.execute('SELECT email FROM users WHERE id = ?', (reminder['user_id'],)).fetchone()
        if user and user['email']:
            # هنا عاود عوض send_email_reminder بالكود ديالك
            send_email_reminder(user['email'], f"Reminder: {reminder['title']}",
                                f"Votre rappel '{reminder['title']}' est prévu pour le {reminder['due_date']}.")
            db.execute('UPDATE reminders SET email_sent = 1 WHERE id = ?', (reminder['id'],))
            db.commit()
    print(f"[{datetime.now()}] Reminders processed.")
scheduler = BackgroundScheduler()
scheduler.add_job(func=send_due_reminders, trigger="interval", minutes=1)  # كل دقيقة (جرب في البداية 1 دقيقة)
scheduler.start()

# تأكد من إيقاف scheduler عند إيقاف التطبيق
atexit.register(lambda: scheduler.shutdown())

@app.route('/')
def home():
    return "App is running with scheduled reminder sender!"



@app.route('/account')
def account():
    return render_template('account.html')
from datetime import datetime

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%d/%m/%Y %H:%M'):
    if value is None:
        return ""
    # value ممكن يكون نص، أو datetime object
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value  # إذا ما قدرناش نحوله، نرجع النص كما هو
    return value.strftime(format)

@app.route('/folders/<int:folder_id>/content')
def folder_content(folder_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))

    db = get_db()
    user_id = session['user_id']

    # نتأكد من أن الفولدر يخص المستخدم
    folder = db.execute("SELECT * FROM folders WHERE id = ? AND user_id = ?", (folder_id, user_id)).fetchone()
    if not folder:
        return "<p>Dossier non trouvé ou accès refusé.</p>"

    files = db.execute("SELECT * FROM files WHERE folder_id = ? AND user_id = ?", (folder_id, user_id)).fetchall()

    # نرجع جزء HTML صغير فقط
    return render_template('folder_content.html', folder=folder, files=files)
@app.route('/users')
def show_users():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    db = get_db()
    users = db.execute("SELECT id, fullname, email FROM users").fetchall()
    
    # نقدر نرجعهم نصياً بسيطاً، ولا تعمّل template مخصصة
    
    users_list = ""
    for user in users:
        users_list += f"ID: {user['id']} - Name: {user['fullname']} - Email: {user['email']}<br>"
    
    return users_list


# --- Database setup ---
def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullname TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        is_verified INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS email_verification (
        user_id INTEGER PRIMARY KEY,
        token TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS password_reset (
        user_id INTEGER PRIMARY KEY,
        token TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS folders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        user_id INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        path TEXT NOT NULL,
        size INTEGER,
        folder_id INTEGER,
        user_id INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS reminders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        due_date TEXT NOT NULL,
        is_paid INTEGER DEFAULT 0,
        file_id INTEGER,
        user_id INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        type TEXT, -- file, folder, reminder...
        related_id INTEGER, -- id ديال العنصر المرتبط
        is_read INTEGER DEFAULT 0
    );
    ''')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
   