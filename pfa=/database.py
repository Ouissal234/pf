import sqlite3
from werkzeug.security import generate_password_hash

def init_db():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()

    # جدول المستخدمين
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullname TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_verified INTEGER DEFAULT 0,
        reset_token TEXT,
        reset_token_expiration TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # جدول العملاء
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        nom TEXT NOT NULL,
        email TEXT,
        telephone TEXT,
        adresse TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')

    # جدول الفواتير
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS factures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        client_id INTEGER,
        numero TEXT NOT NULL,
        date TEXT NOT NULL,
        montant REAL NOT NULL,
        statut TEXT DEFAULT 'impayé',
        fichier_path TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (client_id) REFERENCES clients(id)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS email_verification(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')

    # جدول الفئات
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        nom TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')

    # جدول المجلدات
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS folders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')

    # جدول الملفات
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        path TEXT NOT NULL,
        size INTEGER NOT NULL,
        folder_id INTEGER,
        user_id INTEGER NOT NULL,
        category TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (folder_id) REFERENCES folders(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
                   
    ''')
    try:
        cursor.execute("ALTER TABLE files ADD COLUMN category TEXT")
    except sqlite3.OperationalError as e:
        print("⚠️ Peut-être déjà ajoutée :", e)

        # جدول التذكيرات
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS reminders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        due_date TEXT NOT NULL,
        is_paid BOOLEAN DEFAULT 0,
        file_id INTEGER,
        user_id INTEGER NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now')),
        email_sent INTEGER DEFAULT 0,
        FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE SET NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    type TEXT,
    related_id INTEGER,
    is_read INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
''')
    try:
        cursor.execute("ALTER TABLE notifications ADD COLUMN created_at TEXT;")
    except sqlite3.OperationalError as e:
        if "duplicate column name" not in str(e).lower():
            raise e
    
    # إضافة عمود email_sent إذا ماكانش موجود
    try:
        cursor.execute("ALTER TABLE reminders ADD COLUMN email_sent INTEGER DEFAULT 0;")
    except sqlite3.OperationalError as e:
        if "duplicate column name" not in str(e).lower():
            raise e

    # جدول إعادة تعيين كلمة المرور
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS password_reset (
        user_id INTEGER,
        token TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')

    # إضافة أدمن افتراضي إذا ماكانش
    try:
        cursor.execute(
            "INSERT INTO users (fullname, email, password, is_verified) VALUES (?, ?, ?, ?)",
            ('Admin', 'admin@example.com', generate_password_hash('admin123'), 1)
        )
    except sqlite3.IntegrityError:
        pass  # موجود من قبل

    conn.commit()
    conn.close()
    print("✅ Base de données initialisée avec succès!")

if __name__ == '__main__':
    init_db()
