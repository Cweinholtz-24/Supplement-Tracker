import os, json, io, base64, sqlite3, psutil, time, csv
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify, Response, flash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, datetime, timedelta
from pathlib import Path
import pyotp
import qrcode
import csv

app = Flask(__name__)
app.secret_key = "super_secure_key"
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

DATA_DIR = Path("data")
USER_DIR = DATA_DIR / "users"
USER_DIR.mkdir(parents=True, exist_ok=True)

# Database setup
DB_PATH = DATA_DIR / "supplement_tracker.db"

# Store app start time for uptime calculation
APP_START_TIME = time.time()

def init_db():
    """Initialize the database with required tables"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                twofa_secret TEXT NOT NULL,
                email TEXT DEFAULT '',
                disabled BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                login_attempts INTEGER DEFAULT 0,
                last_failed_login TIMESTAMP,
                ip_address TEXT DEFAULT '',
                custom_fields TEXT DEFAULT '{}',
                location TEXT DEFAULT ''
            )
        ''')

        # Add missing columns if they don't exist
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN location TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # Column already exists

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN custom_fields TEXT DEFAULT '{}'")
        except sqlite3.OperationalError:
            pass  # Column already exists

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN ip_address TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # Column already exists

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN login_attempts INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # Column already exists

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN last_failed_login TIMESTAMP")
        except sqlite3.OperationalError:
            pass  # Column already exists

        # Admins table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                twofa_secret TEXT NOT NULL,
                role TEXT DEFAULT 'Admin',
                email TEXT DEFAULT '',
                disabled BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                permissions TEXT DEFAULT '{}',
                login_attempts INTEGER DEFAULT 0,
                last_failed_login TIMESTAMP
            )
        ''')

        # Add missing columns if they don't exist
        try:
            cursor.execute("ALTER TABLE admins ADD COLUMN permissions TEXT DEFAULT '{}'")
        except sqlite3.OperationalError:
            pass  # Column already exists

        try:
            cursor.execute("ALTER TABLE admins ADD COLUMN login_attempts INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # Column already exists

        try:
            cursor.execute("ALTER TABLE admins ADD COLUMN last_failed_login TIMESTAMP")
        except sqlite3.OperationalError:
            pass  # Column already exists

        # Protocols table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS protocols (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                compounds TEXT NOT NULL,
                is_template BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, name)
            )
        ''')

        # Protocol logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS protocol_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol_id INTEGER NOT NULL,
                log_date DATE NOT NULL,
                compound TEXT NOT NULL,
                taken BOOLEAN DEFAULT FALSE,
                note TEXT DEFAULT '',
                mood TEXT DEFAULT '',
                energy TEXT DEFAULT '',
                side_effects TEXT DEFAULT '',
                weight TEXT DEFAULT '',
                general_notes TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (protocol_id) REFERENCES protocols (id),
                UNIQUE(protocol_id, log_date, compound)
            )
        ''')

        # App configuration table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS app_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_by TEXT DEFAULT ''
            )
        ''')

        # Add missing columns if they don't exist
        try:
            cursor.execute("ALTER TABLE app_config ADD COLUMN updated_by TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # Column already exists

        # System monitoring table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_type TEXT NOT NULL,
                message TEXT NOT NULL,
                severity TEXT DEFAULT 'info',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                ip_address TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Notifications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                type TEXT DEFAULT 'info',
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Support tickets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS support_tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT DEFAULT 'open',
                priority TEXT DEFAULT 'medium',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Announcements table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS announcements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                type TEXT DEFAULT 'info',
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
        ''')

        # IP blacklist table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT DEFAULT ''
            )
        ''')

        # Insert default config values
        default_configs = [
            ('app_name', 'Supplement Tracker'),
            ('max_protocols_per_user', '10'),
            ('email_reminders_enabled', 'true'),
            ('registration_enabled', 'true'),
            ('data_export_enabled', 'true'),
            ('analytics_enabled', 'true'),
            ('sendgrid_api_key', ''),
            ('sendgrid_from_email', ''),
            ('maintenance_mode', 'false'),
            ('max_login_attempts', '5'),
            ('session_timeout', '30'),
            ('password_min_length', '8'),
            ('require_2fa', 'true'),
            ('force_2fa_setup', 'true'),
            ('password_complexity', 'true')
        ]

        for key, value in default_configs:
            cursor.execute('''
                INSERT OR IGNORE INTO app_config (key, value) 
                VALUES (?, ?)
            ''', (key, value))

        conn.commit()

def get_db_connection():
    """Get database connection"""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=20.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=1000")
        conn.execute("PRAGMA temp_store=MEMORY")
        return conn
    except sqlite3.Error as e:
        log_system_event('database_error', f'Database connection error: {str(e)}', 'error')
        raise

def get_app_config():
    """Get all app configuration from database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM app_config")
        return {row[0]: row[1] for row in cursor.fetchall()}

def get_config_value(key, default=None):
    """Get a specific config value from database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM app_config WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row[0] if row else default

def validate_password_complexity(password):
    """Validate password meets complexity requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    has_upper = any(c.isupper() for c in password)
    has_number = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

    if not has_upper:
        return False, "Password must contain at least one uppercase letter"
    if not has_number:
        return False, "Password must contain at least one number"
    if not has_special:
        return False, "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"

    return True, "Password meets complexity requirements"

def user_has_valid_2fa(username):
    """Check if user has a valid 2FA secret"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT twofa_secret FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return row and row[0] and len(row[0]) > 10

def admin_has_valid_2fa(username):
    """Check if admin has a valid 2FA secret"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT twofa_secret FROM admins WHERE username = ?", (username,))
        row = cursor.fetchone()
        return row and row[0] and len(row[0]) > 10

def log_system_event(log_type, message, severity='info', user_id=None, ip_address=None):
    """Log system events for monitoring"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO system_logs (log_type, message, severity, user_id, ip_address)
            VALUES (?, ?, ?, ?, ?)
        ''', (log_type, message, severity, user_id, ip_address))
        conn.commit()

def get_system_stats():
    """Get system statistics"""
    try:
        uptime = time.time() - APP_START_TIME
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        return {
            'uptime': uptime,
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'disk_percent': disk.percent,
            'memory_used': memory.used,
            'memory_total': memory.total,
            'disk_used': disk.used,
            'disk_total': disk.total
        }
    except Exception as e:
        return {'error': str(e)}

# Initialize database on startup
init_db()

class User(UserMixin):
    def __init__(self, username, user_id=None):
        self.id = username
        self.user_id = user_id

    @staticmethod
    def get(username):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                return User(username, row[0])
        return None

class Admin(UserMixin):
    def __init__(self, username, admin_id=None, role=None):
        self.id = f"admin_{username}"
        self.admin_id = admin_id
        self.username = username
        self.role = role

    @staticmethod
    def get(username):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, role FROM admins WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                return Admin(username, row[0], row[1])
        return None

@login_manager.user_loader
def load_user(user_id):
    if user_id.startswith("admin_"):
        admin_username = user_id.replace("admin_", "")
        return Admin.get(admin_username)
    return User.get(user_id)

def load_data(username=None):
    """Load user data from database"""
    username = username or current_user.id
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT password_hash, twofa_secret, email 
                FROM users WHERE username = ?
            ''', (username,))
            row = cursor.fetchone()
            if not row:
                return {"password": "", "2fa_secret": "", "protocols": {}, "email": ""}

            cursor.execute('''
                SELECT name, compounds FROM protocols 
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
            ''', (username,))
            protocols = {}
            for protocol_row in cursor.fetchall():
                protocol_name = protocol_row[0]
                try:
                    compounds = json.loads(protocol_row[1])
                except json.JSONDecodeError:
                    compounds = []

                cursor.execute('''
                    SELECT log_date, compound, taken, note, mood, energy, side_effects, weight, general_notes
                    FROM protocol_logs pl
                    JOIN protocols p ON pl.protocol_id = p.id
                    WHERE p.name = ? AND p.user_id = (SELECT id FROM users WHERE username = ?)
                ''', (protocol_name, username))

                logs = {}
                for log_row in cursor.fetchall():
                    log_date = log_row[0]
                    if log_date not in logs:
                        logs[log_date] = {}
                    logs[log_date][log_row[1]] = {
                        "taken": bool(log_row[2]),
                        "note": log_row[3] or "",
                        "mood": log_row[4] or "",
                        "energy": log_row[5] or "",
                        "side_effects": log_row[6] or "",
                        "weight": log_row[7] or "",
                        "notes": log_row[8] or ""
                    }

                protocols[protocol_name] = {
                    "compounds": compounds,
                    "logs": logs
                }

            return {
                "password": row[0],
                "2fa_secret": row[1],
                "email": row[2] or "",
                "protocols": protocols
            }
    except sqlite3.Error as e:
        log_system_event('database_error', f'Error loading data for user {username}: {str(e)}', 'error')
        return {"password": "", "2fa_secret": "", "protocols": {}, "email": ""}

def save_data(data, username=None):
    """Save user data to database"""
    username = username or current_user.id
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                UPDATE users SET email = ? WHERE username = ?
            ''', (data.get("email", ""), username))

            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            user_row = cursor.fetchone()
            if not user_row:
                return
            user_id = user_row[0]

            for protocol_name, protocol_data in data.get("protocols", {}).items():
                compounds = json.dumps(protocol_data.get("compounds", []))

                cursor.execute('''
                    INSERT OR REPLACE INTO protocols (user_id, name, compounds)
                    VALUES (?, ?, ?)
                ''', (user_id, protocol_name, compounds))

                cursor.execute("SELECT id FROM protocols WHERE user_id = ? AND name = ?", 
                             (user_id, protocol_name))
                protocol_row = cursor.fetchone()
                if not protocol_row:
                    continue
                protocol_id = protocol_row[0]

                logs = protocol_data.get("logs", {})
                for log_date, entries in logs.items():
                    for compound, entry_data in entries.items():
                        cursor.execute('''
                            INSERT OR REPLACE INTO protocol_logs 
                            (protocol_id, log_date, compound, taken, note, mood, energy, 
                             side_effects, weight, general_notes)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (protocol_id, log_date, compound,
                              entry_data.get("taken", False),
                              entry_data.get("note", ""),
                              entry_data.get("mood", ""),
                              entry_data.get("energy", ""),
                              entry_data.get("side_effects", ""),
                              entry_data.get("weight", ""),
                              entry_data.get("notes", "")))

            conn.commit()
    except sqlite3.Error as e:
        log_system_event('database_error', f'Error saving data for user {username}: {str(e)}', 'error')
        raise

@app.route("/register", methods=["GET", "POST"])
def register():
    if get_config_value('registration_enabled', 'true') != 'true':
        flash("Registration is currently disabled", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]

        if not username or not password:
            flash("Username and password are required", "error")
            return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Register", action="register")

        if len(username) < 3:
            flash("Username must be at least 3 characters", "error")
            return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Register", action="register")

        # Check password complexity if enabled
        if get_config_value('password_complexity', 'true') == 'true':
            is_valid, error_msg = validate_password_complexity(password)
            if not is_valid:
                flash(error_msg, "error")
                return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Register", action="register")
        else:
            min_password_length = int(get_config_value('password_min_length', '8'))
            if len(password) < min_password_length:
                flash(f"Password must be at least {min_password_length} characters", "error")
                return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Register", action="register")

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                flash("Username already exists", "error")
                return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Register", action="register")

            cursor.execute("SELECT id FROM admins WHERE username = ?", (username,))
            if cursor.fetchone():
                flash("Username conflicts with admin account", "error")
                return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Register", action="register")

            secret = pyotp.random_base32()
            cursor.execute('''
                INSERT INTO users (username, password_hash, twofa_secret, email)
                VALUES (?, ?, ?, ?)
            ''', (username, generate_password_hash(password), secret, ""))
            conn.commit()

        log_system_event('user_registration', f'New user registered: {username}', 'info')
        session["pending_user"] = username
        flash("Account created successfully! Please set up 2FA.", "success")
        return redirect(url_for("twofa_setup"))
    return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Register", action="register")

@app.route("/admin/register", methods=["GET", "POST"])
def admin_register():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]
        role = request.form.get("role", "Admin")

        if not username or not password:
            flash("Username and password are required", "error")
            return render_template_string(THEME_HEADER + ADMIN_AUTH_TEMPLATE, title="Admin Register", action="admin/register")

        if len(username) < 3:
            flash("Username must be at least 3 characters", "error")
            return render_template_string(THEME_HEADER + ADMIN_AUTH_TEMPLATE, title="Admin Register", action="admin/register")

        # Check password complexity if enabled
        if get_config_value('password_complexity', 'true') == 'true':
            is_valid, error_msg = validate_password_complexity(password)
            if not is_valid:
                flash(error_msg, "error")
                return render_template_string(THEME_HEADER + ADMIN_AUTH_TEMPLATE, title="Admin Register", action="admin/register")
        else:
            min_password_length = int(get_config_value('password_min_length', '8'))
            if len(password) < min_password_length:
                flash(f"Password must be at least {min_password_length} characters", "error")
                return render_template_string(THEME_HEADER + ADMIN_AUTH_TEMPLATE, title="Admin Register", action="admin/register")

        if role not in ["Super Admin", "Admin", "Operator"]:
            flash("Invalid role selected", "error")
            return render_template_string(THEME_HEADER + ADMIN_AUTH_TEMPLATE, title="Admin Register", action="admin/register")

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                flash("Username conflicts with user account", "error")
                return render_template_string(THEME_HEADER + ADMIN_AUTH_TEMPLATE, title="Admin Register", action="admin/register")

            cursor.execute("SELECT id FROM admins WHERE username = ?", (username,))
            if cursor.fetchone():
                flash("Admin already exists", "error")
                return render_template_string(THEME_HEADER + ADMIN_AUTH_TEMPLATE, title="Admin Register", action="admin/register")

            secret = pyotp.random_base32()
            cursor.execute('''
                INSERT INTO admins (username, password_hash, twofa_secret, role, email)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, generate_password_hash(password), secret, role, ""))
            conn.commit()

        log_system_event('admin_registration', f'New admin registered: {username} ({role})', 'info')
        session["pending_admin"] = username
        flash("Admin account created successfully! Please set up 2FA.", "success")
        return redirect(url_for("admin_twofa_setup"))
    return render_template_string(THEME_HEADER + ADMIN_AUTH_TEMPLATE, title="Admin Register", action="admin/register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]
        client_ip = request.remote_addr

        if not username or not password:
            flash("Username and password are required", "error")
            return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Login", action="login")

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash, login_attempts FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if not row:
                log_system_event('login_failed', f'Login attempt for non-existent user: {username}', 'warning', ip_address=client_ip)
                flash("User not found", "error")
                return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Login", action="login")

            max_attempts = int(get_config_value('max_login_attempts', '5'))
            if row[1] >= max_attempts:
                log_system_event('login_blocked', f'Login blocked for user: {username} (too many attempts)', 'warning', ip_address=client_ip)
                flash("Account temporarily locked due to too many failed attempts", "error")
                return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Login", action="login")

            if not check_password_hash(row[0], password):
                cursor.execute("UPDATE users SET login_attempts = login_attempts + 1, last_failed_login = CURRENT_TIMESTAMP WHERE username = ?", (username,))
                conn.commit()
                log_system_event('login_failed', f'Invalid password for user: {username}', 'warning', ip_address=client_ip)
                flash("Incorrect password", "error")
                return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Login", action="login")

            cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP, login_attempts = 0, ip_address = ? WHERE username = ?", (client_ip, username))
            conn.commit()

        log_system_event('login_success', f'User logged in: {username}', 'info', ip_address=client_ip)
        session["pending_user"] = username
        return redirect(url_for("twofa_verify"))
    return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Login", action="login")

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]
        client_ip = request.remote_addr

        if not username or not password:
            flash("Username and password are required", "error")
            return render_template_string(THEME_HEADER + ADMIN_AUTH_TEMPLATE, title="Admin Login", action="admin/login")

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash, login_attempts FROM admins WHERE username = ?", (username,))
            row = cursor.fetchone()
            if not row:
                log_system_event('admin_login_failed', f'Admin login attempt for non-existent user: {username}', 'warning', ip_address=client_ip)
                flash("Admin not found", "error")
                return render_template_string(THEME_HEADER + ADMIN_AUTH_TEMPLATE, title="Admin Login", action="admin/login")

            max_attempts = int(get_config_value('max_login_attempts', '5'))
            if row[1] >= max_attempts:
                log_system_event('admin_login_blocked', f'Admin login blocked for user: {username} (too many attempts)', 'warning', ip_address=client_ip)
                flash("Account temporarily locked due to too many failed attempts", "error")
                return render_template_string(THEME_HEADER + ADMIN_AUTH_TEMPLATE, title="Admin Login", action="admin/login")

            if not check_password_hash(row[0], password):
                cursor.execute("UPDATE admins SET login_attempts = login_attempts + 1, last_failed_login = CURRENT_TIMESTAMP WHERE username = ?", (username,))
                conn.commit()
                log_system_event('admin_login_failed', f'Invalid password for admin: {username}', 'warning', ip_address=client_ip)
                flash("Incorrect password", "error")
                return render_template_string(THEME_HEADER + ADMIN_AUTH_TEMPLATE, title="Admin Login", action="admin/login")

            cursor.execute("UPDATE admins SET last_login = CURRENT_TIMESTAMP, login_attempts = 0 WHERE username = ?", (username,))
            conn.commit()

        log_system_event('admin_login_success', f'Admin logged in: {username}', 'info', ip_address=client_ip)
        session["pending_admin"] = username
        return redirect(url_for("admin_twofa_verify"))
    return render_template_string(THEME_HEADER + ADMIN_AUTH_TEMPLATE, title="Admin Login", action="admin/login")

@app.route("/2fa", methods=["GET", "POST"])
def twofa_verify():
    username = session.get("pending_user")
    if not username:
        flash("Session expired. Please login again.", "error")
        return redirect(url_for("login"))
    data = load_data(username)
    if request.method == "POST":
        code = request.form["code"]
        if not code or len(code) != 6:
            flash("Please enter a valid 6-digit code", "error")
            return render_template_string(THEME_HEADER + TWOFA_TEMPLATE)
        if pyotp.TOTP(data["2fa_secret"]).verify(code):
            login_user(User(username))
            session.pop("pending_user")
            flash("Successfully logged in!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid 2FA code. Please try again.", "error")
            return render_template_string(THEME_HEADER + TWOFA_TEMPLATE)
    return render_template_string(THEME_HEADER + TWOFA_TEMPLATE)

@app.route("/admin/2fa", methods=["GET", "POST"])
def admin_twofa_verify():
    username = session.get("pending_admin")
    if not username:
        flash("Session expired. Please login again.", "error")
        return redirect(url_for("admin_login"))
    data = load_admin_data(username)
    if request.method == "POST":
        code = request.form["code"]
        if not code or len(code) != 6:
            flash("Please enter a valid 6-digit code", "error")
            return render_template_string(THEME_HEADER + TWOFA_TEMPLATE)
        if pyotp.TOTP(data["2fa_secret"]).verify(code):
            admin = Admin.get(username)
            login_user(admin)
            session.pop("pending_admin")
            flash("Successfully logged in as admin!", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid 2FA code. Please try again.", "error")
            return render_template_string(THEME_HEADER + TWOFA_TEMPLATE)
    return render_template_string(THEME_HEADER + TWOFA_TEMPLATE)

def load_admin_data(username):
    """Load admin data from database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT password_hash, twofa_secret, email, role 
            FROM admins WHERE username = ?
        ''', (username,))
        row = cursor.fetchone()
        if not row:
            return {"password": "", "2fa_secret": "", "email": "", "role": ""}

        return {
            "password": row[0],
            "2fa_secret": row[1],
            "email": row[2] or "",
            "role": row[3] or "Admin"
        }

def is_admin():
    """Check if current user is an admin"""
    return hasattr(current_user, 'role') and current_user.is_authenticated

def admin_required(f):
    """Decorator to require admin authentication"""
    def decorated_function(*args, **kwargs):
        if not is_admin():
            flash("Admin access required", "error")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def require_2fa_setup(f):
    """Decorator to force 2FA setup if not completed"""
    def decorated_function(*args, **kwargs):
        if get_config_value('force_2fa_setup', 'true') == 'true':
            if current_user.is_authenticated:
                # Check if this is an admin user
                if hasattr(current_user, 'role'):
                    if not admin_has_valid_2fa(current_user.username):
                        if request.endpoint not in ['admin_twofa_setup', 'admin_logout', 'admin_2fa_setup_complete']:
                            flash("Please complete 2FA setup before continuing", "warning")
                            return redirect(url_for("admin_twofa_setup"))
                else:
                    if not user_has_valid_2fa(current_user.id):
                        if request.endpoint not in ['twofa_setup', 'logout', 'twofa_setup_complete']:
                            flash("Please complete 2FA setup before continuing", "warning")
                            return redirect(url_for("twofa_setup"))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def super_admin_required(f):
    """Decorator to require super admin authentication"""
    def decorated_function(*args, **kwargs):
        if not is_admin() or current_user.role != "Super Admin":
            flash("Super Admin access required", "error")
            return redirect(url_for("admin_dashboard"))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route("/2fa_setup_complete", methods=["POST"])
def twofa_setup_complete():
    username = session.get("pending_user")
    if not username:
        flash("Session expired. Please login again.", "error")
        return redirect(url_for("login"))

    code = request.form.get("code")
    if not code or len(code) != 6:
        flash("Please enter a valid 6-digit code", "error")
        return redirect(url_for("twofa_setup"))

    data = load_data(username)
    if pyotp.TOTP(data["2fa_secret"]).verify(code):
        login_user(User(username))
        session.pop("pending_user")
        flash("2FA setup completed successfully!", "success")
        return redirect(url_for("dashboard"))
    else:
        flash("Invalid 2FA code. Please try again.", "error")
        return redirect(url_for("twofa_setup"))

@app.route("/admin/2fa_setup_complete", methods=["POST"])
def admin_twofa_setup_complete():
    username = session.get("pending_admin")
    if not username:
        flash("Session expired. Please login again.", "error")
        return redirect(url_for("admin_login"))

    code = request.form.get("code")
    if not code or len(code) != 6:
        flash("Please enter a valid 6-digit code", "error")
        return redirect(url_for("admin_twofa_setup"))

    data = load_admin_data(username)
    if pyotp.TOTP(data["2fa_secret"]).verify(code):
        admin = Admin.get(username)
        login_user(admin)
        session.pop("pending_admin")
        flash("Admin 2FA setup completed successfully!", "success")
        return redirect(url_for("admin_dashboard"))
    else:
        flash("Invalid 2FA code. Please try again.", "error")
        return redirect(url_for("admin_twofa_setup"))

@app.route("/2fa_setup")
def twofa_setup():
    username = session.get("pending_user")
    if not username:
        flash("Session expired. Please login again.", "error")
        return redirect(url_for("login"))

    data = load_data(username)
    if not data.get("2fa_secret"):
        flash("2FA secret not found. Please try registering again.", "error")
        return redirect(url_for("register"))

    try:
        uri = pyotp.TOTP(data["2fa_secret"]).provisioning_uri(
            name=username,
            issuer_name="SupplementTracker"
        )

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        encoded = base64.b64encode(buf.read()).decode()

        return render_template_string(THEME_HEADER + TWOFA_SETUP_TEMPLATE,
                                    qr_code=encoded, 
                                    secret=data['2fa_secret'],
                                    username=username,
                                    is_forced=True)

    except Exception as e:
        flash(f"Error generating 2FA setup: {str(e)}", "error")
        return redirect(url_for("register"))

@app.route("/admin/2fa_setup")
def admin_twofa_setup():
    username = session.get("pending_admin")
    if not username:
        flash("Session expired. Please login again.", "error")
        return redirect(url_for("admin_login"))

    data = load_admin_data(username)
    if not data.get("2fa_secret"):
        flash("2FA secret not found. Please try registering again.", "error")
        return redirect(url_for("admin_register"))

    try:
        uri = pyotp.TOTP(data["2fa_secret"]).provisioning_uri(
            name=f"admin_{username}",
            issuer_name="SupplementTracker-Admin"
        )

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        encoded = base64.b64encode(buf.read()).decode()

        return render_template_string(THEME_HEADER + ADMIN_TWOFA_SETUP_TEMPLATE,
                                    qr_code=encoded, 
                                    secret=data['2fa_secret'],
                                    username=username,
                                    is_forced=True)

    except Exception as e:
        flash(f"Error generating admin 2FA setup: {str(e)}", "error")
        return redirect(url_for("admin_register"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/admin/logout")
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for("admin_login"))

@app.route("/admin/dashboard")
@login_required
@admin_required
@require_2fa_setup
def admin_dashboard():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Get app configuration
        cursor.execute("SELECT key, value FROM app_config")
        config = {row[0]: row[1] for row in cursor.fetchall()}

        # Get user count
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]

        # Get admin count
        cursor.execute("SELECT COUNT(*) FROM admins")
        admin_count = cursor.fetchone()[0]

        # Get protocol count
        cursor.execute("SELECT COUNT(*) FROM protocols")
        protocol_count = cursor.fetchone()[0]

        # Get recent activity
        cursor.execute("SELECT username, last_login FROM users ORDER BY last_login DESC LIMIT 10")
        recent_users = cursor.fetchall()

        # Get system stats
        system_stats = get_system_stats()

        # Get all admins (for super admin)
        admins = []
        if current_user.role == "Super Admin":
            cursor.execute("SELECT username, role, email, last_login, disabled, id FROM admins ORDER BY username")
            admins = cursor.fetchall()

        # Get recent system logs
        cursor.execute("SELECT log_type, message, severity, created_at FROM system_logs ORDER BY created_at DESC LIMIT 20")
        recent_logs = cursor.fetchall()

        # Get active announcements
        cursor.execute("SELECT title, content, type FROM announcements WHERE active = 1 AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)")
        announcements = cursor.fetchall()

    return render_template_string(THEME_HEADER + ADMIN_DASHBOARD_TEMPLATE, 
                                config=config, 
                                user_count=user_count,
                                admin_count=admin_count,
                                protocol_count=protocol_count,
                                recent_users=recent_users,
                                admins=admins,
                                system_stats=system_stats,
                                recent_logs=recent_logs,
                                announcements=announcements,
                                current_admin=current_user)

@app.route("/admin/config", methods=["POST"])
@login_required
@admin_required
def update_config():
    if current_user.role not in ["Super Admin", "Admin"]:
        flash("Insufficient permissions to modify configuration", "error")
        return redirect(url_for("admin_dashboard"))

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Check if updated_by column exists
        cursor.execute("PRAGMA table_info(app_config)")
        columns = [row[1] for row in cursor.fetchall()]
        has_updated_by = 'updated_by' in columns

        # Update configuration values
        for key in ["app_name", "max_protocols_per_user", "sendgrid_api_key", "sendgrid_from_email", "password_min_length", "max_login_attempts", "session_timeout"]:
            value = request.form.get(key)
            if value is not None:
                if has_updated_by:
                    cursor.execute('''
                        INSERT OR REPLACE INTO app_config (key, value, updated_at, updated_by)
                        VALUES (?, ?, CURRENT_TIMESTAMP, ?)
                    ''', (key, value, current_user.username))
                else:
                    cursor.execute('''
                        INSERT OR REPLACE INTO app_config (key, value, updated_at)
                        VALUES (?, ?, CURRENT_TIMESTAMP)
                    ''', (key, value))

        # Handle boolean configs
        for key in ["email_reminders_enabled", "registration_enabled", "data_export_enabled", "analytics_enabled", "maintenance_mode", "require_2fa", "force_2fa_setup", "password_complexity"]:
            value = "true" if request.form.get(key) == "on" else "false"
            if has_updated_by:
                cursor.execute('''
                    INSERT OR REPLACE INTO app_config (key, value, updated_at, updated_by)
                    VALUES (?, ?, CURRENT_TIMESTAMP, ?)
                ''', (key, value, current_user.username))
            else:
                cursor.execute('''
                    INSERT OR REPLACE INTO app_config (key, value, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                ''', (key, value))

        conn.commit()

    log_system_event('config_update', f'Configuration updated by admin: {current_user.username}', 'info')
    flash("Configuration updated successfully!", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/test_email", methods=["POST"])
@login_required
@admin_required
def test_email():
    test_email_address = request.form.get("test_email")

    if not test_email_address:
        flash("Please enter a test email address", "error")
        return redirect(url_for("admin_dashboard"))

    subject = "SendGrid Test Email - Supplement Tracker"
    body = f"""This is a test email from your Supplement Tracker application.

If you received this email, your SendGrid configuration is working correctly!

Test details:
- Sent from: Admin Dashboard
- Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- Configuration: SendGrid API

Best regards,
Supplement Tracker Admin Team"""

    if send_email(test_email_address, subject, body):
        flash(f"Test email sent successfully to {test_email_address}!", "success")
    else:
        flash("Failed to send test email. Please check your SendGrid configuration.", "error")

    return redirect(url_for("admin_dashboard"))

@app.route("/admin/system_monitoring")
@login_required
@admin_required
def system_monitoring():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Get system statistics
        system_stats = get_system_stats()

        # Get database size
        cursor.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
        db_size_row = cursor.fetchone()
        db_size = db_size_row[0] if db_size_row else 0

        # Get active sessions (simplified)
        cursor.execute("SELECT COUNT(*) FROM users WHERE last_login > datetime('now', '-1 hour')")
        active_sessions = cursor.fetchone()[0]

        # Get recent errors
        cursor.execute("SELECT message, created_at FROM system_logs WHERE severity = 'error' ORDER BY created_at DESC LIMIT 10")
        recent_errors = cursor.fetchall()

        # Get login attempts in last 24 hours
        cursor.execute("SELECT COUNT(*) FROM system_logs WHERE log_type = 'login_failed' AND created_at > datetime('now', '-1 day')")
        failed_logins_24h = cursor.fetchone()[0]

    return render_template_string(THEME_HEADER + SYSTEM_MONITORING_TEMPLATE,
                                system_stats=system_stats,
                                db_size=db_size,
                                active_sessions=active_sessions,
                                recent_errors=recent_errors,
                                failed_logins_24h=failed_logins_24h)

@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Get total count for pagination
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]

        # Get paginated users
        cursor.execute('''
            SELECT u.id, u.username, u.email, u.created_at, u.last_login,
                   COUNT(p.id) as protocol_count, u.disabled, u.login_attempts
            FROM users u
            LEFT JOIN protocols p ON u.id = p.user_id
            GROUP BY u.id, u.username, u.email, u.created_at, u.last_login, u.disabled, u.login_attempts
            ORDER BY u.username
            LIMIT ? OFFSET ?
        ''', (per_page, offset))
        users = cursor.fetchall()

    # Calculate pagination info
    total_pages = (total_users + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    prev_page = page - 1 if has_prev else None
    next_page = page + 1 if has_next else None

    return render_template_string(THEME_HEADER + ADMIN_USERS_TEMPLATE, 
                                users=users, 
                                current_page=page,
                                total_pages=total_pages,
                                total_users=total_users,
                                has_prev=has_prev,
                                has_next=has_next,
                                prev_page=prev_page,
                                next_page=next_page,
                                per_page=per_page)

@app.route("/admin/users/<int:user_id>/disable", methods=["POST"])
@login_required
@admin_required
def disable_user(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET disabled = TRUE WHERE id = ?", (user_id,))
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        username = cursor.fetchone()[0]
        conn.commit()

    log_system_event('user_disabled', f'User disabled by admin: {username}', 'info')
    flash(f"User '{username}' disabled successfully", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/enable", methods=["POST"])
@login_required
@admin_required
def enable_user(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET disabled = FALSE WHERE id = ?", (user_id,))
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        username = cursor.fetchone()[0]
        conn.commit()

    log_system_event('user_enabled', f'User enabled by admin: {username}', 'info')
    flash(f"User '{username}' enabled successfully", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        username_row = cursor.fetchone()
        if not username_row:
            flash("User not found", "error")
            return redirect(url_for("admin_users"))
        username = username_row[0]

        cursor.execute('''
            DELETE FROM protocol_logs 
            WHERE protocol_id IN (SELECT id FROM protocols WHERE user_id = ?)
        ''', (user_id,))
        cursor.execute("DELETE FROM protocols WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()

    log_system_event('user_deleted', f'User deleted by admin: {username}', 'warning')
    flash(f"User '{username}' and all associated data deleted successfully", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/reset_2fa", methods=["POST"])
@login_required
@admin_required
def reset_user_2fa(user_id):
    new_secret = pyotp.random_base32()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET twofa_secret = ? WHERE id = ?", (new_secret, user_id))
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        username = cursor.fetchone()[0]
        conn.commit()

    log_system_event('user_2fa_reset', f'2FA reset for user by admin: {username}', 'info')
    flash(f"2FA reset for user '{username}'. They will need to set up 2FA again.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def edit_user(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, email FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            flash("User not found", "error")
            return redirect(url_for("admin_users"))

        if request.method == "POST":
            new_email = request.form.get("email", "")
            new_password = request.form.get("new_password", "").strip()

            if new_password:
                # Validate password complexity if enabled
                if get_config_value('password_complexity', 'true') == 'true':
                    is_valid, error_msg = validate_password_complexity(new_password)
                    if not is_valid:
                        flash(error_msg, "error")
                        return render_template_string(THEME_HEADER + EDIT_USER_TEMPLATE, user=user, user_id=user_id)

                cursor.execute("UPDATE users SET email = ?, password_hash = ? WHERE id = ?", 
                             (new_email, generate_password_hash(new_password), user_id))
                flash(f"User '{user[0]}' updated with new password", "success")
            else:
                cursor.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
                flash(f"User '{user[0]}' email updated", "success")

            conn.commit()
            log_system_event('user_edited', f'User edited by admin: {user[0]}', 'info')
            return redirect(url_for("admin_users"))

    return render_template_string(THEME_HEADER + EDIT_USER_TEMPLATE, user=user, user_id=user_id)

@app.route("/admin/delete_admin/<username>", methods=["POST"])
@login_required
@super_admin_required
def delete_admin(username):
    if username == current_user.username:
        flash("Cannot delete your own admin account", "error")
        return redirect(url_for("admin_dashboard"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM admins WHERE username = ?", (username,))
        conn.commit()

    log_system_event('admin_deleted', f'Admin deleted by super admin: {username}', 'warning')
    flash(f"Admin '{username}' deleted successfully", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/")
@login_required
@require_2fa_setup
def dashboard():
    data = load_data()
    return render_template_string(THEME_HEADER + DASHBOARD_TEMPLATE, protocols=data["protocols"].keys(), user=current_user.id)

@app.route("/create", methods=["POST"])
@login_required
@require_2fa_setup
def create_protocol():
    name = request.form.get("protocol_name", "").strip()
    if not name:
        flash("Protocol name is required", "error")
        return redirect(url_for("dashboard"))
    if len(name) > 50:
        flash("Protocol name too long (max 50 characters)", "error")
        return redirect(url_for("dashboard"))

    max_protocols = int(get_config_value('max_protocols_per_user', '10'))
    data = load_data()
    if len(data["protocols"]) >= max_protocols:
        flash(f"Maximum of {max_protocols} protocols allowed per user", "error")
        return redirect(url_for("dashboard"))

    if name not in data["protocols"]:
        data["protocols"][name] = {
            "compounds": ["FOXO4-DRI", "Fisetin", "Quercetin"],
            "logs": {}
        }
        save_data(data)
        flash(f"Protocol '{name}' created successfully!", "success")
    else:
        flash(f"Protocol '{name}' already exists", "warning")
    return redirect(url_for("tracker", name=name))

@app.route("/delete_protocol/<name>", methods=["POST"])
@login_required
@require_2fa_setup
def delete_protocol(name):
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE username = ?", (current_user.id,))
        user_row = cursor.fetchone()
        if not user_row:
            flash("User not found", "error")
            return redirect(url_for("dashboard"))
        user_id = user_row[0]

        cursor.execute("SELECT id FROM protocols WHERE user_id = ? AND name = ?", (user_id, name))
        protocol_row = cursor.fetchone()
        if not protocol_row:
            flash(f"Protocol '{name}' not found", "error")
            return redirect(url_for("dashboard"))
        protocol_id = protocol_row[0]

        cursor.execute("DELETE FROM protocol_logs WHERE protocol_id = ?", (protocol_id,))
        cursor.execute("DELETE FROM protocols WHERE id = ?", (protocol_id,))

        conn.commit()
        flash(f"Protocol '{name}' deleted successfully", "success")

    return redirect(url_for("dashboard"))

@app.route("/protocol/<name>", methods=["GET", "POST"])
@login_required
@require_2fa_setup
def tracker(name):
    today = date.today().isoformat()
    data = load_data()
    prot = data["protocols"][name]
    if request.method == "POST":
        data["email"] = request.form.get("email", "")
        prot["logs"][today] = {}
        for c in prot["compounds"]:
            prot["logs"][today][c] = {
                "taken": request.form.get(f"check_{c}") == "on",
                "note": request.form.get(f"note_{c}", "")
            }
        save_data(data)
        flash("Daily log saved successfully!", "success")
        return redirect(url_for("tracker", name=name))
    return render_template_string(THEME_HEADER + TRACKER_TEMPLATE,
        name=name, compounds=prot["compounds"], log=prot["logs"].get(today, {}),
        today=today, email=data.get("email", ""))

@app.route("/protocol/<name>/edit_compounds", methods=["POST"])
@login_required
@require_2fa_setup
def edit_compounds(name):
    data = load_data()
    compounds = request.form.get("new_compounds", "")
    compound_list = [c.strip() for c in compounds.split(",") if c.strip()]
    if not compound_list:
        flash("At least one compound is required", "error")
    else:
        data["protocols"][name]["compounds"] = compound_list
        save_data(data)
        flash(f"Compounds updated successfully!", "success")
    return redirect(url_for("tracker", name=name))

@app.route("/protocol/<name>/calendar")
@login_required
@require_2fa_setup
def calendar(name):
    return render_template_string(THEME_HEADER + CAL_TEMPLATE, name=name)

@app.route("/protocol/<name>/logs.json")
@login_required
@require_2fa_setup
def logs_json(name):
    logs = []
    prot = load_data()["protocols"][name]
    for d, entries in prot["logs"].items():
        taken_count = sum(1 for e in entries.values() if e.get("taken"))
        total = len(entries)
        missed = total - taken_count
        color = "#28a745" if missed == 0 else "#dc3545"

        logs.append({
            "title": f"✅ {taken_count}/{total}" if missed == 0 else f"❌ {missed} missed",
            "start": d,
            "allDay": True,
            "backgroundColor": color,
            "borderColor": color,
            "extendedProps": {"entries": entries}
        })
    return jsonify(logs)

@app.route("/protocol/<name>/history")
@login_required
@require_2fa_setup
def history(name):
    logs = load_data()["protocols"][name]["logs"]
    return render_template_string(THEME_HEADER + HIST_TEMPLATE, name=name, logs=logs)

@app.route("/protocol/<name>/reminder")
@login_required
@require_2fa_setup
def reminder(name):
    if get_config_value('email_reminders_enabled', 'true') != 'true':
        flash("Email reminders are currently disabled", "error")
        return redirect(url_for("tracker", name=name))

    data = load_data()
    logs = data["protocols"][name]["logs"]
    last = sorted(logs.keys())[-1] if logs else None
    days_since = (date.today() - datetime.strptime(last, "%Y-%m-%d").date()).days if last else "N/A"
    msg = f"Reminder: Log today's dose for '{name}'\nLast log: {last} ({days_since} days ago)"

    email = data.get("email", "")
    if email:
        if send_email(email, f"Senolytic Reminder: {name}", msg):
            flash("Reminder email sent successfully!", "success")
        else:
            flash("Failed to send reminder email.", "error")
    else:
        flash("No email address configured for reminders.", "warning")

    return redirect(url_for("tracker", name=name))

@app.route("/protocol/<name>/analytics")
@login_required
@require_2fa_setup
def analytics(name):
    if get_config_value('analytics_enabled', 'true') != 'true':
        flash("Analytics is currently disabled", "error")
        return redirect(url_for("tracker", name=name))

    data = load_data()
    prot = data["protocols"][name]
    logs = prot["logs"]

    total_days = len(logs)
    if total_days == 0:
        return render_template_string(THEME_HEADER + ANALYTICS_TEMPLATE, 
                                    name=name, total_days=0, adherence=0, streak=0, 
                                    missed_days=0, compound_stats={})

    compound_stats = {}
    for compound in prot["compounds"]:
        taken_count = sum(1 for day_log in logs.values() 
                         if day_log.get(compound, {}).get("taken", False))
        compound_stats[compound] = {
            "taken": taken_count,
            "missed": total_days - taken_count,
            "percentage": round((taken_count / total_days) * 100, 1)
        }

    total_possible = total_days * len(prot["compounds"])
    total_taken = sum(sum(1 for entry in day_log.values() if entry.get("taken", False)) 
                     for day_log in logs.values())
    overall_adherence = round((total_taken / total_possible) * 100, 1) if total_possible > 0 else 0

    sorted_dates = sorted(logs.keys(), reverse=True)
    current_streak = 0
    for date_str in sorted_dates:
        day_log = logs[date_str]
        all_taken = all(entry.get("taken", False) for entry in day_log.values())
        if all_taken:
            current_streak += 1
        else:
            break

    missed_days = sum(1 for day_log in logs.values() 
                     if not all(entry.get("taken", False) for entry in day_log.values()))

    return render_template_string(THEME_HEADER + ANALYTICS_TEMPLATE,
                                name=name, total_days=total_days, adherence=overall_adherence,
                                streak=current_streak, missed_days=missed_days,
                                compound_stats=compound_stats)

@app.route("/protocol/<name>/export/csv")
@login_required
@require_2fa_setup
def export_csv(name):
    if get_config_value('data_export_enabled', 'true') != 'true':
        flash("Data export is currently disabled", "error")
        return redirect(url_for("tracker", name=name))

    data = load_data()
    prot = data["protocols"][name]

    output = io.StringIO()
    writer = csv.writer(output)

    headers = ["Date"] + prot["compounds"] + [f"{c}_Notes" for c in prot["compounds"]]
    writer.writerow(headers)

    for date_str, day_log in sorted(prot["logs"].items()):
        row = [date_str]
        for compound in prot["compounds"]:
            entry = day_log.get(compound, {})
            row.append("Yes" if entry.get("taken", False) else "No")
        for compound in prot["compounds"]:
            entry = day_log.get(compound, {})
            row.append(entry.get("note", ""))
        writer.writerow(row)

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={name}_data.csv"}
    )

@app.route("/protocol/<name>/enhanced_tracking", methods=["GET", "POST"])
@login_required
@require_2fa_setup
def enhanced_tracking(name):
    today = date.today().isoformat()
    data = load_data()
    prot = data["protocols"][name]

    if request.method == "POST":
        if today not in prot["logs"]:
            prot["logs"][today] = {}

        prot["logs"][today]["mood"] = request.form.get("mood", "")
        prot["logs"][today]["energy"] = request.form.get("energy", "")
        prot["logs"][today]["side_effects"] = request.form.get("side_effects", "")
        prot["logs"][today]["weight"] = request.form.get("weight", "")
        prot["logs"][today]["notes"] = request.form.get("general_notes", "")

        save_data(data)
        flash("Enhanced tracking data saved successfully!", "success")
        return redirect(url_for("enhanced_tracking", name=name))

    return render_template_string(THEME_HEADER + ENHANCED_TRACKING_TEMPLATE,
                                name=name, log=prot["logs"].get(today, {}), today=today)

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

def send_email(to_email, subject, body):
    api_key = get_config_value("sendgrid_api_key", "")
    from_email = get_config_value("sendgrid_from_email", "")

    if not api_key or not from_email:
        return False

    try:
        message = Mail(
            from_email=from_email,
            to_emails=to_email,
            subject=subject,
            plain_text_content=body
        )

        sg = SendGridAPIClient(api_key=api_key)
        response = sg.send(message)

        return response.status_code == 202

    except Exception as e:
        print(f"SendGrid error: {str(e)}")
        return False

# Templates
AUTH_TEMPLATE = """
<div class="container">
  <div class="card" style="max-width: 400px; margin: 80px auto;">
    <h2>🔐 {{title}}</h2>
    <form method="POST">
      <div class="form-group">
        <label>Username</label>
        <input name="username" required>
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" required>
      </div>
      <button type="submit" class="btn-primary">{{title}}</button>
    </form>
    <div class="nav-links" style="justify-content: center; margin-top: 24px;">
      <a href="/login">Login</a>
      <a href="/register">Register</a>
      <a href="/admin/login">Admin Login</a>
    </div>
  </div>
</div>
"""

ADMIN_AUTH_TEMPLATE = """
<div class="container">
  <div class="card" style="max-width: 400px; margin: 80px auto;">
    <h2>👑 {{title}}</h2>
    <form method="POST">
      <div class="form-group">
        <label>Username</label>
        <input name="username" required>
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" required>
      </div>
      {% if 'Register' in title %}
      <div class="form-group">
        <label>Role</label>
        <select name="role" required>
          <option value="Operator">Operator</option>
          <option value="Admin" selected>Admin</option>
          <option value="Super Admin">Super Admin</option>
        </select>
      </div>
      {% endif %}
      <button type="submit" class="btn-primary">{{title}}</button>
    </form>
    <div class="nav-links" style="justify-content: center; margin-top: 24px;">
      <a href="/admin/login">Admin Login</a>
      <a href="/admin/register">Admin Register</a>
      <a href="/login">User Login</a>
    </div>
  </div>
</div>
"""

ADMIN_DASHBOARD_TEMPLATE = """
<div class="container">
  <div class="card">
    <h1>👑 Admin Dashboard</h1>
    <p>Welcome, <strong>{{current_admin.username}}</strong> ({{current_admin.role}})!</p>
    <div class="nav-links">
      <a href="/admin/logout" title="Sign out of admin account">🚪 Logout</a>
      <a href="/admin/2fa_setup" title="Configure two-factor authentication for your admin account">🔒 2FA Setup</a>
      <a href="/admin/system_monitoring" title="View detailed system performance metrics and health monitoring">📊 System Monitoring</a>
    </div>
  </div>

  <div class="card">
    <h2>📊 System Overview</h2>
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
      <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;" title="Total number of registered users in the system">
        <h3 style="margin: 0; color: var(--primary);">{{user_count}}</h3>
        <p style="margin: 8px 0 0 0;">Total Users</p>
      </div>
      <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;" title="Total number of admin accounts with access to this dashboard">
        <h3 style="margin: 0; color: var(--success);">{{admin_count}}</h3>
        <p style="margin: 8px 0 0 0;">Total Admins</p>
      </div>
      <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;" title="Total number of supplement protocols created by all users">
        <h3 style="margin: 0; color: var(--info);">{{protocol_count}}</h3>
        <p style="margin: 8px 0 0 0;">Total Protocols</p>
      </div>
      <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;" title="Current server CPU usage percentage">
        <h3 style="margin: 0; color: var(--warning);">{{system_stats.get('cpu_percent', 0)}}%</h3>
        <p style="margin: 8px 0 0 0;">CPU Usage</p>
      </div>
    </div>
  </div>

  {% if current_admin.role in ['Super Admin', 'Admin'] %}
  <div class="card">
    <h2>⚙️ App Configuration</h2>
    <form method="POST" action="/admin/config">
      <div style="display: grid; gap: 16px;">
        <div class="form-group">
          <label title="The display name of your application">App Name</label>
          <input name="app_name" value="{{config.get('app_name', '')}}" required title="Enter the name that will appear in the app header and emails">
        </div>
        <div class="form-group">
          <label title="Maximum number of supplement protocols each user can create">Max Protocols Per User</label>
          <input name="max_protocols_per_user" type="number" value="{{config.get('max_protocols_per_user', '10')}}" required title="Set the limit to prevent users from creating too many protocols">
        </div>
        <div class="form-group">
          <label title="Minimum required password length for user accounts">Password Minimum Length</label>
          <input name="password_min_length" type="number" value="{{config.get('password_min_length', '6')}}" required title="Enforce minimum password length for security">
        </div>
        <div class="form-group">
          <label title="Number of failed login attempts before account lockout">Max Login Attempts</label>
          <input name="max_login_attempts" type="number" value="{{config.get('max_login_attempts', '5')}}" required title="Prevent brute force attacks by limiting login attempts">
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
          <label style="display: flex; align-items: center; gap: 8px;" title="Allow users to send themselves email reminders for their protocols">
            <input type="checkbox" name="email_reminders_enabled" {% if config.get('email_reminders_enabled') == 'true' %}checked{% endif %}>
            Email Reminders Enabled
          </label>
          <label style="display: flex; align-items: center; gap: 8px;" title="Allow new users to register accounts">
            <input type="checkbox" name="registration_enabled" {% if config.get('registration_enabled') == 'true' %}checked{% endif %}>
            Registration Enabled
          </label>
          <label style="display: flex; align-items: center; gap: 8px;" title="Allow users to export their data as CSV files">
            <input type="checkbox" name="data_export_enabled" {% if config.get('data_export_enabled') == 'true' %}checked{% endif %}>
            Data Export Enabled
          </label>
          <label style="display: flex; align-items: center; gap: 8px;" title="Enable analytics and statistics features for users">
            <input type="checkbox" name="analytics_enabled" {% if config.get('analytics_enabled') == 'true' %}checked{% endif %}>
            Analytics Enabled
          </label>
          <label style="display: flex; align-items: center; gap: 8px;" title="Put the application in maintenance mode (blocks user access)">
            <input type="checkbox" name="maintenance_mode" {% if config.get('maintenance_mode') == 'true' %}checked{% endif %}>
            Maintenance Mode
          </label>
          <label style="display: flex; align-items: center; gap: 8px;" title="Require all users to have 2FA enabled">
            <input type="checkbox" name="require_2fa" {% if config.get('require_2fa') == 'true' %}checked{% endif %}>
            Require 2FA
          </label>
          <label style="display: flex; align-items: center; gap: 8px;" title="Force users to set up 2FA before accessing the application">
            <input type="checkbox" name="force_2fa_setup" {% if config.get('force_2fa_setup') == 'true' %}checked{% endif %}>
            Force 2FA Setup
          </label>
          <label style="display: flex; align-items: center; gap: 8px;" title="Require passwords to have uppercase, numbers, and special characters">
            <input type="checkbox" name="password_complexity" {% if config.get('password_complexity') == 'true' %}checked{% endif %}>
            Password Complexity
          </label>
        </div>
      </div>
      <button type="submit" class="btn-success" title="Save all configuration changes">💾 Save Configuration</button>
    </form>
  </div>

  <div class="card">
    <h2>📧 SendGrid Email Configuration</h2>
    <form method="POST" action="/admin/config">
      <div style="display: grid; gap: 16px;">
        <div class="form-group">
          <label title="API key from your SendGrid account for sending emails">SendGrid API Key</label>
          <input name="sendgrid_api_key" type="password" value="{{config.get('sendgrid_api_key', '')}}" 
                 placeholder="Enter your SendGrid API key" title="Get this from your SendGrid dashboard under Settings > API Keys">
        </div>
        <div class="form-group">
          <label title="Email address that will appear as the sender">From Email Address</label>
          <input name="sendgrid_from_email" type="email" value="{{config.get('sendgrid_from_email', '')}}" 
                 placeholder="verified@yourdomain.com" title="This must be a verified sender in your SendGrid account">
        </div>
      </div>
      <button type="submit" class="btn-primary" title="Save email configuration settings">📧 Save SendGrid Configuration</button>
    </form>

    <div style="margin-top: 24px; padding: 16px; background: var(--bg); border-radius: 8px; border: 1px solid var(--border);">
      <h4 style="margin: 0 0 16px 0; color: var(--primary);">🧪 Test Email Configuration</h4>
      <form method="POST" action="/admin/test_email" style="display: flex; gap: 12px; align-items: end;">
        <div style="flex: 1;">
          <label style="display: block; margin-bottom: 8px; font-weight: 500;" title="Enter an email address to test the configuration">Test Email Address</label>
          <input name="test_email" type="email" placeholder="test@example.com" required 
                 style="width: 100%; margin: 0;" title="We'll send a test email to this address">
        </div>
        <button type="submit" class="btn-success" style="margin: 0;" title="Send a test email to verify your SendGrid configuration">🚀 Send Test Email</button>
      </form>
    </div>
  </div>
  {% endif %}

  <div class="card">
    <h2>👤 User Management</h2>
    <div class="nav-links" style="margin-bottom: 24px;">
      <a href="/admin/users" class="btn-primary" title="View and manage all user accounts, disable/enable users, reset 2FA, and modify user information">👥 Manage Users</a>
    </div>
    <p>Manage user accounts, disable/enable users, reset 2FA, and modify user information.</p>
  </div>

  {% if current_admin.role == 'Super Admin' %}
  <div class="card">
    <h2>👑 Admin Management</h2>
    <div class="nav-links" style="margin-bottom: 24px;">
      <a href="/admin/register" class="btn-primary" title="Create a new admin account with specified role and permissions">➕ Add New Admin</a>
    </div>

    {% if admins %}
      <table>
        <thead>
          <tr>
            <th title="Admin account username">Username</th>
            <th title="Admin permission level: Super Admin (full access), Admin (most features), Operator (limited access)">Role</th>
            <th title="Email address for the admin account">Email</th>
            <th title="Whether the admin account is active or disabled">Status</th>
            <th title="Last time this admin logged into the system">Last Login</th>
            <th title="Available actions for this admin account">Actions</th>
          </tr>
        </thead>
        <tbody>
          {% for admin in admins %}
          <tr>
            <td><strong>{{admin[0]}}</strong></td>
            <td>
              <span class="status-badge {{ 'status-success' if admin[1] == 'Super Admin' else 'status-info' if admin[1] == 'Admin' else 'status-warning' }}" title="{{admin[1]}} - {{ 'Full system access' if admin[1] == 'Super Admin' else 'Most admin features' if admin[1] == 'Admin' else 'Limited admin access' }}">
                {{admin[1]}}
              </span>
            </td>
            <td>{{admin[2] or 'Not set'}}</td>
            <td>
              <span class="status-badge {{ 'status-danger' if admin[4] else 'status-success' }}" title="{{ 'This admin account is disabled and cannot log in' if admin[4] else 'This admin account is active and can log in' }}">
                {{ 'Disabled' if admin[4] else 'Active' }}
              </span>
            </td>
            <td>{{admin[3] or 'Never'}}</td>
            <td>
              {% if admin[0] != current_admin.username %}
              <div style="display: flex; gap: 4px; flex-wrap: wrap;">
                <form method="POST" action="/admin/delete_admin/{{admin[0]}}" style="display: inline;"
                      onsubmit="return confirm('Delete admin {{admin[0]}}? This cannot be undone.')">
                  <button type="submit" class="btn-danger btn-small" title="Permanently delete this admin account">🗑️ Delete</button>
                </form>
              </div>
              {% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    {% endif %}
  </div>
  {% endif %}

  <div class="card">
    <h2>🔍 Recent System Logs</h2>
    {% if recent_logs %}
      <table>
        <thead>
          <tr>
            <th title="Category of system event or activity">Type</th>
            <th title="Detailed description of what happened">Message</th>
            <th title="Importance level: info (normal), warning (potential issue), error (requires attention)">Severity</th>
            <th title="When this event occurred">Time</th>
          </tr>
        </thead>
        <tbody>
          {% for log in recent_logs %}
          <tr>
            <td title="{{log[0]}}">{{log[0]}}</td>
            <td title="{{log[1]}}">{{log[1]}}</td>
            <td>
              <span class="status-badge {{ 'status-danger' if log[2] == 'error' else 'status-warning' if log[2] == 'warning' else 'status-success' }}" title="{{ 'Critical error that needs immediate attention' if log[2] == 'error' else 'Warning that should be monitored' if log[2] == 'warning' else 'Normal system activity' }}">
                {{log[2]}}
              </span>
            </td>
            <td>{{log[3]}}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <p style="text-align: center; color: #6b7280; margin: 40px 0;">No recent system logs.</p>
    {% endif %}
  </div>
</div>
"""

SYSTEM_MONITORING_TEMPLATE = """
<div class="container">
  <div class="card">
    <h1>📊 System Monitoring</h1>
    <div class="nav-links">
      <a href="/admin/dashboard">← Back to Dashboard</a>
    </div>
  </div>

  <div class="card">
    <h2>🖥️ System Health</h2>
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px;">
      <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;">
        <h3 style="margin: 0; color: var(--primary);">{{system_stats.get('uptime', 0) | round(2)}}s</h3>
        <p style="margin: 8px 0 0 0;">System Uptime</p>
      </div>
      <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;">
        <h3 style="margin: 0; color: var(--warning);">{{system_stats.get('cpu_percent', 0)}}%</h3>
        <p style="margin: 8px 0 0 0;">CPU Usage</p>
      </div>
      <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;">
        <h3 style="margin: 0; color: var(--info);">{{system_stats.get('memory_percent', 0)}}%</h3>
        <p style="margin: 8px 0 0 0;">Memory Usage</p>
      </div>
      <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;">
        <h3 style="margin: 0; color: var(--success);">{{(db_size / 1024 / 1024) | round(2)}} MB</h3>
        <p style="margin: 8px 0 0 0;">Database Size</p>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>👥 Active Sessions</h2>
    <p>Active users in the last hour: <strong>{{active_sessions}}</strong></p>
  </div>

  <div class="card">
    <h2>🔐 Security Alerts</h2>
    <p>Failed login attempts in last 24 hours: <strong>{{failed_logins_24h}}</strong></p>
  </div>

  {% if recent_errors %}
  <div class="card">
    <h2>❌ Recent Errors</h2>
    <table>
      <thead>
        <tr>
          <th>Error Message</th>
          <th>Time</th>
        </tr>
      </thead>
      <tbody>
        {% for error in recent_errors %}
        <tr>
          <td>{{error[0]}}</td>
          <td>{{error[1]}}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}
</div>
"""

TWOFA_TEMPLATE = """
<div class="container">
  <div class="card" style="max-width: 400px; margin: 80px auto;">
    <h2>🔐 Two-Factor Authentication</h2>
    <p>Enter the 6-digit code from your authenticator app:</p>
    <form method="POST">
      <div class="form-group">
        <input name="code" required placeholder="000000" maxlength="6" 
               style="text-align: center; font-size: 24px; letter-spacing: 8px;">
      </div>
      <button type="submit" class="btn-primary">Verify Code</button>
    </form>
  </div>
</div>
"""

TWOFA_SETUP_TEMPLATE = """
<div class="container">
  <div class="card" style="max-width: 600px; margin: 40px auto; text-align: center;">
    <h2>🔐 Set Up Two-Factor Authentication</h2>
    {% if is_forced %}
    <div style="background: var(--warning); color: white; padding: 12px 20px; border-radius: 8px; margin-bottom: 24px;">
      <strong>⚠️ 2FA Setup Required</strong><br>
      You must complete 2FA setup to continue using the application.
    </div>
    {% endif %}
    <p style="margin-bottom: 24px;">Scan this QR code with Google Authenticator, Authy, or any compatible 2FA app:</p>

    <div style="background: white; padding: 20px; border-radius: 12px; margin: 20px auto; display: inline-block; box-shadow: var(--shadow);">
      <img src="data:image/png;base64,{{qr_code}}" style="max-width: 256px; height: auto;" alt="2FA QR Code">
    </div>

    <div style="background: var(--bg); padding: 20px; border-radius: 12px; margin: 20px 0; border: 2px solid var(--border);">
      <h3 style="margin: 0 0 12px 0; color: var(--primary);">Manual Entry Code</h3>
      <div style="background: var(--card-bg); padding: 16px; border-radius: 8px; margin: 12px 0;">
        <code style="font-size: 18px; font-weight: bold; color: var(--primary); letter-spacing: 2px;">{{secret}}</code>
      </div>
    </div>

    <div style="margin: 32px 0; background: var(--card-bg); padding: 24px; border-radius: 12px; border: 1px solid var(--border);">
      <h3 style="margin: 0 0 16px 0; color: var(--primary);">Verify Setup</h3>
      <p style="margin-bottom: 16px;">Enter the 6-digit code from your authenticator app to complete setup:</p>
      <form method="POST" action="/2fa_setup_complete">
        <div style="display: flex; flex-direction: column; align-items: center; gap: 16px;">
          <input name="code" required placeholder="000000" maxlength="6" 
                 style="text-align: center; font-size: 24px; letter-spacing: 8px; max-width: 200px;">
          <button type="submit" class="btn-success" style="padding: 12px 24px;">✅ Complete 2FA Setup</button>
        </div>
      </form>
    </div>
  </div>
</div>
"""

ADMIN_TWOFA_SETUP_TEMPLATE = """
<div class="container">
  <div class="card" style="max-width: 600px; margin: 40px auto; text-align: center;">
    <h2>👑 Set Up Admin Two-Factor Authentication</h2>
    {% if is_forced %}
    <div style="background: var(--warning); color: white; padding: 12px 20px; border-radius: 8px; margin-bottom: 24px;">
      <strong>⚠️ Admin 2FA Setup Required</strong><br>
      You must complete 2FA setup to continue using the admin panel.
    </div>
    {% endif %}
    <p style="margin-bottom: 24px;">Scan this QR code with Google Authenticator, Authy, or any compatible 2FA app:</p>

    <div style="background: white; padding: 20px; border-radius: 12px; margin: 20px auto; display: inline-block; box-shadow: var(--shadow);">
      <img src="data:image/png;base64,{{qr_code}}" style="max-width: 256px; height: auto;" alt="Admin 2FA QR Code">
    </div>

    <div style="background: var(--bg); padding: 20px; border-radius: 12px; margin: 20px 0; border: 2px solid var(--border);">
      <h3 style="margin: 0 0 12px 0; color: var(--primary);">Manual Entry Code</h3>
      <div style="background: var(--card-bg); padding: 16px; border-radius: 8px; margin: 12px 0;">
        <code style="font-size: 18px; font-weight: bold; color: var(--primary); letter-spacing: 2px;">{{secret}}</code>
      </div>
    </div>

    <div style="margin: 32px 0; background: var(--card-bg); padding: 24px; border-radius: 12px; border: 1px solid var(--border);">
      <h3 style="margin: 0 0 16px 0; color: var(--primary);">Verify Setup</h3>
      <p style="margin-bottom: 16px;">Enter the 6-digit code from your authenticator app to complete setup:</p>
      <form method="POST" action="/admin/2fa_setup_complete">
        <div style="display: flex; flex-direction: column; align-items: center; gap: 16px;">
          <input name="code" required placeholder="000000" maxlength="6" 
                 style="text-align: center; font-size: 24px; letter-spacing: 8px; max-width: 200px;">
          <button type="submit" class="btn-success" style="padding: 12px 24px;">✅ Complete Admin 2FA Setup</button>
        </div>
      </form>
    </div>
  </div>
</div>
"""

THEME_HEADER = """
<style>
:root { 
  --bg: #f8fafc; 
  --text: #334155; 
  --border: #e2e8f0; 
  --input-bg: #ffffff; 
  --card-bg: #ffffff;
  --primary: #3b82f6;
  --primary-hover: #2563eb;
  --success: #10b981;
  --danger: #ef4444;
  --warning: #f59e0b;
  --info: #06b6d4;
  --shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);
  --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
}
body.dark { 
  --bg: #0f172a; 
  --text: #cbd5e1; 
  --border: #334155; 
  --input-bg: #1e293b; 
  --card-bg: #1e293b;
  --primary: #60a5fa;
  --primary-hover: #3b82f6;
  --success: #34d399;
  --danger: #f87171;
  --warning: #fbbf24;
  --info: #22d3ee;
}
* { box-sizing: border-box; }
body { 
  background: var(--bg); 
  color: var(--text); 
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
  transition: all 0.3s ease;
  margin: 0;
  padding: 20px;
  line-height: 1.6;
}
.container { max-width: 1200px; margin: 0 auto; }
.card { 
  background: var(--card-bg); 
  border-radius: 12px; 
  padding: 24px; 
  margin: 16px 0; 
  box-shadow: var(--shadow);
  border: 1px solid var(--border);
}
h1, h2, h3 { margin-top: 0; font-weight: 600; }
h1 { font-size: 2.5rem; color: var(--primary); }
h2 { font-size: 2rem; margin-bottom: 1rem; }
h3 { font-size: 1.5rem; margin-bottom: 0.75rem; }
a { 
  color: var(--primary); 
  text-decoration: none; 
  font-weight: 500;
  transition: color 0.2s;
}
a:hover { color: var(--primary-hover); }
input, button, textarea, select { 
  background: var(--input-bg); 
  color: var(--text); 
  border: 1px solid var(--border); 
  padding: 12px 16px; 
  margin: 4px; 
  border-radius: 8px;
  font-size: 14px;
  transition: all 0.2s;
}
input:focus, textarea:focus, select:focus { 
  outline: none; 
  border-color: var(--primary); 
  box-shadow: 0 0 0 3px rgb(59 130 246 / 0.1);
}
button { 
  cursor: pointer; 
  font-weight: 500;
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
button:hover { 
  transform: translateY(-1px); 
  box-shadow: var(--shadow-lg);
}
.btn-primary { 
  background: var(--primary); 
  color: white; 
  border-color: var(--primary);
}
.btn-primary:hover { background: var(--primary-hover); }
.btn-success { 
  background: var(--success); 
  color: white; 
  border-color: var(--success);
}
.btn-danger { 
  background: var(--danger); 
  color: white; 
  border-color: var(--danger);
}
.btn-small { 
  padding: 6px 12px; 
  font-size: 12px; 
  border-radius: 6px;
}
.btn-warning { 
  background: var(--warning); 
  color: white; 
  border-color: var(--warning);
}
.btn-info { 
  background: var(--info); 
  color: white; 
  border-color: var(--info);
}
.status-info { 
  background: var(--info); 
  color: white;
}
.status-warning { 
  background: var(--warning); 
  color: white;
}
table { 
  width: 100%; 
  border-collapse: collapse; 
  margin: 16px 0;
  background: var(--card-bg);
  border-radius: 8px;
  overflow: hidden;
  box-shadow: var(--shadow);
}
th, td { 
  padding: 12px 16px; 
  text-align: left; 
  border-bottom: 1px solid var(--border);
}
th { 
  background: var(--primary); 
  color: white; 
  font-weight: 600;
  font-size: 14px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
tr:hover { background: var(--bg); }
.theme-toggle { 
  position: fixed; 
  top: 20px; 
  right: 20px; 
  font-size: 14px; 
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 50px;
  padding: 8px 16px;
  box-shadow: var(--shadow);
  z-index: 1000;
}
.nav-links { 
  display: flex; 
  gap: 16px; 
  margin: 16px 0;
  flex-wrap: wrap;
}
.nav-links a { 
  padding: 8px 16px; 
  border-radius: 6px; 
  background: var(--bg); 
  border: 1px solid var(--border);
  transition: all 0.2s;
}
.nav-links a:hover { 
  background: var(--primary); 
  color: white; 
  transform: translateY(-1px);
}
.protocol-list { 
  display: grid; 
  gap: 16px; 
  margin: 24px 0;
}
.protocol-item { 
  background: var(--card-bg); 
  border: 1px solid var(--border); 
  border-radius: 8px; 
  padding: 16px; 
  display: flex; 
  justify-content: space-between; 
  align-items: center;
  transition: all 0.2s;
}
.protocol-item:hover { 
  transform: translateY(-2px); 
  box-shadow: var(--shadow-lg);
}
.form-group { 
  margin: 24px 0; 
}

.form-group label { 
  display: block; 
  margin-bottom: 12px; 
  font-weight: 600;
  color: var(--text);
  font-size: 14px;
  letter-spacing: 0.025em;
}

.status-badge { 
  padding: 8px 16px; 
  border-radius: 50px; 
  font-size: 13px; 
  font-weight: 600;
  letter-spacing: 0.025em;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  box-shadow: var(--shadow);
  border: 2px solid transparent;
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
}

.status-success { 
  background: linear-gradient(135deg, var(--success), #38a169);
  color: white;
  border-color: var(--success);
}

.status-success:hover {
  transform: translateY(-1px);
  box-shadow: var(--shadow-md);
}

.status-danger { 
  background: linear-gradient(135deg, var(--danger), #e53e3e);
  color: white;
  border-color: var(--danger);
}

.status-danger:hover {
  transform: translateY(-1px);
  box-shadow: var(--shadow-md);
}

.status-info { 
  background: linear-gradient(135deg, var(--info), #3182ce);
  color: white;
  border-color: var(--info);
}

.status-info:hover {
  transform: translateY(-1px);
  box-shadow: var(--shadow-md);
}

.status-warning { 
  background: linear-gradient(135deg, var(--warning), #dd6b20);
  color: white;
  border-color: var(--warning);
}

.status-warning:hover {
  transform: translateY(-1px);
  box-shadow: var(--shadow-md);
}
.checkbox-cell { 
  text-align: center; 
}
.checkbox-cell input[type="checkbox"] { 
  transform: scale(1.2); 
  margin: 0;
}
.flash-messages {
  position: fixed;
  top: 80px;
  right: 20px;
  z-index: 1000;
  max-width: 400px;
}
.flash-message {
  padding: 16px 20px;
  margin-bottom: 12px;
  border-radius: 8px;
  box-shadow: var(--shadow-lg);
  animation: slideIn 0.3s ease-out;
  position: relative;
  display: flex;
  align-items: center;
  gap: 12px;
}
.flash-success {
  background: var(--success);
  color: white;
}
.flash-error {
  background: var(--danger);
  color: white;
}
.flash-warning {
  background: var(--warning);
  color: white;
}
.flash-info {
  background: var(--info);
  color: white;
}
.flash-close {
  background: none;
  border: none;
  color: inherit;
  font-size: 18px;
  cursor: pointer;
  padding: 0;
  margin-left: auto;
}
@keyframes slideIn {
  from { transform: translateX(100%); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
}
</style>
<div class="flash-messages" id="flashMessages">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="flash-message flash-{{ category }}">
          <span>{{ message }}</span>
          <button class="flash-close" onclick="this.parentElement.remove()">×</button>
        </div>
      {% endfor %}
    {% endif %}
  {% endwith %}
</div>
<script>
document.addEventListener('DOMContentLoaded', () => {
  const btn = document.createElement('button');
  btn.innerHTML = "🌙 <span>DarkMode</span>";
  btn.className = "theme-toggle";
  btn.onclick = () => {
    document.body.classList.toggle('dark');
    const isDark = document.body.classList.contains('dark');
    localStorage.setItem('darkmode', isDark);
    btn.innerHTML = isDark ? "☀️ <span>Light Mode</span>" : "🌙 <span>Dark Mode</span>";
  };
  document.body.appendChild(btn);
  if (localStorage.getItem('darkmode') === 'true') {
    document.body.classList.add('dark');
    btn.innerHTML = "☀️ <span>Light Mode</span>";
  }
});
</script>
"""

DASHBOARD_TEMPLATE = """
<div class="container">
  <div class="card">
    <h1>💊 Supplement Tracker</h1>
    <p>Welcome back, <strong>{{user}}</strong>!</p>
    <div class="nav-links">
      <a href="/logout">🚪 Logout</a>
      <a href="/2fa_setup">🔒 2FA Setup</a>
    </div>
  </div>

  <div class="card">
    <h2>📋 Create New Protocol</h2>
    <form method="POST" action="/create">
      <div class="form-group">
        <input name="protocol_name" placeholder="Enter protocol name..." required 
               style="width: 300px;">
        <button type="submit" class="btn-primary">✨ Create Protocol</button>
      </div>
    </form>
  </div>

  <div class="card">
    <h2>🧪 Your Protocols</h2>
    {% if protocols %}
      <div class="protocol-list">
        {% for p in protocols %}
          <div class="protocol-item">
            <div>
              <h3 style="margin: 0 0 8px 0;">{{p}}</h3>
              <div class="nav-links" style="margin: 0;">
                <a href="/protocol/{{p}}">📝 Track</a>
                <a href="/protocol/{{p}}/history">📊 History</a>
                <a href="/protocol/{{p}}/calendar">📅 Calendar</a>
                <a href="/protocol/{{p}}/analytics">📈 Analytics</a>
                <a href="/protocol/{{p}}/export/csv">Export CSV</a>
                <a href="/protocol/{{p}}/enhanced_tracking">Enhanced Tracking</a>
              </div>
            </div>
            <form method="POST" action="/delete_protocol/{{p}}" 
                  onsubmit="return confirm('Delete protocol {{p}}?')">
              <button type="submit" class="btn-danger btn-small">🗑️ Delete</button>
            </form>
          </div>
        {% endfor %}
      </div>
    {% else %}
      <p style="text-align: center; color: #6b7280; margin: 40px 0;">
        No protocols yet. Create your first one above! 🚀
      </p>
    {% endif %}
  </div>
</div>
"""

TRACKER_TEMPLATE = """
<div class="container">
  <div class="card">
    <h1>📋 Protocol: {{name}}</h1>
    <div class="nav-links">
      <a href="/">← Dashboard</a>
      <a href="/protocol/{{name}}/history">📊 History</a>
      <a href="/protocol/{{name}}/calendar">📅 Calendar</a>
      <a href="/protocol/{{name}}/reminder">📧 Send Reminder</a>
      <a href="/protocol/{{name}}/analytics">📈 Analytics</a>
      <a href="/protocol/{{name}}/export/csv">Export CSV</a>
      <a href="/protocol/{{name}}/enhanced_tracking">Enhanced Tracking</a>
    </div>
  </div>

  <div class="card">
    <h2>📅 Today's Tracking - {{today}}</h2>
    <form method="POST">
      <div class="form-group">
        <label>📧 Email for reminders</label>
        <input name="email" value="{{email}}" type="email" 
               placeholder="your@email.com" style="width: 300px;">
      </div>

      <table>
        <tr>
          <th>💊 Compound</th>
          <th>✅ Taken?</th>
          <th>📝 Notes</th>
        </tr>
        {% for c in compounds %}
          <tr>
            <td><strong>{{c}}</strong></td>
            <td class="checkbox-cell">
              <input type="checkbox" name="check_{{c}}" 
                     {% if log.get(c, {}).get('taken') %}checked{% endif %}>
            </td>
            <td>
              <input name="note_{{c}}" value="{{log.get(c, {}).get('note','')}}" 
                     placeholder="Add notes...">
            </td>
          </tr>
        {% endfor %}
      </table>

      <button type="submit" class="btn-success">💾 Save Today's Log</button>
    </form>
  </div>

  <div class="card">
    <h2>🧪 Edit Compounds</h2>
    <form method="POST" action="/protocol/{{name}}/edit_compounds">
      <div class="form-group">
        <label>Compounds (comma-separated)</label>
        <textarea name="new_compounds" rows="3" style="width: 100%;" 
                  placeholder="FOXO4-DRI, Fisetin, Quercetin...">{{ compounds | join(', ') }}</textarea>
      </div>
      <button type="submit" class="btn-primary">🔄 Update Compounds</button>
    </form>
  </div>
</div>
"""

HIST_TEMPLATE = """
<div class="container">
  <div class="card">
    <h1>📊 History for {{name}}</h1>
    <div class="nav-links">
      <a href="/protocol/{{name}}">← Back to Tracking</a>
      <a href="/protocol/{{name}}/calendar">📅 Calendar View</a>
      <a href="/protocol/{{name}}/analytics">📈 Analytics</a>
      <a href="/protocol/{{name}}/export/csv">Export CSV</a>
      <a href="/protocol/{{name}}/enhanced_tracking">Enhanced Tracking</a>
    </div>
  </div>

  {% for d, entries in logs.items() %}
    <div class="card">
      <h3>📅 {{d}}</h3>
      <div style="display: grid; gap: 8px;">
        {% for compound, e in entries.items() %}
          <div style="display: flex; align-items: center; gap: 12px; padding: 8px; background: var(--bg); border-radius: 6px;">
            <span class="status-badge {{ 'status-success' if e.taken else 'status-danger' }}">
              {{ '✅ Taken' if e.taken else '❌ Missed' }}
            </span>
            <strong>{{compound}}</strong>
            {% if e.note %}
              <span style="color: var(--text); opacity: 0.7;">— {{e.note}}</span>
            {% endif %}
          </div>
        {% endfor %}
      </div>
    </div>
  {% endfor %}

  {% if not logs %}
    <div class="card">
      <p style="text-align: center; color: #6b7280; margin: 40px 0;">
        No history yet. Start tracking to see your progress! 🚀
      </p>
    </div>
  {% endif %}
</div>
"""

CAL_TEMPLATE = """
<div class="container">
  <div class="card">
    <h1>📅 Calendar for {{name}}</h1>
    <div class="nav-links">
      <a href="/protocol/{{name}}">← Back to Tracking</a>
      <a href="/protocol/{{name}}/history">📊 History</a>
      <a href="/protocol/{{name}}/analytics">📈 Analytics</a>
    </div>
  </div>

  <div class="card">
    <div id="calendar" style="min-height: 600px;">
      <div style="text-align: center; padding: 40px; color: var(--text); opacity: 0.7;">
        <h3>📅 Loading Calendar...</h3>
        <p>Please wait while the calendar loads.</p>
      </div>
    </div>
  </div>

  <div class="card" id="logDetails" style="display: none;">
    <h3>📋 Day Details</h3>
    <div id="logContent"></div>
  </div>
</div>

<link href="https://cdn.jsdelivr.net/npm/fullcalendar@5.11.5/main.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/fullcalendar@5.11.5/main.min.js"></script>
<script>
document.addEventListener('DOMContentLoaded', function() {
  console.log('Initializing calendar for protocol: {{name}}');

  // Check if FullCalendar loaded
  if (typeof FullCalendar === 'undefined') {
    console.error('FullCalendar library failed to load');
    document.getElementById('calendar').innerHTML = 
      '<div style="text-align: center; padding: 40px; color: var(--danger);">' +
      '<h3>❌ Calendar Library Error</h3>' +
      '<p>Unable to load calendar library. Please refresh the page or check your internet connection.</p>' +
      '<button onclick="location.reload()" class="btn-primary" style="margin-top: 16px;">🔄 Refresh Page</button>' +
      '</div>';
    return;
  }

  try {
    const calendarEl = document.getElementById('calendar');

    // Clear loading message
    calendarEl.innerHTML = '';

    const calendar = new FullCalendar.Calendar(calendarEl, {
      initialView: 'dayGridMonth',
      headerToolbar: {
        left: 'prev,next today',
        center: 'title',
        right: 'dayGridMonth,dayGridWeek'
      },
      events: function(fetchInfo, successCallback, failureCallback) {
        fetch('/protocol/{{name}}/logs.json')
          .then(response => {
            if (!response.ok) {
              throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
          })
          .then(data => {
            console.log('Calendar events loaded:', data.length, 'events');
            successCallback(data);
          })
          .catch(error => {
            console.error('Error loading calendar events:', error);
            failureCallback(error);
            document.getElementById('calendar').innerHTML = 
              '<div style="text-align: center; padding: 40px; color: var(--warning);">' +
              '<h3>⚠️ Data Loading Error</h3>' +
              '<p>Unable to load calendar data. Please try refreshing the page.</p>' +
              '<button onclick="location.reload()" class="btn-primary" style="margin-top: 16px;">🔄 Refresh Page</button>' +
              '</div>';
          });
      },
      eventClick: function(info) {
        console.log('Event clicked:', info.event.title);
        const entries = info.event.extendedProps.entries;
        if (!entries) {
          console.warn('No entries found for event');
          return;
        }

        let html = '<div style="display: grid; gap: 8px;">';
        for (const [compound, data] of Object.entries(entries)) {
          const status = data.taken ? '✅ Taken' : '❌ Missed';
          const note = data.note ? ` - ${data.note}` : '';
          html += `<div style="padding: 8px; background: var(--bg); border-radius: 6px;">
                     <strong>${compound}:</strong> ${status}${note}
                   </div>`;
        }
        html += '</div>';
        document.getElementById('logContent').innerHTML = html;
        document.getElementById('logDetails').style.display = 'block';

        // Scroll to details
        document.getElementById('logDetails').scrollIntoView({ behavior: 'smooth' });
      },
      eventDidMount: function(info) {
        // Add tooltip on hover
        info.el.title = info.event.title + ' - Click for details';
      },
      height: 'auto',
      loading: function(isLoading) {
        if (isLoading) {
          console.log('Calendar is loading...');
        } else {
          console.log('Calendar finished loading');
        }
      }
    });

    calendar.render();
    console.log('Calendar rendered successfully');

  } catch (error) {
    console.error('Calendar initialization error:', error);
    document.getElementById('calendar').innerHTML = 
      '<div style="text-align: center; padding: 40px; color: var(--danger);">' +
      '<h3>❌ Calendar Error</h3>' +
      '<p>Unable to initialize calendar: ' + error.message + '</p>' +
      '<button onclick="location.reload()" class="btn-primary" style="margin-top: 16px;">🔄 Refresh Page</button>' +
      '</div>';
  }
});
</script>
"""

ANALYTICS_TEMPLATE = """
<div class="container">
    <div class="card">
        <h1>📈 Analytics for {{name}}</h1>
        <div class="nav-links">
            <a href="/protocol/{{name}}">← Back to Tracking</a>
        </div>
    </div>

    <div class="card">
        <h2>📊 Summary</h2>
        <p><strong>Total Days Tracked:</strong> {{total_days}}</p>
        <p><strong>Overall Adherence:</strong> {{adherence}}%</p>
        <p><strong>Current Streak:</strong> {{streak}} days</p>
        <p><strong>Missed Days:</strong> {{missed_days}}</p>
    </div>

    <div class="card">
        <h2>💊 Compound Statistics</h2>
        <table>
            <thead>
                <tr>
                    <th>Compound</th>
                    <th>Taken</th>
                    <th>Missed</th>
                    <th>Adherence (%)</th>
                </tr>
            </thead>
            <tbody>
                {% for compound, stats in compound_stats.items() %}
                <tr>
                    <td>{{compound}}</td>
                    <td>{{stats.taken}}</td>
                    <td>{{stats.missed}}</td>
                    <td>{{stats.percentage}}%</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>
"""

ENHANCED_TRACKING_TEMPLATE = """
<div class="container">
    <div class="card">
        <h1>Enhanced Tracking for {{name}} - {{today}}</h1>
        <div class="nav-links">
            <a href="/protocol/{{name}}">← Back to Tracking</a>
            <a href="/protocol/{{name}}/analytics">📈 Analytics</a>
            <a href="/protocol/{{name}}/export/csv">Export CSV</a>
        </div>
    </div>

    <div class="card">
        <form method="POST">
            <div class="form-group">
                <label>Mood</label>
                <input type="text" name="mood" value="{{ log.get('mood', '') }}" placeholder="Enter your mood">
            </div>
            <div class="form-group">
                <label>Energy Level</label>
                <input type="text" name="energy" value="{{ log.get('energy', '') }}" placeholder="Enter your energy level">
            </div>
            <div class="form-group">
                <label>Side Effects</label>
                <input type="text" name="side_effects" value="{{ log.get('side_effects', '') }}" placeholder="Any side effects?">
            </div>
             <div class="form-group">
                <label>Weight</label>
                <input type="text" name="weight" value="{{ log.get('weight', '') }}" placeholder="Enter your weight">
            </div>
            <div class="form-group">
                <label>General Notes</label>
                <textarea name="general_notes" rows="4" placeholder="General notes about today">{{ log.get('notes', '') }}</textarea>
            </div>
            <button type="submit" class="btn-success">Save Enhanced Log</button>
        </form>
    </div>
</div>
"""

ADMIN_USERS_TEMPLATE = """
<div class="container">
  <div class="card">
    <h1>👤 User Management</h1>
    <div class="nav-links">
      <a href="/admin/dashboard">← Back to Dashboard</a>
    </div>
  </div>

  <div class="card">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
      <h2>👥 All Users</h2>
      <div style="color: var(--text); opacity: 0.7;">
        Total: {{total_users}} users | Showing {{(current_page-1)*per_page + 1}}-{{((current_page-1)*per_page + users|length)}} of {{total_users}}
      </div>
    </div>

    {% if users %}
      <table>
        <thead>
          <tr>
            <th>Username</th>
            <th>Email</th>
            <th>Protocols</th>
            <th>Status</th>
            <th>Created</th>
            <th>Last Login</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {% for user in users %}
          <tr>
            <td><strong>{{user[1]}}</strong></td>
            <td>{{user[2] or 'Not set'}}</td>
            <td>
              <span class="status-badge status-info">
                {{user[5]}} protocols
              </span>
            </td>
            <td>
              <span class="status-badge {{ 'status-danger' if user[6] else 'status-success' }}">
                {{ 'Disabled' if user[6] else 'Active' }}
              </span>
            </td>
            <td>{{user[3][:10] if user[3] else 'Unknown'}}</td>
            <td>{{user[4][:10] if user[4] else 'Never'}}</td>
            <td>
              <div style="display: flex; gap: 4px; flex-wrap: wrap;">
                <a href="/admin/users/{{user[0]}}/edit" class="btn-primary btn-small">✏️ Edit</a>
                <form method="POST" action="/admin/users/{{user[0]}}/reset_2fa" style="display: inline;">
                  <button type="submit" class="btn-warning btn-small" onclick="return confirm('Reset 2FA for {{user[1]}}?')">🔄 Reset 2FA</button>
                </form>
                {% if user[6] %}
                <form method="POST" action="/admin/users/{{user[0]}}/enable" style="display: inline;">
                  <button type="submit" class="btn-success btn-small">✅ Enable</button>
                </form>
                {% else %}
                <form method="POST" action="/admin/users/{{user[0]}}/disable" style="display: inline;">
                  <button type="submit" class="btn-warning btn-small" onclick="return confirm('Disable user {{user[1]}}?')">⏸️ Disable</button>
                </form>
                {% endif %}
                <form method="POST" action="/admin/users/{{user[0]}}/delete" style="display: inline;"
                      onsubmit="return confirm('Delete user {{user[1]}} and all their data? This cannot be undone.')">
                  <button type="submit" class="btn-danger btn-small">🗑️ Delete</button>
                </form>
              </div>
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>

      <!-- Pagination Controls -->
      {% if total_pages > 1 %}
      <div class="pagination" style="display: flex; justify-content: center; align-items: center; gap: 12px; margin: 24px 0; padding: 20px; background: var(--bg); border-radius: 8px; border: 1px solid var(--border);">
        {% if has_prev %}
          <a href="/admin/users?page={{prev_page}}" class="btn-primary btn-small">← Previous</a>
        {% else %}
          <span class="btn-small" style="background: var(--bg); color: var(--text); opacity: 0.5; cursor: not-allowed;">← Previous</span>
        {% endif %}

        <div style="display: flex; gap: 8px; align-items: center;">
          {% for page_num in range(1, total_pages + 1) %}
            {% if page_num == current_page %}
              <span class="btn-small" style="background: var(--primary); color: white; font-weight: bold;">{{page_num}}</span>
            {% elif page_num <= 3 or page_num > total_pages - 3 or (page_num >= current_page - 1 and page_num <= current_page + 1) %}
              <a href="/admin/users?page={{page_num}}" class="btn-small" style="background: var(--card-bg); border: 1px solid var(--border);">{{page_num}}</a>
            {% elif page_num == 4 and current_page > 5 %}
              <span style="color: var(--text); opacity: 0.5;">...</span>
            {% elif page_num == total_pages - 3 and current_page < total_pages - 4 %}
              <span style="color: var(--text); opacity: 0.5;">...</span>
            {% endif %}
          {% endfor %}
        </div>

        {% if has_next %}
          <a href="/admin/users?page={{next_page}}" class="btn-primary btn-small">Next →</a>
        {% else %}
          <span class="btn-small" style="background: var(--bg); color: var(--text); opacity: 0.5; cursor: not-allowed;">Next →</span>
        {% endif %}
      </div>
      {% endif %}

    {% else %}
      <p style="text-align: center; color: #6b7280; margin: 40px 0;">No users found.</p>
    {% endif %}
  </div>
</div>
"""

EDIT_USER_TEMPLATE = """
<div class="container">
  <div class="card">
    <h1>✏️ Edit User: {{user[0]}}</h1>
    <div class="nav-links">
      <a href="/admin/users">← Back to Users</a>
    </div>
  </div>

  <div class="card">
    <form method="POST">
      <div class="form-group">
        <label>Username</label>
        <input value="{{user[0]}}" disabled style="background: var(--bg); opacity: 0.7;">
        <small style="color: var(--text); opacity: 0.7;">Username cannot be changed</small>
      </div>
      <div class="form-group">
        <label>Email</label>
        <input name="email" type="email" value="{{user[1] or ''}}" placeholder="user@example.com">
      </div>
      <div class="form-group">
        <label>New Password (leave blank to keep current)</label>
        <input name="new_password" type="password" placeholder="Enter new password">
        <small style="color: var(--text); opacity: 0.7;">Only enter if you want to change the password</small>
      </div>
      <button type="submit" class="btn-success">💾 Save Changes</button>
    </form>
  </div>
</div>
"""

EDIT_ADMIN_TEMPLATE = """
<div class="container">
  <div class="card">
    <h1>✏️ Edit Admin: {{admin[0]}}</h1>
    <div class="nav-links">
      <a href="/admin/dashboard">← Back to Dashboard</a>
    </div>
  </div>

  <div class="card">
    <form method="POST">
      <div class="form-group">
        <label>Username</label>
        <input value="{{admin[0]}}" disabled style="background: var(--bg); opacity: 0.7;">
        <small style="color: var(--text); opacity: 0.7;">Username cannot be changed</small>
      </div>
      <div class="form-group">
        <label>Email</label>
        <input name="email" type="email" value="{{admin[1] or ''}}" placeholder="admin@example.com">
      </div>
      <div class="form-group">
        <label>Role</label>
        <select name="role" required>
          <option value="Operator" {{ 'selected' if admin[2] == 'Operator' else '' }}>Operator</option>
          <option value="Admin" {{ 'selected' if admin[2] == 'Admin' else '' }}>Admin</option>
          <option value="Super Admin" {{ 'selected' if admin[2] == 'Super Admin' else '' }}>Super Admin</option>
        </select>
      </div>
      <div class="form-group">
        <label>New Password (leave blank to keep current)</label>
        <input name="new_password" type="password" placeholder="Enter new password">
        <small style="color: var(--text); opacity: 0.7;">Only enter if you want to change the password</small>
      </div>
      <button type="submit" class="btn-success">💾 Save Changes</button>
    </form>
  </div>
</div>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

# This makes the app available for gunicorn
application = app