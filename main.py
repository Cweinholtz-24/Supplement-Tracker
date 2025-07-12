import os, json, io, base64, sqlite3, psutil, time, csv
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify, Response, flash, make_response
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

        # User reminders table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_reminders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                protocol_id TEXT NOT NULL,
                reminder_time TEXT NOT NULL,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Default compounds table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS default_compounds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                unit TEXT DEFAULT 'mg',
                default_dosage TEXT DEFAULT '1',
                category TEXT DEFAULT 'supplement',
                description TEXT DEFAULT '',
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
    """Decorator to require admin authentication"""```python
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

@app.route("/api/recent-activity", methods=["GET"])
def api_recent_activity():
    """API endpoint for recent user activity"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Get user ID
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            user_row = cursor.fetchone()
            if not user_row:
                return jsonify({"error": "User not found"}), 404
            user_id = user_row[0]

            activities = []

            # Recent protocol logs
            cursor.execute("""
                SELECT p.name, pl.log_date, pl.compound, pl.taken
                FROM protocol_logs pl
                JOIN protocols p ON pl.protocol_id = p.id
                WHERE p.user_id = ?
                ORDER BY pl.created_at DESC
                LIMIT 10
            """, (user_id,))

            for row in cursor.fetchall():
                protocol_name, log_date, compound, taken = row
                action = "✅ Completed" if taken else "⏸️ Skipped"
                activities.append({
                    "message": f"{action} {compound} in {protocol_name}",
                    "timestamp": log_date,
                    "type": "log"
                })

            # Recent protocol creation
            cursor.execute("""
                SELECT name, created_at FROM protocols
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 5
            """, (user_id,))

            for row in cursor.fetchall():
                protocol_name, created_at = row
                activities.append({
                    "message": f"📋 Created protocol: {protocol_name}",
                    "timestamp": created_at,
                    "type": "protocol_created"
                })

            # Sort by timestamp and limit to 10 most recent
            activities.sort(key=lambda x: x['timestamp'], reverse=True)
            activities = activities[:10]

            return jsonify({"activities": activities}), 200

    except Exception as e:
        return jsonify({"error": f"Failed to fetch recent activity: {str(e)}"}), 500

@app.route("/api/dashboard/summary", methods=["GET"])
def api_dashboard_summary():
    """API endpoint to get dashboard summary"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        data = load_data(username)
        today = date.today().isoformat()

        total_protocols = len(data["protocols"])
        protocols_due_today = total_protocols
        completed_today = 0
        current_streak = 0
        total_adherence = 0

        # Calculate stats
        for protocol in data["protocols"].values():
            if today in protocol["logs"]:
                day_log = protocol["logs"][today]
                if all(entry.get("taken", False) for entry in day_log.values()):
                    completed_today += 1

        # Calculate overall adherence
        total_days = 0
        total_taken = 0
        for protocol in data["protocols"].values():
            for day_log in protocol["logs"].values():
                total_days += len(day_log)
                total_taken += sum(1 for entry in day_log.values() if entry.get("taken", False))

        adherence_rate = round((total_taken / total_days) * 100, 1) if total_days > 0 else 0

        return jsonify({
            "protocolsToday": protocols_due_today,
            "completedToday": completed_today,
            "currentStreak": current_streak,
            "adherenceRate": adherence_rate
        }), 200

    except Exception as e:
        return jsonify({"error": f"Failed to fetch dashboard summary: {str(e)}"}), 500

@app.route("/api/protocols/<protocol_id>/log", methods=["POST"])
def api_save_protocol_log(protocol_id):
    """API endpoint to save protocol log"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        user_data = load_data(username)
        protocol_name = protocol_id.replace("_", " ").title()

        # Find matching protocol name
        matching_protocol = None
        for pname in user_data.get("protocols", {}):
            if pname.replace(" ", "_").lower() == protocol_id:
                matching_protocol = pname
                break

        if not matching_protocol:
            return jsonify({"error": "Protocol not found"}), 404

        today = date.today().isoformat()

        if "logs" not in user_data["protocols"][matching_protocol]:
            user_data["protocols"][matching_protocol]["logs"] = {}

        if today not in user_data["protocols"][matching_protocol]["logs"]:
            user_data["protocols"][matching_protocol]["logs"][today] = {}

        # Update compounds
        compounds = data.get('compounds', {})
        notes = data.get('notes', {})

        for compound, taken in compounds.items():
            user_data["protocols"][matching_protocol]["logs"][today][compound] = {
                "taken": taken,
                "note": notes.get(compound, "")
            }

        save_data(user_data, username)

        return jsonify({
            "success": True,
            "message": "Protocol log saved successfully"
        }), 200

    except Exception as e:
        return jsonify({"error": f"Failed to save log: {str(e)}"}), 500

@app.route("/api/protocols/<protocol_id>/history", methods=["GET"])
def api_get_protocol_history(protocol_id):
    """API endpoint to get protocol history"""
    # Return dummy history data
    history = [
        {
            "id": "1",
            "date": "2024-01-01",
            "compounds": {
                "FOXO4-DRI": {"taken": True, "note": "Felt good"},
                "Fisetin": {"taken": True, "note": ""},
                "Quercetin": {"taken": False, "note": "Forgot to take"}
            },
            "mood": "Good",
            "energy": "High",
            "sideEffects": "None",
            "weight": "70kg",
            "generalNotes": "Great day overall"
        }
    ]

    return jsonify(history), 200

@app.route("/api/user/profile", methods=["GET"])
def api_get_user_profile():
    """API endpoint to get user profile"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, email, created_at FROM users WHERE username = ?", (username,))
            user_row = cursor.fetchone()

            if not user_row:
                return jsonify({"error": "User not found"}), 404

            cursor.execute("SELECT COUNT(*) FROM protocols WHERE user_id = (SELECT id FROM users WHERE username = ?)", (username,))
            protocol_count = cursor.fetchone()[0]

            profile = {
                "username": user_row[0],
                "email": user_row[1] or "",
                "createdAt": user_row[2],
                "protocolCount": protocol_count
            }

            return jsonify(profile), 200
    except Exception as e:
        return jsonify({"error": f"Failed to fetch profile: {str(e)}"}), 500

@app.route("/api/notifications", methods=["GET"])
def api_get_notifications():
    """API endpoint to get user notifications"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, title, message, type, is_read, created_at
                FROM notifications 
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
                ORDER BY created_at DESC LIMIT 20
            ''', (username,))

            notifications = []
            for row in cursor.fetchall():
                notifications.append({
                    "id": row[0],
                    "title": row[1],
                    "message": row[2],
                    "type": row[3],
                    "isRead": bool(row[4]),
                    "createdAt": row[5]
                })

            return jsonify(notifications), 200
    except Exception as e:
        return jsonify({"error": f"Failed to fetch notifications: {str(e)}"}), 500

@app.route("/api/notifications/<int:notification_id>/read", methods=["POST"])
def api_mark_notification_read(notification_id):
    """API endpoint to mark notification as read"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE notifications SET is_read = TRUE 
                WHERE id = ? AND user_id = (SELECT id FROM users WHERE username = ?)
            ''', (notification_id, username))
            conn.commit()

            return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to mark notification as read: {str(e)}"}), 500

@app.route("/api/protocols/<protocol_id>/analytics", methods=["GET"])
def api_get_protocol_analytics(protocol_id):
    """API endpoint to get protocol analytics with AI insights"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        data = load_data(username)

        # Find matching protocol
        matching_protocol = None
        for pname in data.get("protocols", {}):
            if pname.replace(" ", "_").lower() == protocol_id:
                matching_protocol = pname
                break

        if not matching_protocol:
            return jsonify({"error": "Protocol not found"}), 404

        prot = data["protocols"][matching_protocol]
        logs = prot["logs"]

        total_days = len(logs)
        if total_days == 0:
            return jsonify({
                "totalDays": 0,
                "adherence": 0,
                "streak": 0,
                "missedDays": 0,
                "compoundStats": {},
                "aiInsights": [],
                "predictions": {},
                "correlations": [],
                "weeklyTrends": [],
                "monthlyTrends": []
            }), 200

        # Basic stats
        compound_stats = {}
        weekly_data = {}
        monthly_data = {}
        mood_energy_correlation = []

        for compound in prot["compounds"]:
            name = compound if isinstance(compound, str) else compound.get('name', compound)
            taken_count = sum(1 for day_log in logs.values() 
                             if day_log.get(name, {}).get("taken", False))
            compound_stats[name] = {
                "taken": taken_count,
                "missed": total_days - taken_count,
                "percentage": round((taken_count / total_days) * 100, 1)
            }

        # Weekly and monthly trends
        for date_str, day_log in logs.items():
            try:
                log_date = datetime.strptime(date_str, "%Y-%m-%d").date()
                week = log_date.strftime("%Y-W%U")
                month = log_date.strftime("%Y-%m")

                day_adherence = sum(1 for entry in day_log.values() if entry.get("taken", False)) / len(day_log) * 100

                if week not in weekly_data:
                    weekly_data[week] = []
                if month not in monthly_data:
                    monthly_data[month] = []

                weekly_data[week].append(day_adherence)
                monthly_data[month].append(day_adherence)

                # Mood/energy correlation
                mood = day_log.get('mood', '')
                energy = day_log.get('energy', '')
                if mood and energy:
                    mood_energy_correlation.append({
                        "date": date_str,
                        "adherence": day_adherence,
                        "mood": mood,
                        "energy": energy
                    })
            except ValueError:
                continue

        # Calculate weekly and monthly averages
        weekly_trends = [{"week": week, "adherence": round(sum(values)/len(values), 1)} 
                        for week, values in weekly_data.items()]
        monthly_trends = [{"month": month, "adherence": round(sum(values)/len(values), 1)} 
                         for month, values in monthly_data.items()]

        total_possible = total_days * len(prot["compounds"])
        total_taken = sum(sum(1 for entry in day_log.values() if entry.get("taken", False)) 
                         for day_log in logs.values())
        overall_adherence = round((total_taken / total_possible) * 100, 1) if total_possible > 0 else 0

        # Calculate streak
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

        # AI Insights generation
        ai_insights = generate_ai_insights(logs, compound_stats, overall_adherence, current_streak)

        # Predictions
        predictions = generate_predictions(weekly_trends, monthly_trends, overall_adherence)

        analytics = {
            "totalDays": total_days,
            "adherence": overall_adherence,
            "streak": current_streak,
            "missedDays": missed_days,
            "compoundStats": compound_stats,
            "aiInsights": ai_insights,
            "predictions": predictions,
            "correlations": mood_energy_correlation,
            "weeklyTrends": weekly_trends,
            "monthlyTrends": monthly_trends,
            "bestPerformingDay": get_best_performing_day(logs),
            "adherencePattern": analyze_adherence_pattern(logs)
        }

        return jsonify(analytics), 200
    except Exception as e:
        return jsonify({"error": f"Failed to fetch analytics: {str(e)}"}), 500

def generate_ai_insights(logs, compound_stats, adherence, streak):
    """Generate AI-powered insights from user data"""
    insights = []

    # Adherence insights
    if adherence >= 90:
        insights.append({
            "type": "success",
            "title": "Excellent Adherence! 🌟",
            "message": f"You're maintaining {adherence}% adherence. This consistency will maximize your supplement benefits.",
            "priority": "high"
        })
    elif adherence >= 70:
        insights.append({
            "type": "warning",
            "title": "Good Progress 📈",
            "message": f"Your {adherence}% adherence is good. Try setting reminders to reach 90%+ for optimal results.",
            "priority": "medium"
        })
    else:
        insights.append({
            "type": "alert",
            "title": "Improvement Needed 🎯",
            "message": f"Your {adherence}% adherence could be improved. Consider simplifying your protocol or setting up automated reminders.",
            "priority": "high"
        })

    # Streak insights
    if streak >= 7:
        insights.append({
            "type": "achievement",
            "title": f"Amazing {streak}-Day Streak! 🔥",
            "message": "Consistent daily habits lead to lasting health benefits. Keep it up!",
            "priority": "medium"
        })

    # Compound-specific insights
    for compound, stats in compound_stats.items():
        if stats["percentage"] < 50:
            insights.append({
                "type": "suggestion",
                "title": f"Focus on {compound} 💊",
                "message": f"You're only taking {compound} {stats['percentage']}% of the time. Consider if this supplement is necessary or set specific reminders.",
                "priority": "low"
            })

    # Pattern-based insights
    if len(logs) >= 14:
        recent_logs = list(logs.keys())[-14:]
        recent_adherence = []
        for date_str in recent_logs:
            day_log = logs[date_str]
            day_adherence = sum(1 for entry in day_log.values() if entry.get("taken", False)) / len(day_log)
            recent_adherence.append(day_adherence)

        if len(recent_adherence) >= 7:
            first_week = sum(recent_adherence[:7]) / 7
            second_week = sum(recent_adherence[7:14]) / 7

            if second_week > first_week + 0.1:
                insights.append({
                    "type": "trending",
                    "title": "Improving Trend! 📊",
                    "message": "Your adherence has improved significantly in the past week. You're building strong habits!",
                    "priority": "medium"
                })
            elif first_week > second_week + 0.1:
                insights.append({
                    "type": "warning",
                    "title": "Declining Pattern 📉",
                    "message": "Your adherence has decreased recently. Consider what changed and adjust your routine.",
                    "priority": "high"
                })

    return insights

def generate_predictions(weekly_trends, monthly_trends, current_adherence):
    """Generate predictive analytics"""
    predictions = {}

    if len(weekly_trends) >= 4:
        recent_weeks = [trend["adherence"] for trend in weekly_trends[-4:]]
        avg_change = sum([recent_weeks[i] - recent_weeks[i-1] for i in range(1, len(recent_weeks))]) / (len(recent_weeks) - 1)

        next_week_prediction = min(100, max(0, current_adherence + avg_change))
        predictions["nextWeekAdherence"] = round(next_week_prediction, 1)

        if avg_change > 2:
            predictions["trend"] = "improving"
        elif avg_change < -2:
            predictions["trend"] = "declining"
        else:
            predictions["trend"] = "stable"

    # Goal achievement prediction
    target_adherence = 90
    if current_adherence < target_adherence:
        days_needed = max(7, (target_adherence - current_adherence) * 2)
        predictions["daysToReachGoal"] = int(days_needed)

    return predictions

def get_best_performing_day(logs):
    """Find the day of the week with best adherence"""
    day_performance = {}

    for date_str, day_log in logs.items():
        try:
            log_date = datetime.strptime(date_str, "%Y-%m-%d").date()
            day_of_week = log_date.strftime("%A")

            day_adherence = sum(1 for entry in day_log.values() if entry.get("taken", False)) / len(day_log)

            if day_of_week not in day_performance:
                day_performance[day_of_week] = []
            day_performance[day_of_week].append(day_adherence)
        except ValueError:
            continue

    if not day_performance:
        return None

    day_averages = {day: sum(adherences)/len(adherences) for day, adherences in day_performance.items()}
    best_day = max(day_averages, key=day_averages.get)

    return {
        "day": best_day,
        "adherence": round(day_averages[best_day] * 100, 1)
    }

def analyze_adherence_pattern(logs):
    """Analyze adherence patterns over time"""
    if len(logs) < 7:
        return "insufficient_data"

    recent_week = list(logs.keys())[-7:]
    adherence_scores = []

    for date_str in recent_week:
        day_log = logs[date_str]
        score = sum(1 for entry in day_log.values() if entry.get("taken", False)) / len(day_log)
        adherence_scores.append(score)

    avg_adherence = sum(adherence_scores) / len(adherence_scores)
    consistency = 1 - (max(adherence_scores) - min(adherence_scores))

    if avg_adherence >= 0.9 and consistency >= 0.8:
        return "excellent"
    elif avg_adherence >= 0.7 and consistency >= 0.6:
        return "good"
    elif avg_adherence >= 0.5:
        return "needs_improvement"
    else:
        return "poor"

@app.route("/api/protocols/<protocol_id>/calendar", methods=["GET"])
def api_get_protocol_calendar(protocol_id):
    """API endpoint to get protocol calendar data"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        data = load_data(username)

        # Find matching protocol
        matching_protocol = None
        for pname in data.get("protocols", {}):
            if pname.replace(" ", "_").lower() == protocol_id:
                matching_protocol = pname
                break

        if not matching_protocol:
            return jsonify({"error": "Protocol not found"}), 404

        prot = data["protocols"][matching_protocol]
        calendar_events = []

        for date_str, entries in prot["logs"].items():
            taken_count = sum(1 for e in entries.values() if e.get("taken"))
            total = len(entries)
            missed = total - taken_count

            calendar_events.append({
                "date": date_str,
                "taken": taken_count,
                "total": total,
                "missed": missed,
                "completed": missed == 0,
                "entries": entries
            })

        return jsonify(calendar_events), 200
    except Exception as e:
        return jsonify({"error": f"Failed to fetch calendar data: {str(e)}"}), 500

@app.route("/manifest.json")
def manifest():
    """PWA manifest for app-like experience"""
    with open("templates/mobile_manifest.json", "r") as f:
        return jsonify(json.load(f))

@app.route("/api/compounds/default", methods=["GET"])
def api_get_default_compounds():
    """API endpoint to get default compounds list"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, unit, default_dosage, category, description FROM default_compounds ORDER BY name")
            compounds = []
            for row in cursor.fetchall():
                compounds.append({
                    "name": row[0],
                    "unit": row[1],
                    "defaultDosage": row[2],
                    "category": row[3],
                    "description": row[4]
                })

            # If no compounds in database, add defaults
            if not compounds:
                default_compounds = [
                    ("FOXO4-DRI", "mg", "10", "peptide", "Senolytic peptide"),
                    ("Fisetin", "mg", "100", "supplement", "Natural senolytic compound"),
                    ("Quercetin", "mg", "500", "supplement", "Flavonoid with senolytic properties"),
                    ("Resveratrol", "mg", "250", "supplement", "Polyphenol antioxidant"),
                    ("Curcumin", "mg", "500", "supplement", "Anti-inflammatory compound"),
                    ("Pterostilbene", "mg", "50", "supplement", "Resveratrol derivative"),
                    ("Luteolin", "mg", "100", "supplement", "Flavonoid compound"),
                    ("Apigenin", "mg", "50", "supplement", "Flavonoid found in herbs")
                ]

                for name, unit, dosage, category, description in default_compounds:
                    cursor.execute('''
                        INSERT INTO default_compounds (name, unit, default_dosage, category, description)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (name, unit, dosage, category, description))

                conn.commit()

                # Return the default compounds
                compounds = [
                    {"name": name, "unit": unit, "defaultDosage": dosage, "category": category, "description": description}
                    for name, unit, dosage, category, description in default_compounds
                ]

        return jsonify(compounds), 200
    except Exception as e:
        return jsonify({"error": f"Failed to fetch default compounds: {str(e)}"}), 500

@app.route("/api/compounds/add", methods=["POST"])
def api_add_custom_compound():
    """API endpoint to add custom compound"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json()
    if not data or not data.get('name'):
        return jsonify({"error": "Compound name is required"}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO default_compounds (name, unit, default_dosage, category, description, created_by)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                data.get('name'),
                data.get('unit', 'mg'),
                data.get('defaultDosage', '1'),
                data.get('category', 'supplement'),
                data.get('description', ''),
                username
            ))
            conn.commit()

        return jsonify({"success": True}), 201
    except Exception as e:
        return jsonify({"error": f"Failed to add compound: {str(e)}"}), 500

@app.route("/admin/compounds", methods=["GET", "POST"])
@login_required
@admin_required
def admin_manage_compounds():
    """Admin endpoint to manage default compounds"""
    if request.method == "POST":
        data = request.get_json()
        compounds = data.get('compounds', [])

        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Clear existing compounds
            cursor.execute("DELETE FROM default_compounds")

            # Insert new compounds
            for compound in compounds:
                cursor.execute('''
                    INSERT INTO default_compounds (name, unit, default_dosage, category, description, created_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    compound.get('name'),
                    compound.get('unit', 'mg'),
                    compound.get('defaultDosage', '1'),
                    compound.get('category', 'supplement'),
                    compound.get('description', ''),
                    current_user.username
                ))

            conn.commit()

        return jsonify({"success": True}), 200

    # GET request
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, unit, default_dosage, category, description FROM default_compounds ORDER BY name")
            compounds = []
            for row in cursor.fetchall():
                compounds.append({
                    "name": row[0],
                    "unit": row[1],
                    "defaultDosage": row[2],
                    "category": row[3],
                    "description": row[4]
                })
        return jsonify(compounds), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/protocols/templates", methods=["GET"])
def api_get_protocol_templates():
    """Get pre-built protocol templates"""
    templates = [
        {
            "id": "longevity_basic",
            "name": "Longevity Basics",
            "description": "Essential compounds for healthy aging",
            "category": "longevity",
            "compounds": [
                {"name": "NMN", "daily_dosage": "250", "times_per_day": 1, "unit": "mg"},
                {"name": "Resveratrol", "daily_dosage": "500", "times_per_day": 1, "unit": "mg"},
                {"name": "Vitamin D3", "daily_dosage": "2000", "times_per_day": 1, "unit": "IU"}
            ],
            "duration": "ongoing",
            "difficulty": "beginner"
        },
        {
            "id": "senolytic_cycle",
            "name": "Senolytic Cycle",
            "description": "3-day senolytic protocol for cellular renewal",
            "category": "senolytics",
            "compounds": [
                {"name": "Fisetin", "daily_dosage": "1000", "times_per_day": 2, "unit": "mg"},
                {"name": "Quercetin", "daily_dosage": "1000", "times_per_day": 2, "unit": "mg"},
                {"name": "FOXO4-DRI", "daily_dosage": "10", "times_per_day": 1, "unit": "mg"}
            ],
            "duration": "3_days",
            "difficulty": "advanced",
            "notes": "Take for 3 consecutive days, then rest for 1 month"
        },
        {
            "id": "cognitive_enhancement",
            "name": "Cognitive Enhancement",
            "description": "Supplements for brain health and cognition",
            "category": "nootropics",
            "compounds": [
                {"name": "Lion's Mane", "daily_dosage": "1000", "times_per_day": 1, "unit": "mg"},
                {"name": "Bacopa Monnieri", "daily_dosage": "300", "times_per_day": 1, "unit": "mg"},
                {"name": "Alpha-GPC", "daily_dosage": "600", "times_per_day": 1, "unit": "mg"}
            ],
            "duration": "ongoing",
            "difficulty": "intermediate"
        }
    ]
    return jsonify(templates), 200

@app.route("/api/protocols/cycles", methods=["GET", "POST"])
def api_manage_protocol_cycles():
    """Manage cycling protocols (on/off schedules)"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    if request.method == "POST":
        data = request.get_json()
        protocol_id = data.get('protocolId')
        cycle_config = data.get('cycleConfig')

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS protocol_cycles (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        protocol_id TEXT NOT NULL,
                        cycle_type TEXT NOT NULL,
                        on_days INTEGER NOT NULL,
                        off_days INTEGER NOT NULL,
                        start_date DATE NOT NULL,
                        is_active BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')

                cursor.execute('''
                    INSERT INTO protocol_cycles 
                    (user_id, protocol_id, cycle_type, on_days, off_days, start_date)
                    VALUES ((SELECT id FROM users WHERE username = ?), ?, ?, ?, ?, ?)
                ''', (username, protocol_id, cycle_config['type'], 
                     cycle_config['onDays'], cycle_config['offDays'], cycle_config['startDate']))

                conn.commit()

            return jsonify({"success": True}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # GET cycles
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT protocol_id, cycle_type, on_days, off_days, start_date, is_active
                FROM protocol_cycles
                WHERE user_id = (SELECT id FROM users WHERE username = ?) AND is_active = TRUE
            ''', (username,))

            cycles = []
            for row in cursor.fetchall():
                cycles.append({
                    "protocolId": row[0],
                    "cycleType": row[1],
                    "onDays": row[2],
                    "offDays": row[3],
                    "startDate": row[4],
                    "isActive": bool(row[5])
                })

            return jsonify(cycles), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/protocols/stacks", methods=["GET", "POST"])
def api_manage_protocol_stacks():
    """Manage protocol stacking (combining multiple protocols)"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    if request.method == "POST":
        data = request.get_json()
        stack_name = data.get('name')
        protocol_ids = data.get('protocolIds', [])
        interactions = data.get('interactions', [])

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS protocol_stacks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        name TEXT NOT NULL,
                        protocol_ids TEXT NOT NULL,
                        interactions TEXT DEFAULT '[]',
                        warnings TEXT DEFAULT '[]',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')

                cursor.execute('''
                    INSERT INTO protocol_stacks (user_id, name, protocol_ids, interactions)
                    VALUES ((SELECT id FROM users WHERE username = ?), ?, ?, ?)
                ''', (username, stack_name, json.dumps(protocol_ids), json.dumps(interactions)))

                conn.commit()

            return jsonify({"success": True}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # GET stacks
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT name, protocol_ids, interactions, warnings, created_at
                FROM protocol_stacks
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
            ''', (username,))

            stacks = []
            for row in cursor.fetchall():
                stacks.append({
                    "name": row[0],
                    "protocolIds": json.loads(row[1]),
                    "interactions": json.loads(row[2]),
                    "warnings": json.loads(row[3]),
                    "createdAt": row[4]
                })

            return jsonify(stacks), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/protocols/cost-tracking", methods=["GET", "POST"])
def api_cost_tracking():
    """Track supplement costs and budgets"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    if request.method == "POST":
        data = request.get_json()

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS supplement_costs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        compound_name TEXT NOT NULL,
                        cost_per_unit REAL NOT NULL,
                        units_per_bottle INTEGER NOT NULL,
                        bottle_cost REAL NOT NULL,
                        supplier TEXT DEFAULT '',
                        purchase_date DATE DEFAULT CURRENT_DATE,
                        expiry_date DATE,
                        notes TEXT DEFAULT '',
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')

                cursor.execute('''
                    INSERT INTO supplement_costs 
                    (user_id, compound_name, cost_per_unit, units_per_bottle, bottle_cost, supplier, expiry_date)
                    VALUES ((SELECT id FROM users WHERE username = ?), ?, ?, ?, ?, ?, ?)
                ''', (username, data['compoundName'], data['costPerUnit'], 
                     data['unitsPerBottle'], data['bottleCost'], 
                     data.get('supplier', ''), data.get('expiryDate')))

                conn.commit()

            return jsonify({"success": True}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # GET cost data
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT compound_name, cost_per_unit, units_per_bottle, bottle_cost, 
                       supplier, purchase_date, expiry_date
                FROM supplement_costs
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
                ORDER BY purchase_date DESC
            ''', (username,))

            costs = []
            total_monthly_cost = 0

            for row in cursor.fetchall():
                cost_data = {
                    "compoundName": row[0],
                    "costPerUnit": row[1],
                    "unitsPerBottle": row[2],
                    "bottleCost": row[3],
                    "supplier": row[4],
                    "purchaseDate": row[5],
                    "expiryDate": row[6]
                }
                costs.append(cost_data)

                # Calculate monthly cost (assuming 30-day supply)
                daily_cost = cost_data["costPerUnit"]
                total_monthly_cost += daily_cost * 30

            return jsonify({
                "costs": costs,
                "monthlyTotal": round(total_monthly_cost, 2),
                "yearlyEstimate": round(total_monthly_cost * 12, 2)
            }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/protocols/<protocol_id>/stats", methods=["GET"])
def api_get_protocol_stats(protocol_id):
    """API endpoint to get detailed protocol statistics with advanced features"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        data = load_data(username)

        # Find matching protocol
        matching_protocol = None
        for pname in data.get("protocols", {}):
            if pname.replace(" ", "_").lower() == protocol_id:
                matching_protocol = pname
                break

        if not matching_protocol:
            return jsonify({"error": "Protocol not found"}), 404

        prot = data["protocols"][matching_protocol]
        logs = prot["logs"]

        # Calculate advanced statistics
        total_days = len(logs)
        if total_days == 0:
            return jsonify({"totalDays": 0, "weeklyStats": [], "monthlyStats": [], "trends": {}}), 200

        # Weekly statistics
        weekly_stats = {}
        monthly_stats = {}
        compound_timing = {}
        side_effects = {}

        for date_str, day_log in logs.items():
            try:
                log_date = datetime.strptime(date_str, "%Y-%m-%d").date()
                week = log_date.strftime("%Y-W%U")
                month = log_date.strftime("%Y-%m")

                if week not in weekly_stats:
                    weekly_stats[week] = {"taken": 0, "total": 0, "days": 0}
                if month not in monthly_stats:
                    monthly_stats[month] = {"taken": 0, "total": 0, "days": 0}

                day_taken = sum(1 for entry in day_log.values() if entry.get("taken", False))
                day_total = len(day_log)

                weekly_stats[week]["taken"] += day_taken
                weekly_stats[week]["total"] += day_total
                weekly_stats[week]["days"] += 1

                monthly_stats[month]["taken"] += day_taken
                monthly_stats[month]["total"] += day_total
                monthly_stats[month]["days"] += 1

                # Track side effects
                if day_log.get('side_effects'):
                    effect = day_log['side_effects']
                    if effect not in side_effects:
                        side_effects[effect] = 0
                    side_effects[effect] += 1

            except ValueError:
                continue

        # Convert to percentages
        for week_data in weekly_stats.values():
            week_data["percentage"] = round((week_data["taken"] / week_data["total"]) * 100, 1) if week_data["total"] > 0 else 0

        for month_data in monthly_stats.values():
            month_data["percentage"] = round((month_data["taken"] / month_data["total"]) * 100, 1) if month_data["total"] > 0 else 0

        return jsonify({
            "totalDays": total_days,
            "weeklyStats": weekly_stats,
            "monthlyStats": monthly_stats,
            "compoundCount": len(prot["compounds"]),
            "sideEffects": side_effects,
            "avgMoodRating": calculate_avg_mood(logs),
            "avgEnergyRating": calculate_avg_energy(logs),
            "bestComplianceWeek": get_best_week(weekly_stats),
            "improvementSuggestions": generate_improvement_suggestions(logs, weekly_stats)
        }), 200

    except Exception as e:
        return jsonify({"error": f"Failed to fetch stats: {str(e)}"}), 500

def calculate_avg_mood(logs):
    """Calculate average mood rating"""
    mood_scores = []
    mood_mapping = {"excellent": 5, "good": 4, "neutral": 3, "poor": 2, "terrible": 1}

    for day_log in logs.values():
        mood = day_log.get('mood', '').lower()
        if mood in mood_mapping:
            mood_scores.append(mood_mapping[mood])

    return round(sum(mood_scores) / len(mood_scores), 1) if mood_scores else 0

def calculate_avg_energy(logs):
    """Calculate average energy rating"""
    energy_scores = []
    energy_mapping = {"high": 5, "good": 4, "moderate": 3, "low": 2, "exhausted": 1}

    for day_log in logs.values():
        energy = day_log.get('energy', '').lower()
        if energy in energy_mapping:
            energy_scores.append(energy_mapping[energy])

    return round(sum(energy_scores) / len(energy_scores), 1) if energy_scores else 0

def get_best_week(weekly_stats):
    """Find the week with highest adherence"""
    if not weekly_stats:
        return None

    best_week = max(weekly_stats.items(), key=lambda x: x[1]["percentage"])
    return {"week": best_week[0], "adherence": best_week[1]["percentage"]}

def generate_improvement_suggestions(logs, weekly_stats):
    """Generate personalized improvement suggestions"""
    suggestions = []

    # Analyze patterns
    if len(weekly_stats) >= 4:
        recent_weeks = list(weekly_stats.values())[-4:]
        adherence_trend = [week["percentage"] for week in recent_weeks]

        if adherence_trend[-1] < adherence_trend[0]:
            suggestions.append({
                "type": "trend",
                "message": "Your adherence has been declining. Consider reviewing your routine and identifying barriers."
            })

    # Side effect analysis
    side_effects_count = sum(1 for day_log in logs.values() if day_log.get('side_effects'))
    if side_effects_count > len(logs) * 0.2:  # More than 20% of days
        suggestions.append({
            "type": "health",
            "message": "You're reporting side effects frequently. Consider consulting with a healthcare provider."
        })

    return suggestions

@app.route("/api/reminders/smart", methods=["GET", "POST"])
def api_smart_reminders():
    """Smart context-aware reminders"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    if request.method == "POST":
        data = request.get_json()

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS smart_reminders (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        protocol_id TEXT NOT NULL,
                        reminder_type TEXT NOT NULL,
                        context_trigger TEXT NOT NULL,
                        custom_message TEXT,
                        enabled BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')

                cursor.execute('''
                    INSERT INTO smart_reminders 
                    (user_id, protocol_id, reminder_type, context_trigger, custom_message)
                    VALUES ((SELECT id FROM users WHERE username = ?), ?, ?, ?, ?)
                ''', (username, data.get('protocolId'), data.get('type'), 
                     data.get('trigger'), data.get('message')))

                conn.commit()

            return jsonify({"success": True}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # GET smart reminders
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT protocol_id, reminder_type, context_trigger, custom_message, enabled
                FROM smart_reminders
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
            ''', (username,))

            reminders = []
            for row in cursor.fetchall():
                reminders.append({
                    "protocolId": row[0],
                    "type": row[1],
                    "trigger": row[2],
                    "message": row[3],
                    "enabled": bool(row[4])
                })

            return jsonify({
                "reminders": reminders,
                "suggestions": []
            }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/voice-commands", methods=["POST"])
def api_voice_commands():
    """Process voice commands for hands-free operation"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json()
    command = data.get('command', '').lower()

    try:
        # Parse voice commands
        if 'mark' in command and 'taken' in command:
            # Extract protocol/compound name
            protocols = load_data(username)["protocols"]

            for protocol_name in protocols.keys():
                if protocol_name.lower() in command:
                    # Mark as taken
                    today = date.today().isoformat()
                    if today not in protocols[protocol_name]["logs"]:
                        protocols[protocol_name]["logs"][today] = {}

                    for compound in protocols[protocol_name]["compounds"]:
                        compound_name = compound if isinstance(compound, str) else compound.get('name')
                        if compound_name.lower() in command:
                            protocols[protocol_name]["logs"][today][compound_name] = {
                                "taken": True,
                                "note": "Logged via voice command"
                            }

                    save_data({"protocols": protocols}, username)
                    return jsonify({
                        "success": True,
                        "message": f"Marked supplements in {protocol_name} as taken",
                        "action": "mark_taken"
                    }), 200

        elif 'status' in command or 'progress' in command:
            # Get status
            data = load_data(username)
            total_protocols = len(data["protocols"])
            today = date.today().isoformat()

            completed_today = 0
            for protocol in data["protocols"].values():
                if today in protocol["logs"]:
                    day_log = protocol["logs"][today]
                    if all(entry.get("taken", False) for entry in day_log.values()):
                        completed_today += 1

            return jsonify({
                "success": True,
                "message": f"You have completed {completed_today} out of {total_protocols} protocols today",
                "action": "status_report",
                "data": {"completed": completed_today, "total": total_protocols}
            }), 200

        else:
            return jsonify({
                "success": False,
                "message": "Command not recognized. Try 'Mark [compound] as taken' or 'Show my progress'",
                "action": "unknown"
            }), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/barcode/scan", methods=["POST"])
def api_barcode_scan():
    """Process barcode scans to add supplements"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json()
    barcode = data.get('barcode')

    try:
        # Mock supplement database lookup
        supplement_database = {
            "123456789": {
                "name": "Vitamin D3",
                "brand": "Nature's Best",
                "dosage": "2000",
                "unit": "IU",
                "servingsPerBottle": 120,
                "category": "vitamin"
            },
            "987654321": {
                "name": "Omega-3 Fish Oil",
                "brand": "Nordic Naturals",
                "dosage": "1000",
                "unit": "mg",
                "servingsPerBottle": 60,
                "category": "supplement"
            }
        }

        if barcode in supplement_database:
            supplement = supplement_database[barcode]

            # Add to user's available compounds
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR IGNORE INTO default_compounds 
                    (name, unit, default_dosage, category, description, created_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (supplement["name"], supplement["unit"], supplement["dosage"],
                     supplement["category"], f"Scanned from {supplement['brand']}", username))
                conn.commit()

            return jsonify({
                "success": True,
                "supplement": supplement,
                "message": f"Added {supplement['name']} to your available compounds"
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": "Supplement not found in database",
                "suggestion": "You can manually add this supplement"
            }), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/gamification/achievements", methods=["GET"])
def api_get_achievements():
    """Get user achievements and badges"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        data = load_data(username)
        achievements = calculate_achievements(data, username)

        return jsonify({
            "achievements": achievements,
            "totalPoints": sum(a["points"] for a in achievements if a["unlocked"]),
            "level": calculate_user_level(achievements)
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/offline/sync", methods=["POST"])
def api_offline_sync():
    """Sync offline data when connection is restored"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json()
    offline_logs = data.get('offlineLogs', [])

    try:
        user_data = load_data(username)
        synced_count = 0

        for log_entry in offline_logs:
            protocol_name = log_entry.get('protocolName')
            date_str = log_entry.get('date')
            compounds = log_entry.get('compounds', {})

            if protocol_name in user_data["protocols"]:
                if date_str not in user_data["protocols"][protocol_name]["logs"]:
                    user_data["protocols"][protocol_name]["logs"][date_str] = {}

                for compound, data_entry in compounds.items():
                    user_data["protocols"][protocol_name]["logs"][date_str][compound] = data_entry

                synced_count += 1

        save_data(user_data, username)

        return jsonify({
            "success": True,
            "syncedEntries": synced_count,
            "message": f"Successfully synced {synced_count} offline entries"
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/multi-language/content", methods=["GET"])
def api_get_localized_content():
    """Get localized content for internationalization"""
    language = request.args.get('lang', 'en')

    translations = {
        "en": {
            "dashboard": "Dashboard",
            "protocols": "Protocols",
            "analytics": "Analytics",
            "taken": "Taken",
            "missed": "Missed",
            "notes": "Notes",
            "excellent_adherence": "Excellent adherence! Keep it up!",
            "needs_improvement": "Your adherence could be improved"
        },
        "es": {
            "dashboard": "Panel de Control",
            "protocols": "Protocolos",
            "analytics": "Análisis",
            "taken": "Tomado",
            "missed": "Perdido",
            "notes": "Notas",
            "excellent_adherence": "¡Excelente adherencia! ¡Sigue así!",
            "needs_improvement": "Tu adherencia podría mejorar"
        },
        "fr": {
            "dashboard": "Tableau de Bord",
            "protocols": "Protocoles",
            "analytics": "Analyses",
            "taken": "Pris",
            "missed": "Manqué",
            "notes": "Notes",
            "excellent_adherence": "Excellente adhérence! Continuez!",
            "needs_improvement": "Votre adhérence pourrait être améliorée"
        }
    }

    return jsonify(translations.get(language, translations["en"])), 200

def calculate_achievements(data, username):
    """Calculate user achievements and badges"""
    achievements = [
        {
            "id": "first_protocol",
            "name": "First Steps",
            "description": "Created your first protocol",
            "icon": "🎯",
            "points": 50,
            "unlocked": len(data["protocols"]) > 0
        },
        {
            "id": "week_streak",
            "name": "Week Warrior",
            "description": "Maintained 7-day streak",
            "icon": "🔥",
            "points": 100,
            "unlocked": calculate_max_streak(data) >= 7
        },
        {
            "id": "month_streak",
            "name": "Monthly Master",
            "description": "Maintained 30-day streak",
            "icon": "👑",
            "points": 500,
            "unlocked": calculate_max_streak(data) >= 30
        },
        {
            "id": "perfect_adherence",
            "name": "Perfectionist",
            "description": "100% adherence for a month",
            "icon": "⭐",
            "points": 200,
            "unlocked": check_perfect_month(data)
        }
    ]

    return achievements

def calculate_max_streak(data):
    """Calculate the maximum streak across all protocols"""
    max_streak = 0

    for protocol in data["protocols"].values():
        logs = protocol["logs"]
        if not logs:
            continue

        sorted_dates = sorted(logs.keys())
        current_streak = 0
        temp_max = 0

        for i, date_str in enumerate(sorted_dates):
            day_log = logs[date_str]
            all_taken = all(entry.get("taken", False) for entry in day_log.values())

            if all_taken:
                current_streak += 1
                temp_max = max(temp_max, current_streak)
            else:
                current_streak = 0

        max_streak = max(max_streak, temp_max)

    return max_streak

def check_perfect_month(data):
    """Check if user has had perfect adherence for any month"""
    for protocol in data["protocols"].values():
        logs = protocol["logs"]
        monthly_data = {}

        for date_str, day_log in logs.items():
            try:
                log_date = datetime.strptime(date_str, "%Y-%m-%d").date()
                month = log_date.strftime("%Y-%m")

                if month not in monthly_data:
                    monthly_data[month] = {"perfect_days": 0, "total_days": 0}

                monthly_data[month]["total_days"] += 1

                if all(entry.get("taken", False) for entry in day_log.values()):
                    monthly_data[month]["perfect_days"] += 1
            except ValueError:
                continue

        for month_data in monthly_data.values():
            if (month_data["total_days"] >= 20 and 
                month_data["perfect_days"] == month_data["total_days"]):
                return True

    return False

def calculate_user_level(achievements):
    """Calculate user level based on total points"""
    total_points = sum(a["points"] for a in achievements if a["unlocked"])

    if total_points >= 1000:
        return {"level": 5, ""title": "Supplement Master"}
    elif total_points >= 500:
        return {"level": 4, "title": "Health Enthusiast"}
    elif total_points >= 200:
        return {"level": 3, "title": "Consistent Tracker"}
    elif total_points >= 100:
        return {"level": 2, "title": "Getting Started"}
    else:
        return {"level": 1, "title": "Beginner"}

@app.route("/api/reminders", methods=["GET", "POST"])
def api_manage_reminders():
    """Enhanced API endpoint to manage user reminders"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    if request.method == "POST":
        data = request.get_json()

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO user_reminders 
                    (user_id, protocol_id, reminder_time, enabled, created_at)
                    VALUES (
                        (SELECT id FROM users WHERE username = ?),
                        ?, ?, ?, CURRENT_TIMESTAMP
                    )
                ''', (username, data.get('protocolId'), data.get('time'), data.get('enabled', True)))
                conn.commit()

            return jsonify({"success": True}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # GET request with enhanced features
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT protocol_id, reminder_time, enabled
                FROM user_reminders
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
            ''', (username,))

            reminders = []
            for row in cursor.fetchall():
                reminders.append({
                    "protocolId": row[0],
                    "time": row[1],
                    "enabled": bool(row[2])
                })

            # Add smart suggestions
            suggestions = generate_reminder_suggestions(username)

            return jsonify({
                "reminders": reminders,
                "suggestions": suggestions
            }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def generate_reminder_suggestions(username):
    """Generate intelligent reminder suggestions"""
    data = load_data(username)
    suggestions = []

    # Analyze user's pattern
    for protocol_name, protocol in data["protocols"].items():
        logs = protocol["logs"]
        if len(logs) >= 7:
            # Find best time based on historical data
            time_analysis = {}
            for date_str, day_log in logs.items():
                if all(entry.get("taken", False) for entry in day_log.values()):
                    # Mock time analysis - in real app, you'd track actual times
                    suggested_time = "08:00"  # Morning suggestion
                    if suggested_time not in time_analysis:
                        time_analysis[suggested_time] = 0
                    time_analysis[suggested_time] += 1

            if time_analysis:
                best_time = max(time_analysis, key=time_analysis.get)
                suggestions.append({
                    "protocolId": protocol_name,
                    "suggestedTime": best_time,
                    "reason": f"You have {time_analysis[best_time]}% success rate at this time",
                    "confidence": "high"
                })

    return suggestions

@app.route("/api/healthkit/sync", methods=["POST"])
def api_sync_healthkit_data():
    """API endpoint to receive and store HealthKit data from iOS app"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    try:
        supplements = data.get('supplements', [])
        sync_date = data.get('syncDate')

        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Get user ID
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            user_row = cursor.fetchone()
            if not user_row:
                return jsonify({"error": "User not found"}), 404
            user_id = user_row[0]

            # Create healthkit_data table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS healthkit_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    supplement_name TEXT NOT NULL,
                    amount REAL NOT NULL,
                    unit TEXT NOT NULL,
                    recorded_date TIMESTAMP NOT NULL,
                    synced_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    UNIQUE(user_id, supplement_name, recorded_date)
                )
            ''')

            # Insert HealthKit supplement data
            for supplement in supplements:
                try:
                    cursor.execute('''
                        INSERT OR REPLACE INTO healthkit_data 
                        (user_id, supplement_name, amount, unit, recorded_date, synced_date)
                        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ''', (
                        user_id,
                        supplement.get('name'),
                        supplement.get('amount', 1.0),
                        supplement.get('unit', 'count'),
                        supplement.get('date')
                    ))
                except Exception as e:
                    print(f"Error inserting supplement data: {e}")
                    continue

            conn.commit()

            log_system_event('healthkit_sync', 
                           f'HealthKit data synced for user {username}: {len(supplements)} supplements', 
                           'info', user_id=user_id)

        return jsonify({
            "success": True,
            "message": f"Successfully synced {len(supplements)} supplement records from HealthKit",
            "syncedAt": datetime.now().isoformat()
        }), 200

    except Exception as e:
        log_system_event('healthkit_sync_error', 
                       f'HealthKit sync failed for user {username}: {str(e)}', 
                       'error')
        return jsonify({"error": f"Failed to sync HealthKit data: {str(e)}"}), 500

@app.route("/api/wearables/sync", methods=["POST"])
def api_sync_wearable_data():
    """Sync data from various wearable devices"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json()
    device_type = data.get('deviceType')  # 'apple_watch', 'fitbit', 'garmin', etc.
    metrics = data.get('metrics', {})

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Create wearable_data table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS wearable_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    device_type TEXT NOT NULL,
                    metric_type TEXT NOT NULL,
                    value REAL NOT NULL,
                    unit TEXT NOT NULL,
                    recorded_date TIMESTAMP NOT NULL,
                    synced_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    UNIQUE(user_id, device_type, metric_type, recorded_date)
                )
            ''')

            user_id = get_user_id(username)

            for metric_type, metric_data in metrics.items():
                cursor.execute('''
                    INSERT OR REPLACE INTO wearable_data 
                    (user_id, device_type, metric_type, value, unit, recorded_date)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (user_id, device_type, metric_type, 
                     metric_data['value'], metric_data['unit'], metric_data['date']))

            conn.commit()

            return jsonify({
                "success": True,
                "message": f"Synced {len(metrics)} metrics from {device_type}"
            }), 200

    except Exception as e:
        return jsonify({"error": f"Failed to sync wearable data: {str(e)}"}), 500

@app.route("/api/biomarkers", methods=["GET", "POST"])
def api_manage_biomarkers():
    """Manage biomarker data and lab results"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    if request.method == "POST":
        data = request.get_json()

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS biomarker_data (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        biomarker_name TEXT NOT NULL,
                        value REAL NOT NULL,
                        unit TEXT NOT NULL,
                        reference_min REAL,
                        reference_max REAL,
                        test_date DATE NOT NULL,
                        lab_name TEXT DEFAULT '',
                        notes TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')

                user_id = get_user_id(username)

                for biomarker in data.get('biomarkers', []):
                    cursor.execute('''
                        INSERT INTO biomarker_data 
                        (user_id, biomarker_name, value, unit, reference_min, reference_max, 
                         test_date, lab_name, notes)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (user_id, biomarker['name'], biomarker['value'], biomarker['unit'],
                         biomarker.get('referenceMin'), biomarker.get('referenceMax'),
                         biomarker['testDate'], biomarker.get('labName', ''), 
                         biomarker.get('notes', '')))

                conn.commit()

                return jsonify({"success": True}), 201

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # GET biomarkers
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT biomarker_name, value, unit, reference_min, reference_max,
                       test_date, lab_name, notes
                FROM biomarker_data
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
                ORDER BY test_date DESC
            ''', (username,))

            biomarkers = []
            for row in cursor.fetchall():
                biomarkers.append({
                    "name": row[0],
                    "value": row[1],
                    "unit": row[2],
                    "referenceMin": row[3],
                    "referenceMax": row[4],
                    "testDate": row[5],
                    "labName": row[6],
                    "notes": row[7]
                })

            return jsonify(biomarkers), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/correlations/analyze", methods=["POST"])
def api_analyze_correlations():
    """Analyze correlations between supplements and health metrics"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        user_id = get_user_id(username)

        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Get protocol logs with health metrics
            cursor.execute('''
                SELECT pl.log_date, pl.compound, pl.taken, pl.mood, pl.energy, pl.side_effects
                FROM protocol_logs pl
                JOIN protocols p ON pl.protocol_id = p.id
                WHERE p.user_id = ?
                AND pl.log_date >= date('now', '-90 days')
                ORDER BY pl.log_date
            ''', (user_id,))

            logs = cursor.fetchall()

            # Get wearable data
            cursor.execute('''
                SELECT metric_type, value, recorded_date
                FROM wearable_data
                WHERE user_id = ? AND recorded_date >= date('now', '-90 days')
            ''', (user_id,))

            wearable_data = cursor.fetchall()

            # Analyze correlations
            correlations = analyze_supplement_correlations(logs, wearable_data)

            return jsonify({
                "correlations": correlations,
                "analysisDate": datetime.now().isoformat(),
                "dataPoints": len(logs)
            }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/export/comprehensive", methods=["GET"])
def api_comprehensive_export():
    """Export all user data in multiple formats"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    format_type = request.args.get('format', 'json')  # json, csv, pdf

    try:
        user_id = get_user_id(username)

        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Get all user data
            export_data = {
                "user": {"username": username, "exportDate": datetime.now().isoformat()},
                "protocols": [],
                "logs": [],
                "biomarkers": [],
                "wearableData": [],
                "healthKitData": [],
                "costs": []
            }

            # Protocols
            cursor.execute('SELECT name, compounds FROM protocols WHERE user_id = ?', (user_id,))
            for row in cursor.fetchall():
                export_data["protocols"].append({
                    "name": row[0],
                    "compounds": json.loads(row[1])
                })

            # Protocol logs
            cursor.execute('''
                SELECT p.name, pl.log_date, pl.compound, pl.taken, pl.note, 
                       pl.mood, pl.energy, pl.side_effects, pl.weight, pl.general_notes
                FROM protocol_logs pl
                JOIN protocols p ON pl.protocol_id = p.id
                WHERE p.user_id = ?
            ''', (user_id,))

            for row in cursor.fetchall():
                export_data["logs"].append({
                    "protocolName": row[0],
                    "date": row[1],
                    "compound": row[2],
                    "taken": bool(row[3]),
                    "note": row[4],
                    "mood": row[5],
                    "energy": row[6],
                    "sideEffects": row[7],
                    "weight": row[8],
                    "generalNotes": row[9]
                })

            # Biomarkers
            cursor.execute('''
                SELECT biomarker_name, value, unit, test_date, lab_name
                FROM biomarker_data WHERE user_id = ?
            ''', (user_id,))

            for row in cursor.fetchall():
                export_data["biomarkers"].append({
                    "name": row[0],
                    "value": row[1],
                    "unit": row[2],
                    "testDate": row[3],
                    "labName": row[4]
                })

            if format_type == 'json':
                return jsonify(export_data), 200
            elif format_type == 'csv':
                return export_as_csv(export_data)
            else:
                return jsonify({"error": "Unsupported format"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/compounds", methods=["GET"])
def api_get_compounds():
    """API endpoint to get available compounds for mobile apps"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, unit, default_dosage, category, description FROM default_compounds ORDER BY name")
            compounds = []
            for row in cursor.fetchall():
                compounds.append({
                    "name": row[0],
                    "unit": row[1],
                    "defaultDosage": row[2],
                    "category": row[3],
                    "description": row[4]
                })

            return jsonify({"compounds": compounds}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to fetch compounds: {str(e)}"}), 500

@app.route("/api/compounds", methods=["POST"])
def api_add_compound():
    """API endpoint to add new compound"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json()
    if not data or not data.get('name'):
        return jsonify({"error": "Compound name is required"}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO default_compounds (name, unit, default_dosage, category, description, created_by)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                data.get('name'),
                data.get('unit', 'mg'),
                data.get('defaultDosage', '1'),
                data.get('category', 'supplement'),
                data.get('description', ''),
                username
            ))
            conn.commit()

        return jsonify({"success": True}), 201
    except Exception as e:
        return jsonify({"error": f"Failed to add compound: {str(e)}"}), 500

@app.route("/api/protocols/<protocol_id>/edit", methods=["PUT"])
def api_edit_protocol(protocol_id):
    """API endpoint to edit protocol compounds"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json()
    compounds = data.get('compounds', [])

    try:
        user_data = load_data(username)

        # Find matching protocol
        matching_protocol = None
        for pname in user_data.get("protocols", {}):
            if pname.replace(" ", "_").lower() == protocol_id:
                matching_protocol = pname
                break

        if not matching_protocol:
            return jsonify({"error": "Protocol not found"}), 404

        # Update compounds
        user_data["protocols"][matching_protocol]["compounds"] = compounds
        save_data(user_data, username)

        return jsonify({"success": True}), 200

    except Exception as e:
        return jsonify({"error": f"Failed to edit protocol: {str(e)}"}), 500

@app.route("/api/healthkit/data", methods=["GET"])
def api_get_healthkit_data():
    """API endpoint to retrieve user's HealthKit data with enhanced features"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Get user's HealthKit data from last 30 days
            cursor.execute('''
                SELECT supplement_name, amount, unit, recorded_date, synced_date
                FROM healthkit_data
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
                AND recorded_date >= datetime('now', '-30 days')
                ORDER BY recorded_date DESC
            ''', (username,))

            healthkit_data = []
            for row in cursor.fetchall():
                healthkit_data.append({
                    "supplementName": row[0],
                    "amount": row[1],
                    "unit": row[2],
                    "recordedDate": row[3],
                    "syncedDate": row[4]
                })

            # Get summary statistics
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_entries,
                    COUNT(DISTINCT supplement_name) as unique_supplements,
                    MIN(recorded_date) as first_entry,
                    MAX(recorded_date) as last_entry
                FROM healthkit_data
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
            ''', (username,))

            stats = cursor.fetchone()

            return jsonify({
                "healthKitData": healthkit_data,
                "totalRecords": len(healthkit_data),
                "summary": {
                    "totalEntries": stats[0],
                    "uniqueSupplements": stats[1],
                    "firstEntry": stats[2],
                    "lastEntry": stats[3]
                }
            }), 200

    except Exception as e:
        return jsonify({"error": f"Failed to fetch HealthKit data: {str(e)}"}), 500

def get_user_id(username):
    """Helper function to get user ID"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return row[0] if row else None

def analyze_supplement_correlations(logs, wearable_data):
    """Analyze correlations between supplement intake and health metrics"""
    correlations = []

    # Group data by date
    daily_data = {}

    for log in logs:
        date = log[0]
        if date not in daily_data:
            daily_data[date] = {"supplements": [], "mood": None, "energy": None}

        if log[2]:  # if taken
            daily_data[date]["supplements"].append(log[1])

        if log[3]:  # mood
            daily_data[date]["mood"] = log[3]
        if log[4]:  # energy
            daily_data[date]["energy"] = log[4]

    # Add wearable data
    for metric in wearable_data:
        date = metric[2][:10]  # Extract date part
        if date in daily_data:
            daily_data[date][metric[0]] = metric[1]

    # Simple correlation analysis
    compound_effects = {}

    for date, data in daily_data.items():
        for supplement in data["supplements"]:
            if supplement not in compound_effects:
                compound_effects[supplement] = {"mood_scores": [], "energy_scores": []}

            if data["mood"]:
                mood_mapping = {"excellent": 5, "good": 4, "neutral": 3, "poor": 2, "terrible": 1}
                if data["mood"].lower() in mood_mapping:
                    compound_effects[supplement]["mood_scores"].append(mood_mapping[data["mood"].lower()])

            if data["energy"]:
                energy_mapping = {"high": 5, "good": 4, "moderate": 3, "low": 2, "exhausted": 1}
                if data["energy"].lower() in energy_mapping:
                    compound_effects[supplement]["energy_scores"].append(energy_mapping[data["energy"].lower()])

    # Calculate correlations
    for compound, effects in compound_effects.items():
        if len(effects["mood_scores"]) > 3:
            avg_mood = sum(effects["mood_scores"]) / len(effects["mood_scores"])
            correlations.append({
                "compound": compound,
                "metric": "mood",
                "correlation": round(avg_mood, 2),
                "strength": "positive" if avg_mood > 3 else "negative" if avg_mood < 3 else "neutral",
                "dataPoints": len(effects["mood_scores"])
            })

        if len(effects["energy_scores"]) > 3:
            avg_energy = sum(effects["energy_scores"]) / len(effects["energy_scores"])
            correlations.append({
                "compound": compound,
                "metric": "energy",
                "correlation": round(avg_energy, 2),
                "strength": "positive" if avg_energy > 3 else "negative" if avg_energy < 3 else "neutral",
                "dataPoints": len(effects["energy_scores"])
            })

    return correlations

def export_as_csv(data):
    """Export data as CSV format"""
    output = io.StringIO()

    # Write protocols
    output.write("PROTOCOLS\n")
    output.write("Protocol Name,Compounds\n")
    for protocol in data["protocols"]:
        compounds = "; ".join([c["name"] if isinstance(c, dict) else c for c in protocol["compounds"]])
        output.write(f"{protocol['name']},{compounds}\n")

    output.write("\nLOGS\n")
    output.write("Protocol,Date,Compound,Taken,Note,Mood,Energy,Side Effects,Weight,General Notes\n")
    for log in data["logs"]:
        output.write(f"{log['protocolName']},{log['date']},{log['compound']},{log['taken']},{log['note']},{log['mood']},{log['energy']},{log['sideEffects']},{log['weight']},{log['generalNotes']}\n")

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=supplement_data_export.csv"}
    )

# Add CORS headers for iOS app
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

# This makes the app available for gunicorn
application = app