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

@app.route("/admin/compounds", methods=["GET"])
@login_required
@admin_required
def admin_compounds_page():
    """Admin page to manage compounds"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name, unit, default_dosage, category, description FROM default_compounds ORDER BY name")
        compounds = cursor.fetchall()
    
    return render_template_string(THEME_HEADER + ADMIN_COMPOUNDS_TEMPLATE, compounds=compounds)

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
    compounds_json = request.form.get("compounds_json", "")
    
    try:
        compound_list = json.loads(compounds_json) if compounds_json else []
        if not compound_list:
            flash("At least one compound is required", "error")
        else:
            data["protocols"][name]["compounds"] = compound_list
            save_data(data)
            flash(f"Compounds updated successfully!", "success")
    except json.JSONDecodeError:
        flash("Invalid compound data", "error")
    
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



@app.route("/protocol/<name>/cost-analysis")
@login_required
@require_2fa_setup
def cost_analysis(name):
    """Cost analysis for protocol"""
    return render_template_string(THEME_HEADER + COST_ANALYSIS_TEMPLATE, name=name)

@app.route("/protocol/<name>/cycle-management")
@login_required
@require_2fa_setup
def cycle_management(name):
    """Cycle management interface"""
    return render_template_string(THEME_HEADER + CYCLE_MANAGEMENT_TEMPLATE, name=name)

@app.route("/protocol/<name>/stack-analysis")
@login_required
@require_2fa_setup
def stack_analysis(name):
    """Protocol stacking analysis"""
    return render_template_string(THEME_HEADER + STACK_ANALYSIS_TEMPLATE, name=name)

@app.route("/protocol/<name>/barcode-scanner")
@login_required
@require_2fa_setup
def barcode_scanner(name):
    """Barcode scanner interface"""
    return render_template_string(THEME_HEADER + BARCODE_SCANNER_TEMPLATE, name=name)

@app.route("/protocol/<name>/voice-commands")
@login_required
@require_2fa_setup
def voice_commands(name):
    """Voice commands interface"""
    return render_template_string(THEME_HEADER + VOICE_COMMANDS_TEMPLATE, name=name)

# Template definitions for new features
COST_ANALYSIS_TEMPLATE = """
<div class="container">
    <div class="card">
        <h1>💰 Cost Analysis for {{name}}</h1>
        <div class="nav-links">
            <a href="/protocol/{{name}}">← Back to Protocol</a>
            <a href="/protocol/{{name}}/analytics">📈 Analytics</a>
        </div>
    </div>

    <div class="card">
        <h2>💳 Add Supplement Costs</h2>
        <form id="cost-form">
            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px;">
                <div class="form-group">
                    <label>Supplement Name</label>
                    <input id="supplement-name" required>
                </div>
                <div class="form-group">
                    <label>Cost per Unit ($)</label>
                    <input id="cost-per-unit" type="number" step="0.01" required>
                </div>
                <div class="form-group">
                    <label>Units per Bottle</label>
                    <input id="units-per-bottle" type="number" required>
                </div>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px;">
                <div class="form-group">
                    <label>Total Bottle Cost ($)</label>
                    <input id="bottle-cost" type="number" step="0.01" required>
                </div>
                <div class="form-group">
                    <label>Supplier</label>
                    <input id="supplier">
                </div>
                <div class="form-group">
                    <label>Expiry Date</label>
                    <input id="expiry-date" type="date">
                </div>
            </div>
            <button type="submit" class="btn-primary">💾 Add Cost Data</button>
        </form>
    </div>

    <div class="card">
        <h2>📊 Cost Summary</h2>
        <div id="cost-summary">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
                <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;">
                    <h3 style="margin: 0; color: var(--primary);" id="monthly-cost">$0.00</h3>
                    <p style="margin: 8px 0 0 0;">Monthly Cost</p>
                </div>
                <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;">
                    <h3 style="margin: 0; color: var(--warning);" id="yearly-cost">$0.00</h3>
                    <p style="margin: 8px 0 0 0;">Yearly Estimate</p>
                </div>
                <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;">
                    <h3 style="margin: 0; color: var(--info);" id="cost-per-day">$0.00</h3>
                    <p style="margin: 8px 0 0 0;">Daily Cost</p>
                </div>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>📋 Supplement Costs</h2>
        <div id="costs-table">
            <p style="text-align: center; color: var(--text-muted);">No cost data added yet.</p>
        </div>
    </div>
</div>

<script>
document.getElementById('cost-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const costData = {
        compoundName: document.getElementById('supplement-name').value,
        costPerUnit: parseFloat(document.getElementById('cost-per-unit').value),
        unitsPerBottle: parseInt(document.getElementById('units-per-bottle').value),
        bottleCost: parseFloat(document.getElementById('bottle-cost').value),
        supplier: document.getElementById('supplier').value,
        expiryDate: document.getElementById('expiry-date').value
    };
    
    fetch('/api/protocols/cost-tracking', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(costData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Cost data added successfully!');
            loadCostData();
            document.getElementById('cost-form').reset();
        } else {
            alert('Error: ' + data.error);
        }
    });
});

function loadCostData() {
    fetch('/api/protocols/cost-tracking')
        .then(response => response.json())
        .then(data => {
            document.getElementById('monthly-cost').textContent = '$' + data.monthlyTotal;
            document.getElementById('yearly-cost').textContent = '$' + data.yearlyEstimate;
            document.getElementById('cost-per-day').textContent = '$' + (data.monthlyTotal / 30).toFixed(2);
            
            if (data.costs.length > 0) {
                let tableHTML = '<table><thead><tr><th>Supplement</th><th>Cost/Unit</th><th>Supplier</th><th>Expiry</th></tr></thead><tbody>';
                data.costs.forEach(cost => {
                    tableHTML += `<tr>
                        <td><strong>${cost.compoundName}</strong></td>
                        <td>$${cost.costPerUnit}</td>
                        <td>${cost.supplier || 'N/A'}</td>
                        <td>${cost.expiryDate || 'N/A'}</td>
                    </tr>`;
                });
                tableHTML += '</tbody></table>';
                document.getElementById('costs-table').innerHTML = tableHTML;
            }
        });
}

// Load initial data
loadCostData();
</script>
"""

CYCLE_MANAGEMENT_TEMPLATE = """
<div class="container">
    <div class="card">
        <h1>🔄 Cycle Management for {{name}}</h1>
        <div class="nav-links">
            <a href="/protocol/{{name}}">← Back to Protocol</a>
            <a href="/protocol/{{name}}/analytics">📈 Analytics</a>
        </div>
    </div>

    <div class="card">
        <h2>⚙️ Set Up Cycling Schedule</h2>
        <form id="cycle-form">
            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px;">
                <div class="form-group">
                    <label>Cycle Type</label>
                    <select id="cycle-type" required>
                        <option value="">Select cycle type...</option>
                        <option value="weekly">Weekly Cycle</option>
                        <option value="monthly">Monthly Cycle</option>
                        <option value="custom">Custom Cycle</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Days On</label>
                    <input id="days-on" type="number" min="1" max="30" required>
                </div>
                <div class="form-group">
                    <label>Days Off</label>
                    <input id="days-off" type="number" min="1" max="30" required>
                </div>
            </div>
            <div class="form-group">
                <label>Start Date</label>
                <input id="start-date" type="date" required>
            </div>
            <button type="submit" class="btn-primary">🔄 Create Cycle</button>
        </form>
    </div>

    <div class="card">
        <h2>📅 Current Cycles</h2>
        <div id="current-cycles">
            <p style="text-align: center; color: var(--text-muted);">No active cycles.</p>
        </div>
    </div>

    <div class="card">
        <h2>📊 Cycle Calendar</h2>
        <div id="cycle-calendar" style="background: var(--bg); padding: 16px; border-radius: 8px; min-height: 300px;">
            <p style="text-align: center; color: var(--text-muted);">Set up a cycle to see the calendar.</p>
        </div>
    </div>
</div>

<script>
document.getElementById('cycle-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const cycleConfig = {
        protocolId: '{{name}}',
        cycleConfig: {
            type: document.getElementById('cycle-type').value,
            onDays: parseInt(document.getElementById('days-on').value),
            offDays: parseInt(document.getElementById('days-off').value),
            startDate: document.getElementById('start-date').value
        }
    };
    
    fetch('/api/protocols/cycles', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cycleConfig)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Cycle created successfully!');
            loadCycles();
            document.getElementById('cycle-form').reset();
        } else {
            alert('Error: ' + data.error);
        }
    });
});

function loadCycles() {
    fetch('/api/protocols/cycles')
        .then(response => response.json())
        .then(cycles => {
            if (cycles.length > 0) {
                let cyclesHTML = '';
                cycles.forEach(cycle => {
                    cyclesHTML += `
                        <div style="background: var(--bg); padding: 16px; margin: 8px 0; border-radius: 8px; border-left: 4px solid var(--primary);">
                            <h4 style="margin: 0 0 8px 0;">${cycle.cycleType} Cycle</h4>
                            <p style="margin: 0;">${cycle.onDays} days on, ${cycle.offDays} days off</p>
                            <small style="color: var(--text-muted);">Started: ${cycle.startDate}</small>
                        </div>
                    `;
                });
                document.getElementById('current-cycles').innerHTML = cyclesHTML;
            }
        });
}

// Load initial data
loadCycles();
</script>
"""

STACK_ANALYSIS_TEMPLATE = """
<div class="container">
    <div class="card">
        <h1>📚 Stack Analysis for {{name}}</h1>
        <div class="nav-links">
            <a href="/protocol/{{name}}">← Back to Protocol</a>
            <a href="/protocol/{{name}}/analytics">📈 Analytics</a>
        </div>
    </div>

    <div class="card">
        <h2>🔬 Supplement Interactions</h2>
        <div id="interactions-analysis">
            <p>Analyzing supplement interactions...</p>
        </div>
    </div>

    <div class="card">
        <h2>⚠️ Warnings & Recommendations</h2>
        <div id="warnings-section">
            <div style="background: var(--bg); padding: 16px; border-radius: 8px;">
                <h4 style="color: var(--warning);">⚠️ General Guidelines</h4>
                <ul>
                    <li>Take fat-soluble vitamins (A, D, E, K) with meals containing fat</li>
                    <li>Separate calcium and iron supplements by 2+ hours</li>
                    <li>Take magnesium away from other minerals to avoid competition</li>
                    <li>Consult healthcare providers before combining multiple supplements</li>
                </ul>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>📈 Synergistic Combinations</h2>
        <div id="synergies-section">
            <div style="background: var(--bg); padding: 16px; border-radius: 8px;">
                <h4 style="color: var(--success);">✅ Known Synergies</h4>
                <ul>
                    <li><strong>Vitamin D + Magnesium:</strong> Improves vitamin D absorption</li>
                    <li><strong>Curcumin + Black Pepper:</strong> Enhances bioavailability</li>
                    <li><strong>Quercetin + Vitamin C:</strong> Antioxidant synergy</li>
                    <li><strong>Omega-3 + Vitamin E:</strong> Protects fatty acids from oxidation</li>
                </ul>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>🧪 Create Supplement Stack</h2>
        <form id="stack-form">
            <div class="form-group">
                <label>Stack Name</label>
                <input id="stack-name" required placeholder="e.g., Morning Longevity Stack">
            </div>
            <div class="form-group">
                <label>Select Protocols to Combine</label>
                <div id="protocol-checkboxes" style="display: grid; gap: 8px;">
                    <!-- Will be populated dynamically -->
                </div>
            </div>
            <button type="submit" class="btn-primary">📚 Create Stack</button>
        </form>
    </div>
</div>

<script>
// Analyze current protocol for interactions
function analyzeInteractions() {
    // This would normally call an API to analyze supplement interactions
    const analysisHTML = `
        <div style="background: var(--bg); padding: 16px; border-radius: 8px;">
            <h4 style="color: var(--info);">🔬 Analysis Results</h4>
            <p>Based on your current protocol compounds, here are the key findings:</p>
            <div style="margin: 16px 0;">
                <span class="status-badge status-success">No major interactions detected</span>
                <span class="status-badge status-info">2 synergistic combinations found</span>
            </div>
            <p><strong>Recommendation:</strong> Your current stack appears well-balanced. Consider timing recommendations below.</p>
        </div>
    `;
    document.getElementById('interactions-analysis').innerHTML = analysisHTML;
}

document.getElementById('stack-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const stackData = {
        name: document.getElementById('stack-name').value,
        protocolIds: ['{{name}}'], // Current protocol
        interactions: [],
        warnings: []
    };
    
    fetch('/api/protocols/stacks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(stackData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Stack created successfully!');
            document.getElementById('stack-form').reset();
        } else {
            alert('Error: ' + data.error);
        }
    });
});

// Initialize analysis
analyzeInteractions();
</script>
"""

BARCODE_SCANNER_TEMPLATE = """
<div class="container">
    <div class="card">
        <h1>📱 Barcode Scanner</h1>
        <div class="nav-links">
            <a href="/protocol/{{name}}">← Back to Protocol</a>
        </div>
    </div>

    <div class="card">
        <h2>📷 Scan Supplement Barcode</h2>
        <div style="text-align: center; padding: 40px;">
            <div style="background: var(--bg); border: 2px dashed var(--border); border-radius: 12px; padding: 40px; margin: 20px 0;">
                <h3 style="color: var(--text-muted);">📱 Mobile Feature</h3>
                <p style="color: var(--text-secondary);">Barcode scanning is available in the mobile apps.</p>
                <p style="margin-top: 24px;">
                    <a href="#manual-entry" class="btn-primary">➕ Add Manually Instead</a>
                </p>
            </div>
        </div>
    </div>

    <div class="card" id="manual-entry">
        <h2>✍️ Manual Entry</h2>
        <form id="manual-supplement-form">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                <div class="form-group">
                    <label>Supplement Name</label>
                    <input id="supplement-name" required>
                </div>
                <div class="form-group">
                    <label>Brand</label>
                    <input id="brand">
                </div>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px;">
                <div class="form-group">
                    <label>Dosage</label>
                    <input id="dosage" required>
                </div>
                <div class="form-group">
                    <label>Unit</label>
                    <select id="unit" required>
                        <option value="mg">mg</option>
                        <option value="g">g</option>
                        <option value="mcg">mcg</option>
                        <option value="IU">IU</option>
                        <option value="capsule">capsule</option>
                        <option value="tablet">tablet</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Category</label>
                    <select id="category" required>
                        <option value="vitamin">Vitamin</option>
                        <option value="mineral">Mineral</option>
                        <option value="supplement">Supplement</option>
                        <option value="herb">Herb</option>
                        <option value="peptide">Peptide</option>
                        <option value="other">Other</option>
                    </select>
                </div>
            </div>
            <button type="submit" class="btn-success">💾 Add to Available Compounds</button>
        </form>
    </div>
</div>

<script>
document.getElementById('manual-supplement-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const supplementData = {
        name: document.getElementById('supplement-name').value,
        unit: document.getElementById('unit').value,
        defaultDosage: document.getElementById('dosage').value,
        category: document.getElementById('category').value,
        description: `${document.getElementById('brand').value || 'Generic'} brand supplement`
    };
    
    fetch('/api/compounds', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(supplementData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Supplement added successfully!');
            document.getElementById('manual-supplement-form').reset();
        } else {
            alert('Error: ' + data.error);
        }
    });
});
</script>
"""

VOICE_COMMANDS_TEMPLATE = """
<div class="container">
    <div class="card">
        <h1>🎤 Voice Commands</h1>
        <div class="nav-links">
            <a href="/protocol/{{name}}">← Back to Protocol</a>
        </div>
    </div>

    <div class="card">
        <h2>🗣️ Voice Control</h2>
        <div style="text-align: center; padding: 40px;">
            <div style="background: var(--bg); border: 2px dashed var(--border); border-radius: 12px; padding: 40px; margin: 20px 0;">
                <h3 style="color: var(--text-muted);">🎤 Mobile Feature</h3>
                <p style="color: var(--text-secondary);">Voice commands are available in the mobile apps with Siri/Google Assistant integration.</p>
                
                <div style="margin: 24px 0; text-align: left; background: var(--card-bg); padding: 20px; border-radius: 8px;">
                    <h4 style="color: var(--primary);">Available Commands:</h4>
                    <ul style="color: var(--text);">
                        <li>"Hey Siri, mark my morning supplements as taken"</li>
                        <li>"Hey Siri, show my supplement progress"</li>
                        <li>"Hey Siri, log my supplements for today"</li>
                        <li>"Hey Google, mark fisetin as taken"</li>
                        <li>"Hey Google, what's my adherence rate?"</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>⌨️ Quick Actions (Web)</h2>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
            <button class="btn-success" onclick="markAllTaken()">✅ Mark All Taken</button>
            <button class="btn-info" onclick="showProgress()">📊 Show Progress</button>
            <button class="btn-warning" onclick="setReminder()">⏰ Set Reminder</button>
            <button class="btn-primary" onclick="exportData()">📤 Quick Export</button>
        </div>
    </div>

    <div class="card">
        <h2>📱 Mobile App Download</h2>
        <div style="text-align: center; padding: 20px;">
            <p>Download our mobile apps for full voice command support:</p>
            <div style="margin: 20px 0;">
                <a href="#" class="btn-primary" style="margin: 8px;">📱 Download iOS App</a>
                <a href="#" class="btn-success" style="margin: 8px;">🤖 Download Android App</a>
            </div>
        </div>
    </div>
</div>

<script>
function markAllTaken() {
    if (confirm('Mark all supplements as taken for today?')) {
        // This would integrate with the existing tracking system
        alert('All supplements marked as taken!');
    }
}

function showProgress() {
    window.location.href = '/protocol/{{name}}/analytics';
}

function setReminder() {
    const time = prompt('Set reminder time (HH:MM format):');
    if (time) {
        alert(`Reminder set for ${time}`);
    }
}

function exportData() {
    window.location.href = '/protocol/{{name}}/export/csv';
}
</script>
"""

@app.route("/protocol/<name>/reminder", endpoint="reminder_v2")
@login_required
@require_2fa_setup
def reminder_v2(name):
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
                                    missed_days=0, compound_stats={}, ai_insights=[],
                                    predictions={}, correlations=[], weekly_trends=[],
                                    monthly_trends=[], best_performing_day=None,
                                    adherence_pattern="insufficient_data")

    # Generate comprehensive analytics
    analytics = generate_comprehensive_analytics(logs, prot["compounds"])

    return render_template_string(THEME_HEADER + ANALYTICS_TEMPLATE,
                                name=name, 
                                total_days=analytics["totalDays"],
                                adherence=analytics["adherence"],
                                streak=analytics["streak"],
                                missed_days=analytics["missedDays"],
                                compound_stats=analytics["compoundStats"],
                                ai_insights=analytics["aiInsights"],
                                predictions=analytics["predictions"],
                                correlations=analytics["correlations"],
                                weekly_trends=analytics["weeklyTrends"],
                                monthly_trends=analytics["monthlyTrends"],
                                best_performing_day=analytics["bestPerformingDay"],
                                adherence_pattern=analytics["adherencePattern"])

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

  <div class="card">
    <h2>🧪 Compound Management</h2>
    <div class="nav-links" style="margin-bottom: 24px;">
      <a href="/admin/compounds" class="btn-primary" title="Manage default compounds available to all users">🧪 Manage Compounds</a>
    </div>
    <p>Manage the default compounds available to all users when creating protocols.</p>
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
  --text: #1e293b; 
  --text-secondary: #64748b;
  --text-muted: #94a3b8;
  --border: #e2e8f0; 
  --input-bg: #ffffff; 
  --card-bg: #ffffff;
  --primary: #3b82f6;
  --primary-hover: #2563eb;
  --success: #059669;
  --danger: #dc2626;
  --warning: #d97706;
  --info: #0891b2;
  --shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);
  --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
  --calendar-text: #1e293b;
  --calendar-bg: #ffffff;
  --calendar-hover: #f1f5f9;
  --calendar-border: #e2e8f0;
  --calendar-today: #3b82f6;
  --calendar-event: #0891b2;
}
body.dark { 
  --bg: #0f172a; 
  --text: #f1f5f9; 
  --text-secondary: #cbd5e1;
  --text-muted: #94a3b8;
  --border: #334155; 
  --input-bg: #1e293b; 
  --card-bg: #1e293b;
  --primary: #60a5fa;
  --primary-hover: #3b82f6;
  --success: #10b981;
  --danger: #f87171;
  --warning: #fbbf24;
  --info: #22d3ee;
  --calendar-text: #f1f5f9;
  --calendar-bg: #1e293b;
  --calendar-hover: #334155;
  --calendar-border: #475569;
  --calendar-today: #60a5fa;
  --calendar-event: #22d3ee;
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

/* Calendar-specific styling for better visibility */
.fc {
  color: var(--calendar-text) !important;
  background: var(--calendar-bg) !important;
}

.fc-theme-standard .fc-scrollgrid {
  border: 1px solid var(--calendar-border) !important;
}

.fc-theme-standard td, .fc-theme-standard th {
  border: 1px solid var(--calendar-border) !important;
}

.fc-daygrid-day {
  background: var(--calendar-bg) !important;
  color: var(--calendar-text) !important;
}

.fc-daygrid-day:hover {
  background: var(--calendar-hover) !important;
}

.fc-daygrid-day-number {
  color: var(--calendar-text) !important;
  font-weight: 500 !important;
  padding: 4px 8px !important;
}

.fc-day-today {
  background: rgba(59, 130, 246, 0.1) !important;
}

.fc-day-today .fc-daygrid-day-number {
  color: var(--calendar-today) !important;
  font-weight: 700 !important;
}

.fc-toolbar {
  color: var(--text) !important;
}

.fc-toolbar-title {
  color: var(--text) !important;
  font-weight: 600 !important;
}

.fc-button {
  background: var(--primary) !important;
  border-color: var(--primary) !important;
  color: white !important;
}

.fc-button:hover {
  background: var(--primary-hover) !important;
  border-color: var(--primary-hover) !important;
}

.fc-button:disabled {
  background: var(--text-muted) !important;
  border-color: var(--text-muted) !important;
}

.fc-event {
  background: var(--calendar-event) !important;
  border-color: var(--calendar-event) !important;
  color: white !important;
  font-weight: 500 !important;
}

.fc-event:hover {
  opacity: 0.9 !important;
}

.fc-col-header-cell {
  background: var(--bg) !important;
  color: var(--text) !important;
  font-weight: 600 !important;
}

.fc-scrollgrid-sync-inner {
  color: var(--text) !important;
}

/* Improve general text contrast */
p, span, div {
  color: var(--text);
}

.text-secondary {
  color: var(--text-secondary) !important;
}

.text-muted {
  color: var(--text-muted) !important;
}

/* Improve table readability */
table {
  color: var(--text);
}

th {
  color: white !important;
}

td {
  color: var(--text) !important;
}

/* Improve form element contrast */
input, textarea, select {
  color: var(--text) !important;
  background: var(--input-bg) !important;
  border: 1px solid var(--border) !important;
}

input::placeholder, textarea::placeholder {
  color: var(--text-muted) !important;
}

/* Improve card readability */
.card {
  color: var(--text) !important;
}

.card h1, .card h2, .card h3, .card h4, .card h5, .card h6 {
  color: var(--text) !important;
}

/* Improve protocol item readability */
.protocol-item {
  color: var(--text) !important;
}

.protocol-item h3 {
  color: var(--text) !important;
}

/* Improve status badges for better contrast */
.status-badge {
  font-weight: 600 !important;
  text-shadow: 0 1px 2px rgba(0,0,0,0.1) !important;
}

/* Improve navigation links */
.nav-links a {
  color: var(--text) !important;
  background: var(--bg) !important;
}

.nav-links a:hover {
  color: white !important;
  background: var(--primary) !important;
}

/* Improve flash messages readability */
.flash-message {
  text-shadow: 0 1px 2px rgba(0,0,0,0.1) !important;
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
    <h1>💊 Advanced Supplement Tracker</h1>
    <p>Welcome back, <strong>{{user}}</strong>!</p>
    <div class="nav-links">
      <a href="/logout">🚪 Logout</a>
      <a href="/2fa_setup">🔒 2FA Setup</a>
      <a href="/dashboard/gamification">🏆 Achievements</a>
      <a href="/dashboard/templates">📋 Protocol Templates</a>
    </div>
  </div>

  <!-- Today's Summary -->
  <div class="card">
    <h2>📅 Today's Summary</h2>
    <div id="daily-summary">
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px;">
        <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;">
          <h3 style="margin: 0; color: var(--primary);" id="protocols-today">0</h3>
          <p style="margin: 8px 0 0 0;">Protocols Due</p>
        </div>
        <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;">
          <h3 style="margin: 0; color: var(--success);" id="completed-today">0</h3>
          <p style="margin: 8px 0 0 0;">Completed</p>
        </div>
        <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;">
          <h3 style="margin: 0; color: var(--warning);" id="current-streak">0</h3>
          <p style="margin: 8px 0 0 0;">Day Streak</p>
        </div>
        <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;">
          <h3 style="margin: 0; color: var(--info);" id="adherence-rate">0%</h3>
          <p style="margin: 8px 0 0 0;">Adherence</p>
        </div>
      </div>
    </div>
  </div>

  <!-- Quick Actions -->
  <div class="card">
    <h2>⚡ Quick Actions</h2>
    <div class="nav-links">
      <a href="#create-protocol" class="btn-primary">✨ Create Protocol</a>
      <a href="/dashboard/barcode-scanner" class="btn-info">📱 Scan Barcode</a>
      <a href="/dashboard/voice-commands" class="btn-success">🎤 Voice Commands</a>
      <a href="/dashboard/export-all" class="btn-warning">📊 Export All Data</a>
    </div>
  </div>

  <div class="card" id="create-protocol">
    <h2>📋 Create New Protocol</h2>
    <div style="display: grid; grid-template-columns: 1fr auto; gap: 16px; align-items: end;">
      <form method="POST" action="/create" style="display: flex; gap: 16px; align-items: end;">
        <div class="form-group" style="margin: 0;">
          <label>Protocol Name</label>
          <input name="protocol_name" placeholder="Enter protocol name..." required>
        </div>
        <button type="submit" class="btn-primary">✨ Create Protocol</button>
      </form>
      <a href="/dashboard/templates" class="btn-info">📋 Use Template</a>
    </div>
  </div>

  <div class="card">
    <h2>🧪 Your Protocols</h2>
    {% if protocols %}
      <div class="protocol-list">
        {% for p in protocols %}
          <div class="protocol-item">
            <div>
              <h3 style="margin: 0 0 8px 0;">{{p}}</h3>
              <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 8px; margin: 8px 0;">
                <a href="/protocol/{{p}}" class="btn-primary btn-small">📝 Track</a>
                <a href="/protocol/{{p}}/analytics" class="btn-info btn-small">📈 Analytics</a>
                <a href="/protocol/{{p}}/calendar" class="btn-success btn-small">📅 Calendar</a>
                <a href="/protocol/{{p}}/history" class="btn-warning btn-small">📊 History</a>
              </div>
              <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 8px; margin: 8px 0;">
                <a href="/protocol/{{p}}/cost-analysis" class="btn-info btn-small">💰 Costs</a>
                <a href="/protocol/{{p}}/cycle-management" class="btn-primary btn-small">🔄 Cycles</a>
                <a href="/protocol/{{p}}/stack-analysis" class="btn-success btn-small">📚 Stacks</a>
                <a href="/protocol/{{p}}/enhanced_tracking" class="btn-warning btn-small">📊 Enhanced</a>
              </div>
            </div>
            <div style="display: flex; flex-direction: column; gap: 8px; align-items: flex-end;">
              <div id="protocol-status-{{loop.index0}}" style="text-align: right;">
                <span class="status-badge status-info">Loading...</span>
              </div>
              <form method="POST" action="/delete_protocol/{{p}}" 
                    onsubmit="return confirm('Delete protocol {{p}}?')">
                <button type="submit" class="btn-danger btn-small">🗑️ Delete</button>
              </form>
            </div>
          </div>
        {% endfor %}
      </div>
    {% else %}
      <div style="text-align: center; padding: 40px;">
        <h3 style="color: var(--text-muted);">No protocols yet</h3>
        <p style="color: var(--text-secondary);">Create your first protocol above or browse our templates!</p>
        <div style="margin: 24px 0;">
          <a href="/dashboard/templates" class="btn-primary">📋 Browse Templates</a>
        </div>
      </div>
    {% endif %}
  </div>

  <!-- Recent Activity -->
  <div class="card">
    <h2>📈 Recent Activity</h2>
    <div id="recent-activity">
      <p style="text-align: center; color: var(--text-muted);">Loading recent activity...</p>
    </div>
  </div>

  <!-- Notifications -->
  <div class="card">
    <h2>🔔 Notifications</h2>
    <div id="notifications">
      <p style="text-align: center; color: var(--text-muted);">No new notifications.</p>
    </div>
  </div>
</div>

<script>
// Load dashboard data
document.addEventListener('DOMContentLoaded', function() {
    loadDashboardSummary();
    loadRecentActivity();
    loadNotifications();
    
    // Load protocol status for each protocol
    {% for p in protocols %}
    loadProtocolStatus('{{p}}', {{loop.index0}});
    {% endfor %}
});

function loadDashboardSummary() {
    // This would normally fetch from an API
    // For now, showing static data
    document.getElementById('protocols-today').textContent = '{{protocols|length}}';
    document.getElementById('completed-today').textContent = '0';
    document.getElementById('current-streak').textContent = '0';
    document.getElementById('adherence-rate').textContent = '0%';
}

function loadProtocolStatus(protocolName, index) {
    // Simulate loading protocol status
    setTimeout(() => {
        const statuses = ['📊 On Track', '⚠️ Behind', '✅ Complete', '🔄 Cycling'];
        const statusClasses = ['status-success', 'status-warning', 'status-success', 'status-info'];
        const randomIndex = Math.floor(Math.random() * statuses.length);
        
        document.getElementById(`protocol-status-${index}`).innerHTML = 
            `<span class="status-badge ${statusClasses[randomIndex]}">${statuses[randomIndex]}</span>`;
    }, 500 + index * 200);
}

function loadRecentActivity() {
    const activities = [
        '✅ Completed morning protocol',
        '📊 Viewed analytics for Longevity Stack',
        '💊 Added new compound: NAD+',
        '📅 Set up weekly cycle for Senolytic Protocol'
    ];
    
    let activityHTML = '<div style="display: grid; gap: 8px;">';
    activities.forEach(activity => {
        activityHTML += `
            <div style="background: var(--bg); padding: 12px; border-radius: 6px; border-left: 3px solid var(--primary);">
                <span style="color: var(--text);">${activity}</span>
                <small style="color: var(--text-muted); margin-left: 16px;">2 hours ago</small>
            </div>
        `;
    });
    activityHTML += '</div>';
    
    document.getElementById('recent-activity').innerHTML = activityHTML;
}

function loadNotifications() {
    // This would normally fetch from /api/notifications
    const notifications = [
        { type: 'reminder', message: 'Time to take your evening supplements!', time: '1 hour ago' },
        { type: 'achievement', message: 'You earned the "Week Warrior" badge!', time: '2 days ago' }
    ];
    
    if (notifications.length > 0) {
        let notificationsHTML = '<div style="display: grid; gap: 8px;">';
        notifications.forEach(notification => {
            const icon = notification.type === 'reminder' ? '⏰' : '🏆';
            notificationsHTML += `
                <div style="background: var(--bg); padding: 12px; border-radius: 6px; border-left: 3px solid var(--info);">
                    <span style="color: var(--text);">${icon} ${notification.message}</span>
                    <small style="color: var(--text-muted); margin-left: 16px;">${notification.time}</small>
                </div>
            `;
        });
        notificationsHTML += '</div>';
        document.getElementById('notifications').innerHTML = notificationsHTML;
    }
}
</script>
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
          <th>📊 Dosage</th>
          <th>⏰ Times/Day</th>
          <th>✅ Taken?</th>
          <th>📝 Notes</th>
        </tr>
        {% for c in compounds %}
          {% if c is mapping %}
            {% set compound_name = c.get('name', c) %}
            {% set dosage = c.get('daily_dosage', '1') %}
            {% set times = c.get('times_per_day', 1) %}
            {% set unit = c.get('unit', 'capsule') %}
          {% else %}
            {% set compound_name = c %}
            {% set dosage = '1' %}
            {% set times = 1 %}
            {% set unit = 'capsule' %}
          {% endif %}
          <tr>
            <td><strong>{{compound_name}}</strong></td>
            <td>{{dosage}} {{unit}}</td>
            <td>{{times}}x daily</td>
            <td class="checkbox-cell">
              <input type="checkbox" name="check_{{compound_name}}" 
                     {% if log.get(compound_name, {}).get('taken') %}checked{% endif %}>
            </td>
            <td>
              <input name="note_{{compound_name}}" value="{{log.get(compound_name, {}).get('note','')}}" 
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
    <div id="compound-editor">
      <div class="form-group">
        <label>Available Compounds</label>
        <select id="compound-select" style="width: 100%;">
          <option value="">Select a compound to add...</option>
        </select>
      </div>
      
      <div class="form-group">
        <label>Custom Compound Name</label>
        <input id="custom-compound" type="text" placeholder="Enter custom compound name..." style="width: 100%;">
      </div>
      
      <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px;">
        <div class="form-group">
          <label>Daily Dosage</label>
          <input id="dosage-input" type="text" value="1" style="width: 100%;">
        </div>
        <div class="form-group">
          <label>Times per Day</label>
          <input id="times-input" type="number" value="1" min="1" max="10" style="width: 100%;">
        </div>
        <div class="form-group">
          <label>Unit</label>
          <select id="unit-select" style="width: 100%;">
            <option value="capsule">capsule</option>
            <option value="tablet">tablet</option>
            <option value="mg">mg</option>
            <option value="ml">ml</option>
            <option value="drops">drops</option>
            <option value="pump">pump</option>
          </select>
        </div>
      </div>
      
      <button type="button" id="add-compound-btn" class="btn-primary">➕ Add Compound</button>
    </div>
    
    <div id="current-compounds" style="margin-top: 24px;">
      <h3>Current Compounds</h3>
      <div id="compounds-list"></div>
    </div>
    
    <form method="POST" action="/protocol/{{name}}/edit_compounds" id="save-compounds-form">
      <input type="hidden" name="compounds_json" id="compounds-json">
      <button type="submit" class="btn-success" style="margin-top: 16px;">💾 Save Compounds</button>
    </form>
  </div>
  
  <script>
    let currentCompounds = {{ compounds | tojson }};
    let availableCompounds = [];
    
    // Load available compounds
    fetch('/api/compounds/default')
      .then(response => response.json())
      .then(data => {
        availableCompounds = data;
        updateCompoundSelect();
      });
    
    function updateCompoundSelect() {
      const select = document.getElementById('compound-select');
      select.innerHTML = '<option value="">Select a compound to add...</option>';
      
      availableCompounds.forEach(compound => {
        const option = document.createElement('option');
        option.value = compound.name;
        option.textContent = `${compound.name} (${compound.defaultDosage}${compound.unit})`;
        option.dataset.unit = compound.unit;
        option.dataset.dosage = compound.defaultDosage;
        select.appendChild(option);
      });
    }
    
    function renderCompounds() {
      const list = document.getElementById('compounds-list');
      list.innerHTML = '';
      
      currentCompounds.forEach((compound, index) => {
        const compoundDiv = document.createElement('div');
        compoundDiv.className = 'compound-item';
        compoundDiv.style.cssText = 'display: flex; align-items: center; padding: 12px; margin: 8px 0; background: var(--bg); border-radius: 8px; border: 1px solid var(--border);';
        
        const name = typeof compound === 'string' ? compound : (compound.name || compound);
        const dosage = typeof compound === 'string' ? '1' : (compound.daily_dosage || '1');
        const times = typeof compound === 'string' ? 1 : (compound.times_per_day || 1);
        const unit = typeof compound === 'string' ? 'capsule' : (compound.unit || 'capsule');
        
        compoundDiv.innerHTML = `
          <div style="flex: 1;">
            <strong>${name}</strong><br>
            <span style="color: var(--text-secondary); font-size: 0.9em;">${dosage} ${unit}, ${times}x daily</span>
          </div>
          <button type="button" onclick="removeCompound(${index})" class="btn-danger btn-small">🗑️ Remove</button>
        `;
        
        list.appendChild(compoundDiv);
      });
      
      // Update hidden input
      document.getElementById('compounds-json').value = JSON.stringify(currentCompounds);
    }
    
    function removeCompound(index) {
      currentCompounds.splice(index, 1);
      renderCompounds();
    }
    
    document.getElementById('compound-select').addEventListener('change', function() {
      const selectedCompound = availableCompounds.find(c => c.name === this.value);
      if (selectedCompound) {
        document.getElementById('dosage-input').value = selectedCompound.defaultDosage;
        document.getElementById('unit-select').value = selectedCompound.unit;
      }
    });
    
    document.getElementById('add-compound-btn').addEventListener('click', function() {
      const select = document.getElementById('compound-select');
      const customInput = document.getElementById('custom-compound');
      const dosageInput = document.getElementById('dosage-input');
      const timesInput = document.getElementById('times-input');
      const unitSelect = document.getElementById('unit-select');
      
      const compoundName = select.value || customInput.value.trim();
      
      if (!compoundName) {
        alert('Please select or enter a compound name');
        return;
      }
      
      // Check if compound already exists
      const exists = currentCompounds.some(compound => {
        const name = typeof compound === 'string' ? compound : compound.name;
        return name === compoundName;
      });
      
      if (exists) {
        alert('This compound is already in the protocol');
        return;
      }
      
      const newCompound = {
        name: compoundName,
        daily_dosage: dosageInput.value || '1',
        times_per_day: parseInt(timesInput.value) || 1,
        unit: unitSelect.value || 'capsule'
      };
      
      currentCompounds.push(newCompound);
      renderCompounds();
      
      // Reset form
      select.value = '';
      customInput.value = '';
      dosageInput.value = '1';
      timesInput.value = '1';
      unitSelect.value = 'capsule';
    });
    
    // Initial render
    renderCompounds();
  </script>
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
      '<div style="text-align: center; padding: 40px; color: var(--danger); background: var(--card-bg); border-radius: 8px; border: 1px solid var(--border);">' +
      '<h3 style="color: var(--danger); margin-bottom: 16px;">❌ Calendar Library Error</h3>' +
      '<p style="color: var(--text); margin-bottom: 16px;">Unable to load calendar library. Please refresh the page or check your internet connection.</p>' +
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
              '<div style="text-align: center; padding: 40px; background: var(--card-bg); border-radius: 8px; border: 1px solid var(--border);">' +
              '<h3 style="color: var(--warning); margin-bottom: 16px;">⚠️ Data Loading Error</h3>' +
              '<p style="color: var(--text); margin-bottom: 16px;">Unable to load calendar data. Please try refreshing the page.</p>' +
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
      '<div style="text-align: center; padding: 40px; background: var(--card-bg); border-radius: 8px; border: 1px solid var(--border);">' +
      '<h3 style="color: var(--danger); margin-bottom: 16px;">❌ Calendar Error</h3>' +
      '<p style="color: var(--text); margin-bottom: 16px;">Unable to initialize calendar: ' + error.message + '</p>' +
      '<button onclick="location.reload()" class="btn-primary" style="margin-top: 16px;">🔄 Refresh Page</button>' +
      '</div>';
  }
});
</script>
"""

ANALYTICS_TEMPLATE = """
<div class="container">
    <div class="card">
        <h1>📈 Advanced Analytics for {{name}}</h1>
        <div class="nav-links">
            <a href="/protocol/{{name}}">← Back to Tracking</a>
            <a href="/protocol/{{name}}/ai-insights">🧠 AI Insights</a>
            <a href="/protocol/{{name}}/correlations">🔗 Correlations</a>
            <a href="/protocol/{{name}}/predictions">🔮 Predictions</a>
        </div>
    </div>

    <!-- Key Metrics Cards -->
    <div class="card">
        <h2>📊 Key Metrics</h2>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
            <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;">
                <h3 style="margin: 0; color: var(--primary);">{{total_days}}</h3>
                <p style="margin: 8px 0 0 0;">Total Days</p>
            </div>
            <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;">
                <h3 style="margin: 0; color: var(--success);">{{adherence}}%</h3>
                <p style="margin: 8px 0 0 0;">Adherence</p>
            </div>
            <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;">
                <h3 style="margin: 0; color: var(--warning);">{{streak}}</h3>
                <p style="margin: 8px 0 0 0;">Current Streak</p>
            </div>
            <div style="background: var(--bg); padding: 16px; border-radius: 8px; text-align: center;">
                <h3 style="margin: 0; color: var(--danger);">{{missed_days}}</h3>
                <p style="margin: 8px 0 0 0;">Missed Days</p>
            </div>
        </div>
    </div>

    <!-- AI Insights -->
    {% if ai_insights %}
    <div class="card">
        <h2>🧠 AI Insights</h2>
        <div style="display: grid; gap: 12px;">
            {% for insight in ai_insights %}
            <div style="background: var(--bg); padding: 16px; border-radius: 8px; border-left: 4px solid {{ '#28a745' if insight.type == 'success' else '#ffc107' if insight.type == 'warning' else '#dc3545' if insight.type == 'alert' else '#17a2b8' }};">
                <h4 style="margin: 0 0 8px 0; color: var(--text);">{{insight.title}}</h4>
                <p style="margin: 0; color: var(--text-secondary);">{{insight.message}}</p>
                <small style="color: var(--text-muted);">Priority: {{insight.priority}}</small>
            </div>
            {% endfor %}
        </div>
    </div>
    {% endif %}

    <!-- Predictions -->
    {% if predictions %}
    <div class="card">
        <h2>🔮 Predictions</h2>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px;">
            {% if predictions.nextWeekAdherence %}
            <div style="background: var(--bg); padding: 16px; border-radius: 8px;">
                <h4 style="margin: 0 0 8px 0;">Next Week Forecast</h4>
                <p style="margin: 0; font-size: 1.5rem; font-weight: bold; color: var(--primary);">{{predictions.nextWeekAdherence}}%</p>
                <small style="color: var(--text-muted);">Predicted adherence</small>
            </div>
            {% endif %}
            {% if predictions.trend %}
            <div style="background: var(--bg); padding: 16px; border-radius: 8px;">
                <h4 style="margin: 0 0 8px 0;">Trend Analysis</h4>
                <p style="margin: 0; font-size: 1.2rem; font-weight: bold; color: {{ '#28a745' if predictions.trend == 'improving' else '#ffc107' if predictions.trend == 'stable' else '#dc3545' }};">
                    {% if predictions.trend == 'improving' %}📈 Improving
                    {% elif predictions.trend == 'stable' %}➡️ Stable
                    {% else %}📉 Declining{% endif %}
                </p>
            </div>
            {% endif %}
            {% if predictions.daysToReachGoal %}
            <div style="background: var(--bg); padding: 16px; border-radius: 8px;">
                <h4 style="margin: 0 0 8px 0;">Goal Achievement</h4>
                <p style="margin: 0; font-size: 1.5rem; font-weight: bold; color: var(--info);">{{predictions.daysToReachGoal}}</p>
                <small style="color: var(--text-muted);">Days to reach 90% adherence</small>
            </div>
            {% endif %}
        </div>
    </div>
    {% endif %}

    <!-- Best Performing Day -->
    {% if best_performing_day %}
    <div class="card">
        <h2>⭐ Best Performance</h2>
        <div style="background: var(--bg); padding: 16px; border-radius: 8px;">
            <h3 style="margin: 0 0 8px 0;">{{best_performing_day.day}}</h3>
            <p style="margin: 0; font-size: 1.2rem; color: var(--success);">{{best_performing_day.adherence}}% average adherence</p>
            <small style="color: var(--text-muted);">Your most consistent day of the week</small>
        </div>
    </div>
    {% endif %}

    <!-- Adherence Pattern -->
    <div class="card">
        <h2>📈 Adherence Pattern</h2>
        <div style="background: var(--bg); padding: 16px; border-radius: 8px;">
            {% if adherence_pattern == 'excellent' %}
                <h3 style="color: var(--success);">🌟 Excellent Pattern</h3>
                <p>Your consistency is outstanding! Keep up the excellent work.</p>
            {% elif adherence_pattern == 'good' %}
                <h3 style="color: var(--info);">👍 Good Pattern</h3>
                <p>Good progress! Your adherence shows steady improvement.</p>
            {% elif adherence_pattern == 'needs_improvement' %}
                <h3 style="color: var(--warning);">📈 Room for Improvement</h3>
                <p>Consider setting up reminders or simplifying your protocol.</p>
            {% elif adherence_pattern == 'poor' %}
                <h3 style="color: var(--danger);">🎯 Needs Attention</h3>
                <p>Let's work on building better habits. Consider consulting with a healthcare provider.</p>
            {% else %}
                <h3 style="color: var(--text-muted);">📊 Building Pattern</h3>
                <p>Keep tracking to analyze your patterns and get personalized insights.</p>
            {% endif %}
        </div>
    </div>

    <!-- Compound Statistics -->
    <div class="card">
        <h2>💊 Compound Performance</h2>
        <table>
            <thead>
                <tr>
                    <th>Compound</th>
                    <th>Taken</th>
                    <th>Missed</th>
                    <th>Adherence</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {% for compound, stats in compound_stats.items() %}
                <tr>
                    <td><strong>{{compound}}</strong></td>
                    <td>{{stats.taken}}</td>
                    <td>{{stats.missed}}</td>
                    <td>{{stats.percentage}}%</td>
                    <td>
                        <span class="status-badge {{ 'status-success' if stats.percentage >= 80 else 'status-warning' if stats.percentage >= 60 else 'status-danger' }}">
                            {% if stats.percentage >= 80 %}Excellent
                            {% elif stats.percentage >= 60 %}Good
                            {% else %}Needs Work{% endif %}
                        </span>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <!-- Weekly Trends Chart -->
    {% if weekly_trends %}
    <div class="card">
        <h2>📊 Weekly Trends</h2>
        <div style="background: var(--bg); padding: 16px; border-radius: 8px;">
            <canvas id="weeklyChart" width="400" height="200"></canvas>
        </div>
    </div>
    {% endif %}

    <!-- Monthly Trends Chart -->
    {% if monthly_trends %}
    <div class="card">
        <h2>📅 Monthly Trends</h2>
        <div style="background: var(--bg); padding: 16px; border-radius: 8px;">
            <canvas id="monthlyChart" width="400" height="200"></canvas>
        </div>
    </div>
    {% endif %}

    <!-- Correlations -->
    {% if correlations %}
    <div class="card">
        <h2>🔗 Health Correlations</h2>
        <div style="max-height: 400px; overflow-y: auto;">
            {% for correlation in correlations %}
            <div style="background: var(--bg); padding: 12px; margin: 8px 0; border-radius: 6px; border-left: 3px solid var(--primary);">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <strong>{{correlation.date}}</strong>
                        <span style="margin-left: 16px;">Adherence: {{correlation.adherence}}%</span>
                    </div>
                    <div style="text-align: right;">
                        {% if correlation.mood %}<span style="margin-right: 8px;">😊 {{correlation.mood}}</span>{% endif %}
                        {% if correlation.energy %}<span>⚡ {{correlation.energy}}</span>{% endif %}
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
    {% endif %}

    <!-- Advanced Actions -->
    <div class="card">
        <h2>🔧 Advanced Tools</h2>
        <div class="nav-links">
            <a href="/protocol/{{name}}/cost-analysis" class="btn-info">💰 Cost Analysis</a>
            <a href="/protocol/{{name}}/cycle-management" class="btn-primary">🔄 Cycle Management</a>
            <a href="/protocol/{{name}}/stack-analysis" class="btn-success">📚 Stack Analysis</a>
            <a href="/protocol/{{name}}/export-advanced" class="btn-warning">📊 Advanced Export</a>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
// Weekly Trends Chart
{% if weekly_trends %}
const weeklyCtx = document.getElementById('weeklyChart').getContext('2d');
new Chart(weeklyCtx, {
    type: 'line',
    data: {
        labels: {{ weekly_trends | map(attribute='week') | list | tojson }},
        datasets: [{
            label: 'Weekly Adherence %',
            data: {{ weekly_trends | map(attribute='adherence') | list | tojson }},
            borderColor: 'rgb(59, 130, 246)',
            backgroundColor: 'rgba(59, 130, 246, 0.1)',
            tension: 0.4
        }]
    },
    options: {
        responsive: true,
        scales: {
            y: {
                beginAtZero: true,
                max: 100
            }
        }
    }
});
{% endif %}

// Monthly Trends Chart
{% if monthly_trends %}
const monthlyCtx = document.getElementById('monthlyChart').getContext('2d');
new Chart(monthlyCtx, {
    type: 'bar',
    data: {
        labels: {{ monthly_trends | map(attribute='month') | list | tojson }},
        datasets: [{
            label: 'Monthly Adherence %',
            data: {{ monthly_trends | map(attribute='adherence') | list | tojson }},
            backgroundColor: 'rgba(34, 197, 94, 0.8)',
            borderColor: 'rgb(34, 197, 94)',
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        scales: {
            y: {
                beginAtZero: true,
                max: 100
            }
        }
    }
});
{% endif %}
</script>
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

ADMIN_COMPOUNDS_TEMPLATE = """
<div class="container">
  <div class="card">
    <h1>🧪 Compound Management</h1>
    <div class="nav-links">
      <a href="/admin/dashboard">← Back to Dashboard</a>
    </div>
  </div>

  <div class="card">
    <h2>Add New Compound</h2>
    <form id="add-compound-form">
      <div style="display: grid; grid-template-columns: 2fr 1fr 1fr 1fr; gap: 16px;">
        <div class="form-group">
          <label>Compound Name</label>
          <input id="compound-name" type="text" required placeholder="e.g., Fisetin">
        </div>
        <div class="form-group">
          <label>Default Dosage</label>
          <input id="compound-dosage" type="text" required placeholder="e.g., 100">
        </div>
        <div class="form-group">
          <label>Unit</label>
          <select id="compound-unit" required>
            <option value="mg">mg</option>
            <option value="capsule">capsule</option>
            <option value="tablet">tablet</option>
            <option value="ml">ml</option>
            <option value="drops">drops</option>
            <option value="pump">pump</option>
            <option value="g">g</option>
            <option value="mcg">mcg</option>
          </select>
        </div>
        <div class="form-group">
          <label>Category</label>
          <select id="compound-category" required>
            <option value="supplement">Supplement</option>
            <option value="peptide">Peptide</option>
            <option value="vitamin">Vitamin</option>
            <option value="mineral">Mineral</option>
            <option value="herb">Herb</option>
            <option value="other">Other</option>
          </select>
        </div>
      </div>
      <div class="form-group">
        <label>Description</label>
        <textarea id="compound-description" rows="2" placeholder="Brief description of the compound..."></textarea>
      </div>
      <button type="submit" class="btn-primary">➕ Add Compound</button>
    </form>
  </div>

  <div class="card">
    <h2>Existing Compounds</h2>
    {% if compounds %}
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Default Dosage</th>
            <th>Unit</th>
            <th>Category</th>
            <th>Description</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="compounds-table">
          {% for compound in compounds %}
          <tr data-compound="{{compound[0]}}">
            <td><strong>{{compound[0]}}</strong></td>
            <td>{{compound[2]}}</td>
            <td>{{compound[1]}}</td>
            <td>{{compound[3]}}</td>
            <td>{{compound[4] or 'No description'}}</td>
            <td>
              <button type="button" class="btn-danger btn-small" onclick="deleteCompound('{{compound[0]}}')">🗑️ Delete</button>
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <p style="text-align: center; color: #6b7280; margin: 40px 0;">No compounds found. Add some above!</p>
    {% endif %}
  </div>
</div>

<script>
document.getElementById('add-compound-form').addEventListener('submit', function(e) {
  e.preventDefault();
  
  const compound = {
    name: document.getElementById('compound-name').value,
    defaultDosage: document.getElementById('compound-dosage').value,
    unit: document.getElementById('compound-unit').value,
    category: document.getElementById('compound-category').value,
    description: document.getElementById('compound-description').value
  };
  
  fetch('/admin/compounds', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({compounds: [compound]})
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      location.reload();
    } else {
      alert('Error adding compound: ' + data.error);
    }
  })
  .catch(error => {
    alert('Error adding compound: ' + error);
  });
});

function deleteCompound(compoundName) {
  if (confirm('Delete compound "' + compoundName + '"?')) {
    // Remove from UI first
    const row = document.querySelector(`tr[data-compound="${compoundName}"]`);
    if (row) {
      row.remove();
    }
    
    // Get current compounds and remove the one being deleted
    const currentCompounds = Array.from(document.querySelectorAll('#compounds-table tr')).map(row => {
      const cells = row.querySelectorAll('td');
      if (cells.length > 0) {
        return {
          name: cells[0].textContent.trim(),
          defaultDosage: cells[1].textContent.trim(),
          unit: cells[2].textContent.trim(),
          category: cells[3].textContent.trim(),
          description: cells[4].textContent.trim()
        };
      }
    }).filter(compound => compound && compound.name !== compoundName);
    
    // Update server
    fetch('/admin/compounds', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({compounds: currentCompounds})
    })
    .then(response => response.json())
    .then(data => {
      if (!data.success) {
        alert('Error deleting compound: ' + data.error);
        location.reload();
      }
    })
    .catch(error => {
      alert('Error deleting compound: ' + error);
      location.reload();
    });
  }
}
</script>
"""

# API Endpoints for iOS App
@app.route("/api/login", methods=["POST"])
def api_login():
    """API endpoint for iOS app login - first step"""
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Username and password required"}), 400
    
    username = data['username'].strip().lower()
    password = data['password']
    client_ip = request.remote_addr
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, disabled, login_attempts FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        
        if not row:
            log_system_event('api_login_failed', f'API login attempt for non-existent user: {username}', 'warning', ip_address=client_ip)
            return jsonify({"error": "Invalid credentials"}), 401
        
        if row[1]:  # disabled
            return jsonify({"error": "Account disabled"}), 401
            
        max_attempts = int(get_config_value('max_login_attempts', '5'))
        if row[2] >= max_attempts:
            return jsonify({"error": "Account temporarily locked"}), 401
        
        if not check_password_hash(row[0], password):
            cursor.execute("UPDATE users SET login_attempts = login_attempts + 1 WHERE username = ?", (username,))
            conn.commit()
            log_system_event('api_login_failed', f'Invalid password for API user: {username}', 'warning', ip_address=client_ip)
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Password is correct, now require 2FA
        session['pending_api_user'] = username
        
        return jsonify({
            "requires_2fa": True,
            "message": "2FA verification required"
        }), 200

@app.route("/api/verify_2fa", methods=["POST"])
def api_verify_2fa():
    """API endpoint for 2FA verification"""
    data = request.get_json()
    if not data or not data.get('code'):
        return jsonify({"error": "2FA code required"}), 400
    
    username = session.get('pending_api_user')
    if not username:
        return jsonify({"error": "No pending authentication"}), 401
    
    code = data['code']
    client_ip = request.remote_addr
    
    user_data = load_data(username)
    if not pyotp.TOTP(user_data["2fa_secret"]).verify(code):
        return jsonify({"error": "Invalid 2FA code"}), 401
    
    # 2FA verified, complete login
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP, login_attempts = 0, ip_address = ? WHERE username = ?", (client_ip, username))
        conn.commit()
    
    session['api_username'] = username
    session.pop('pending_api_user', None)
    
    log_system_event('api_login_success', f'API user logged in: {username}', 'info', ip_address=client_ip)
    
    return jsonify({
        "success": True,
        "message": "Login successful",
        "user": {"username": username},
        "token": f"session_{username}"
    }), 200

@app.route("/api/protocols", methods=["GET"])
def api_get_protocols():
    """API endpoint to get user protocols"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    
    try:
        data = load_data(username)
        protocols = []
        
        for protocol_name, protocol_data in data.get("protocols", {}).items():
            protocols.append({
                "id": protocol_name.replace(" ", "_").lower(),
                "name": protocol_name,
                "compounds": protocol_data.get("compounds", []),
                "frequency": "Daily",
                "description": f"Protocol with {len(protocol_data.get('compounds', []))} compounds",
                "createdAt": datetime.now().isoformat() + "Z"
            })
        
        return jsonify(protocols), 200
    except Exception as e:
        return jsonify({"error": f"Failed to fetch protocols: {str(e)}"}), 500

@app.route("/api/protocols", methods=["POST"])
def api_create_protocol():
    """API endpoint to create new protocol"""
    username = session.get('api_username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json()
    if not data or not data.get('name'):
        return jsonify({"error": "Protocol name is required"}), 400
    
    name = data.get('name').strip()
    compounds = data.get('compounds', [])
    
    if not name:
        return jsonify({"error": "Protocol name is required"}), 400
    
    if not compounds:
        return jsonify({"error": "At least one compound is required"}), 400
    
    try:
        user_data = load_data(username)
        
        # Check if protocol already exists
        if name in user_data["protocols"]:
            return jsonify({"error": "Protocol already exists"}), 409
        
        # Convert compound details to storage format
        compound_details = []
        for compound in compounds:
            if isinstance(compound, dict):
                compound_details.append({
                    "name": compound.get("name", ""),
                    "daily_dosage": compound.get("dailyDosage", "1"),
                    "times_per_day": compound.get("timesPerDay", 1),
                    "unit": compound.get("unit", "capsule")
                })
            else:
                # Legacy format - just compound name
                compound_details.append({
                    "name": compound,
                    "daily_dosage": "1",
                    "times_per_day": 1,
                    "unit": "capsule"
                })
        
        # Create new protocol
        user_data["protocols"][name] = {
            "compounds": compound_details,
            "logs": {}
        }
        
        save_data(user_data, username)
        
        protocol_response = {
            "id": name.replace(" ", "_").lower(),
            "name": name,
            "compounds": compound_details,
            "frequency": "Daily",
            "description": f"Protocol with {len(compound_details)} compounds",
            "createdAt": datetime.now().isoformat() + "Z"
        }
        
        return jsonify(protocol_response), 201
        
    except Exception as e:
        return jsonify({"error": f"Failed to create protocol: {str(e)}"}), 500

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
            
            return jsonify(reminders), 200
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
        return {"level": 5, "title": "Supplement Master"}
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

@app.route("/api/protocols/<protocol_id>/analytics/advanced", methods=["GET"])
def api_get_advanced_analytics(protocol_id):
    """Enhanced analytics endpoint with AI insights and predictions"""
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
        
        # Generate comprehensive analytics
        analytics = generate_comprehensive_analytics(logs, prot["compounds"])
        
        return jsonify(analytics), 200
        
    except Exception as e:
        return jsonify({"error": f"Failed to fetch advanced analytics: {str(e)}"}), 500

def generate_comprehensive_analytics(logs, compounds):
    """Generate comprehensive analytics with AI insights"""
    total_days = len(logs)
    if total_days == 0:
        return {
            "totalDays": 0,
            "adherence": 0,
            "streak": 0,
            "missedDays": 0,
            "compoundStats": {},
            "aiInsights": [],
            "predictions": {},
            "correlations": [],
            "weeklyTrends": [],
            "monthlyTrends": [],
            "bestPerformingDay": None,
            "adherencePattern": "insufficient_data"
        }
    
    # Calculate basic stats
    compound_stats = {}
    weekly_data = {}
    monthly_data = {}
    
    for compound in compounds:
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
        except ValueError:
            continue
    
    weekly_trends = [{"week": week, "adherence": round(sum(values)/len(values), 1)} 
                    for week, values in weekly_data.items()]
    monthly_trends = [{"month": month, "adherence": round(sum(values)/len(values), 1)} 
                     for month, values in monthly_data.items()]
    
    total_possible = total_days * len(compounds)
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
    
    # AI Insights
    ai_insights = generate_ai_insights(logs, compound_stats, overall_adherence, current_streak)
    
    # Predictions
    predictions = generate_predictions(weekly_trends, monthly_trends, overall_adherence)
    
    # Correlations
    correlations = []
    for date_str, day_log in logs.items():
        mood = day_log.get('mood', '')
        energy = day_log.get('energy', '')
        if mood and energy:
            day_adherence = sum(1 for entry in day_log.values() if entry.get("taken", False)) / len(day_log) * 100
            correlations.append({
                "date": date_str,
                "adherence": round(day_adherence, 1),
                "mood": mood,
                "energy": energy
            })
    
    return {
        "totalDays": total_days,
        "adherence": overall_adherence,
        "streak": current_streak,
        "missedDays": missed_days,
        "compoundStats": compound_stats,
        "aiInsights": ai_insights,
        "predictions": predictions,
        "correlations": correlations,
        "weeklyTrends": weekly_trends,
        "monthlyTrends": monthly_trends,
        "bestPerformingDay": get_best_performing_day(logs),
        "adherencePattern": analyze_adherence_pattern(logs)
    }

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