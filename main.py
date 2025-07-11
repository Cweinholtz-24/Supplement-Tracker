import os, json, io, base64, sqlite3
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify, Response, flash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, datetime
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        # Admins table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                twofa_secret TEXT NOT NULL,
                role TEXT DEFAULT 'Admin',
                email TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        # Protocols table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS protocols (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                compounds TEXT NOT NULL,
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
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insert default config values
        cursor.execute('''
            INSERT OR IGNORE INTO app_config (key, value) 
            VALUES ('app_name', 'Supplement Tracker')
        ''')
        cursor.execute('''
            INSERT OR IGNORE INTO app_config (key, value) 
            VALUES ('max_protocols_per_user', '10')
        ''')
        
        conn.commit()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def migrate_json_to_db():
    """Migrate existing JSON data to database"""
    if not USER_DIR.exists():
        return
        
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Migrate users
        for user_file in USER_DIR.glob("*.json"):
            username = user_file.stem
            try:
                with open(user_file) as f:
                    user_data = json.load(f)
                
                cursor.execute('''
                    INSERT OR IGNORE INTO users (username, password_hash, twofa_secret, email)
                    VALUES (?, ?, ?, ?)
                ''', (username, user_data.get("password", ""), 
                      user_data.get("2fa_secret", ""), user_data.get("email", "")))
                
                # Get user ID
                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                user_row = cursor.fetchone()
                if not user_row:
                    continue
                user_id = user_row[0]
                
                # Migrate protocols
                protocols = user_data.get("protocols", {})
                for protocol_name, protocol_data in protocols.items():
                    compounds = json.dumps(protocol_data.get("compounds", []))
                    cursor.execute('''
                        INSERT OR IGNORE INTO protocols (user_id, name, compounds)
                        VALUES (?, ?, ?)
                    ''', (user_id, protocol_name, compounds))
                    
                    # Get protocol ID
                    cursor.execute("SELECT id FROM protocols WHERE user_id = ? AND name = ?", 
                                 (user_id, protocol_name))
                    protocol_row = cursor.fetchone()
                    if not protocol_row:
                        continue
                    protocol_id = protocol_row[0]
                    
                    # Migrate logs
                    logs = protocol_data.get("logs", {})
                    for log_date, entries in logs.items():
                        for compound, entry_data in entries.items():
                            cursor.execute('''
                                INSERT OR IGNORE INTO protocol_logs 
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
                
            except Exception as e:
                print(f"Error migrating {username}: {e}")
        
        conn.commit()

# Initialize database on startup
init_db()
migrate_json_to_db()

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

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

def load_data(username=None):
    """Load user data from database"""
    username = username or current_user.id
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT password_hash, twofa_secret, email 
            FROM users WHERE username = ?
        ''', (username,))
        row = cursor.fetchone()
        if not row:
            return {"password": "", "2fa_secret": "", "protocols": {}, "email": ""}
        
        # Get protocols
        cursor.execute('''
            SELECT name, compounds FROM protocols 
            WHERE user_id = (SELECT id FROM users WHERE username = ?)
        ''', (username,))
        protocols = {}
        for protocol_row in cursor.fetchall():
            protocol_name = protocol_row[0]
            compounds = json.loads(protocol_row[1])
            
            # Get logs for this protocol
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

def save_data(data, username=None):
    """Save user data to database"""
    username = username or current_user.id
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Update user info
        cursor.execute('''
            UPDATE users SET email = ? WHERE username = ?
        ''', (data.get("email", ""), username))
        
        # Get user ID
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_row = cursor.fetchone()
        if not user_row:
            return
        user_id = user_row[0]
        
        # Handle protocols
        for protocol_name, protocol_data in data.get("protocols", {}).items():
            compounds = json.dumps(protocol_data.get("compounds", []))
            
            # Insert or update protocol
            cursor.execute('''
                INSERT OR REPLACE INTO protocols (user_id, name, compounds)
                VALUES (?, ?, ?)
            ''', (user_id, protocol_name, compounds))
            
            # Get protocol ID
            cursor.execute("SELECT id FROM protocols WHERE user_id = ? AND name = ?", 
                         (user_id, protocol_name))
            protocol_row = cursor.fetchone()
            if not protocol_row:
                continue
            protocol_id = protocol_row[0]
            
            # Handle logs
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

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]
        
        if not username or not password:
            flash("Username and password are required", "error")
            return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Register", action="register")
            
        if len(username) < 3:
            flash("Username must be at least 3 characters", "error")
            return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Register", action="register")
            
        if len(password) < 6:
            flash("Password must be at least 6 characters", "error")
            return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Register", action="register")
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                flash("User already exists", "error")
                return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Register", action="register")
            
            secret = pyotp.random_base32()
            cursor.execute('''
                INSERT INTO users (username, password_hash, twofa_secret, email)
                VALUES (?, ?, ?, ?)
            ''', (username, generate_password_hash(password), secret, ""))
            conn.commit()
            
        session["pending_user"] = username
        flash("Account created successfully! Please set up 2FA.", "success")
        return redirect(url_for("twofa_setup"))
    return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Register", action="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]
        
        if not username or not password:
            flash("Username and password are required", "error")
            return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Login", action="login")
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if not row:
                flash("User not found", "error")
                return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Login", action="login")
            
            if not check_password_hash(row[0], password):
                flash("Incorrect password", "error")
                return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Login", action="login")
            
            # Update last login
            cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?", (username,))
            conn.commit()
            
        session["pending_user"] = username
        return redirect(url_for("twofa_verify"))
    return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Login", action="login")

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

@app.route("/2fa_setup")
def twofa_setup():
    username = session.get("pending_user")
    if not username:
        flash("Session expired. Please login again.", "error")
        return redirect(url_for("login"))
    data = load_data(username)
    uri = pyotp.TOTP(data["2fa_secret"]).provisioning_uri(
        name=username,
        issuer_name="SupplementTracker"
    )
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    encoded = base64.b64encode(buf.read()).decode()
    
    setup_template = """
    <div class="container">
      <div class="card" style="max-width: 500px; margin: 80px auto; text-align: center;">
        <h2>🔐 Set Up Two-Factor Authentication</h2>
        <p>Scan this QR code with Google Authenticator or similar app:</p>
        <img src='data:image/png;base64,{qr_code}' style="border: 1px solid var(--border); border-radius: 8px; margin: 20px 0;">
        <div style="background: var(--bg); padding: 16px; border-radius: 8px; margin: 20px 0;">
          <p><strong>Manual entry code:</strong></p>
          <code style="font-size: 16px; font-weight: bold; color: var(--primary);">{secret}</code>
        </div>
        <a href='/2fa' class="btn-primary" style="display: inline-block; padding: 12px 24px; text-decoration: none; border-radius: 8px;">Continue to Verify →</a>
      </div>
    </div>
    """
    
    return render_template_string(THEME_HEADER + setup_template, qr_code=encoded, secret=data['2fa_secret'])

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    data = load_data()
    return render_template_string(THEME_HEADER + DASHBOARD_TEMPLATE, protocols=data["protocols"].keys(), user=current_user.id)

@app.route("/create", methods=["POST"])
@login_required
def create_protocol():
    name = request.form.get("protocol_name", "").strip()
    if not name:
        flash("Protocol name is required", "error")
        return redirect(url_for("dashboard"))
    if len(name) > 50:
        flash("Protocol name too long (max 50 characters)", "error")
        return redirect(url_for("dashboard"))

    data = load_data()
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
def delete_protocol(name):
    data = load_data()
    if name in data["protocols"]:
        del data["protocols"][name]
        save_data(data)
        flash(f"Protocol '{name}' deleted successfully", "success")
    else:
        flash(f"Protocol '{name}' not found", "error")
    return redirect(url_for("dashboard"))

@app.route("/protocol/<name>", methods=["GET", "POST"])
@login_required
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
def calendar(name):
    return render_template_string(THEME_HEADER + CAL_TEMPLATE, name=name)

@app.route("/protocol/<name>/logs.json")
@login_required
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
def history(name):
    logs = load_data()["protocols"][name]["logs"]
    return render_template_string(THEME_HEADER + HIST_TEMPLATE, name=name, logs=logs)

@app.route("/protocol/<name>/reminder")
@login_required
def reminder(name):
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
def analytics(name):
    data = load_data()
    prot = data["protocols"][name]
    logs = prot["logs"]

    # Calculate analytics
    total_days = len(logs)
    if total_days == 0:
        return render_template_string(THEME_HEADER + ANALYTICS_TEMPLATE, 
                                    name=name, total_days=0, adherence=0, streak=0, 
                                    missed_days=0, compound_stats={})

    adherence_data = []
    compound_stats = {}

    for compound in prot["compounds"]:
        taken_count = sum(1 for day_log in logs.values() 
                         if day_log.get(compound, {}).get("taken", False))
        compound_stats[compound] = {
            "taken": taken_count,
            "missed": total_days - taken_count,
            "percentage": round((taken_count / total_days) * 100, 1)
        }

    # Calculate overall adherence
    total_possible = total_days * len(prot["compounds"])
    total_taken = sum(sum(1 for entry in day_log.values() if entry.get("taken", False)) 
                     for day_log in logs.values())
    overall_adherence = round((total_taken / total_possible) * 100, 1) if total_possible > 0 else 0

    # Calculate current streak
    sorted_dates = sorted(logs.keys(), reverse=True)
    current_streak = 0
    for date_str in sorted_dates:
        day_log = logs[date_str]
        all_taken = all(entry.get("taken", False) for entry in day_log.values())
        if all_taken:
            current_streak += 1
        else:
            break

    # Missed days
    missed_days = sum(1 for day_log in logs.values() 
                     if not all(entry.get("taken", False) for entry in day_log.values()))

    return render_template_string(THEME_HEADER + ANALYTICS_TEMPLATE,
                                name=name, total_days=total_days, adherence=overall_adherence,
                                streak=current_streak, missed_days=missed_days,
                                compound_stats=compound_stats)

@app.route("/protocol/<name>/export/csv")
@login_required
def export_csv(name):
    data = load_data()
    prot = data["protocols"][name]

    output = io.StringIO()
    writer = csv.writer(output)

    # Headers
    headers = ["Date"] + prot["compounds"] + [f"{c}_Notes" for c in prot["compounds"]]
    writer.writerow(headers)

    # Data rows
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
def enhanced_tracking(name):
    today = date.today().isoformat()
    data = load_data()
    prot = data["protocols"][name]

    if request.method == "POST":
        if today not in prot["logs"]:
            prot["logs"][today] = {}

        # Enhanced tracking data
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


import smtplib
from email.mime.text import MIMEText
from flask import flash

def send_email(to_email, subject, body):
    # Use environment variables for SMTP configuration
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    from_email = os.getenv("SMTP_FROM_EMAIL", "")
    password = os.getenv("SMTP_PASSWORD", "")

    if not from_email or not password:
        flash("Email configuration not set up. Please configure SMTP settings.", "error")
        return False

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(from_email, password)
            server.send_message(msg)
            print("📧 Email sent to", to_email)
            return True
    except Exception as e:
        print("❌ Email error:", e)
        flash(f"Failed to send email: {str(e)}", "error")
        return False


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
    </div>
  </div>
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
input, button, textarea { 
  background: var(--input-bg); 
  color: var(--text); 
  border: 1px solid var(--border); 
  padding: 12px 16px; 
  margin: 4px; 
  border-radius: 8px;
  font-size: 14px;
  transition: all 0.2s;
}
input:focus, textarea:focus { 
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
  margin: 16px 0; 
}
.form-group label { 
  display: block; 
  margin-bottom: 8px; 
  font-weight: 500;
}
.status-badge { 
  padding: 4px 8px; 
  border-radius: 20px; 
  font-size: 12px; 
  font-weight: 500;
}
.status-success { 
  background: var(--success); 
  color: white;
}
.status-danger { 
  background: var(--danger); 
  color: white;
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
  btn.innerHTML = "🌙 <span>Dark Mode</span>";
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
    <div id="calendar" style="min-height: 600px;"></div>
  </div>
  
  <div class="card" id="logDetails" style="display: none;">
    <h3>📋 Day Details</h3>
    <div id="logContent"></div>
  </div>
</div>

<link href="https://cdn.jsdelivr.net/npm/fullcalendar@6.1.10/main.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/fullcalendar@6.1.10/main.min.js"></script>
<script>
document.addEventListener('DOMContentLoaded', function() {
  try {
    const calendarEl = document.getElementById('calendar');
    const calendar = new FullCalendar.Calendar(calendarEl, {
      initialView: 'dayGridMonth',
      headerToolbar: {
        left: 'prev,next today',
        center: 'title',
        right: 'dayGridMonth,dayGridWeek'
      },
      events: '/protocol/{{name}}/logs.json',
      eventClick: function(info) {
        const entries = info.event.extendedProps.entries;
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
      },
      height: 'auto'
    });
    calendar.render();
  } catch (error) {
    console.error('Calendar loading error:', error);
    document.getElementById('calendar').innerHTML = 
      '<div style="text-align: center; padding: 40px; color: var(--danger);">' +
      '<h3>❌ Calendar Error</h3>' +
      '<p>Unable to load calendar. Please check your internet connection.</p>' +
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)