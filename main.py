
import os, json, io, base64
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
ADMIN_DIR = DATA_DIR / "admin"
USER_DIR.mkdir(parents=True, exist_ok=True)
ADMIN_DIR.mkdir(parents=True, exist_ok=True)

# Admin Roles
ROLES = {
    "super_admin": {"level": 3, "name": "Super Admin"},
    "admin": {"level": 2, "name": "Admin"},
    "operator": {"level": 1, "name": "Operator"}
}

class User(UserMixin):
    def __init__(self, username, is_admin=False, role=None):
        self.id = username
        self.is_admin = is_admin
        self.role = role

    @staticmethod
    def get(username):
        # Check if it's an admin user
        admin_path = ADMIN_DIR / f"{username}.json"
        if admin_path.exists():
            with open(admin_path) as f:
                admin_data = json.load(f)
            return User(username, is_admin=True, role=admin_data.get("role", "operator"))
        
        # Check if it's a regular user
        path = USER_DIR / f"{username}.json"
        if path.exists():
            return User(username)
        return None

    def has_role(self, required_role):
        if not self.is_admin:
            return False
        user_level = ROLES.get(self.role, {}).get("level", 0)
        required_level = ROLES.get(required_role, {}).get("level", 0)
        return user_level >= required_level

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

def user_file(username=None):
    u = username or current_user.id
    if current_user.is_admin:
        return ADMIN_DIR / f"{u}.json"
    return USER_DIR / f"{u}.json"

def load_data(username=None):
    try:
        with open(user_file(username)) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"password": "", "2fa_secret": "", "protocols": {}, "email": ""}

def save_data(data, username=None):
    try:
        with open(user_file(username), "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error saving data: {e}")
        raise

def load_admin_data(username=None):
    try:
        admin_path = ADMIN_DIR / f"{username or current_user.id}.json"
        with open(admin_path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"password": "", "2fa_secret": "", "role": "operator", "email": "", "created_at": "", "last_login": ""}

def save_admin_data(data, username=None):
    try:
        admin_path = ADMIN_DIR / f"{username or current_user.id}.json"
        with open(admin_path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error saving admin data: {e}")
        raise

def load_app_config():
    config_path = DATA_DIR / "app_config.json"
    try:
        with open(config_path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        default_config = {
            "app_name": "Senolytic Tracker",
            "max_protocols_per_user": 10,
            "default_compounds": ["FOXO4-DRI", "Fisetin", "Quercetin"],
            "email_reminders_enabled": True,
            "registration_enabled": True,
            "data_export_enabled": True,
            "analytics_enabled": True
        }
        save_app_config(default_config)
        return default_config

def save_app_config(config):
    config_path = DATA_DIR / "app_config.json"
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)

def admin_required(role="operator"):
    def decorator(f):
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated or not current_user.is_admin:
                flash("Admin access required", "error")
                return redirect(url_for("login"))
            if not current_user.has_role(role):
                flash(f"Insufficient permissions. {ROLES[role]['name']} role required.", "error")
                return redirect(url_for("admin_dashboard"))
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

@app.route("/admin/register", methods=["GET", "POST"])
def admin_register():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]
        role = request.form["role"]
        
        if not username or not password:
            flash("Username and password are required", "error")
            return render_template_string(THEME_HEADER + ADMIN_REGISTER_TEMPLATE, roles=ROLES)
            
        if role not in ROLES:
            flash("Invalid role selected", "error")
            return render_template_string(THEME_HEADER + ADMIN_REGISTER_TEMPLATE, roles=ROLES)
            
        admin_path = ADMIN_DIR / f"{username}.json"
        if admin_path.exists():
            flash("Admin user already exists", "error")
            return render_template_string(THEME_HEADER + ADMIN_REGISTER_TEMPLATE, roles=ROLES)
            
        secret = pyotp.random_base32()
        admin_data = {
            "password": generate_password_hash(password),
            "2fa_secret": secret,
            "role": role,
            "email": "",
            "created_at": datetime.now().isoformat(),
            "last_login": ""
        }
        save_admin_data(admin_data, username)
        session["pending_user"] = username
        session["is_admin"] = True
        flash(f"Admin account created successfully with {ROLES[role]['name']} role!", "success")
        return redirect(url_for("twofa_setup"))
        
    return render_template_string(THEME_HEADER + ADMIN_REGISTER_TEMPLATE, roles=ROLES)

@app.route("/register", methods=["GET", "POST"])
def register():
    config = load_app_config()
    if not config.get("registration_enabled", True):
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
            
        if len(password) < 6:
            flash("Password must be at least 6 characters", "error")
            return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Register", action="register")
            
        path = user_file(username)
        if path.exists(): 
            flash("User already exists", "error")
            return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Register", action="register")
            
        secret = pyotp.random_base32()
        with open(path, "w") as f:
            json.dump({
                "password": generate_password_hash(password),
                "2fa_secret": secret,
                "protocols": {},
                "email": "",
                "created_at": datetime.now().isoformat()
            }, f)
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
        
        # Check admin users first
        admin_path = ADMIN_DIR / f"{username}.json"
        if admin_path.exists():
            data = load_admin_data(username)
            if check_password_hash(data["password"], password):
                session["pending_user"] = username
                session["is_admin"] = True
                return redirect(url_for("twofa_verify"))
            else:
                flash("Incorrect password", "error")
                return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Login", action="login")
        
        # Check regular users
        path = USER_DIR / f"{username}.json"
        if not path.exists(): 
            flash("User not found", "error")
            return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Login", action="login")
            
        data = load_data(username)
        if not check_password_hash(data["password"], password): 
            flash("Incorrect password", "error")
            return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Login", action="login")
            
        session["pending_user"] = username
        session["is_admin"] = False
        return redirect(url_for("twofa_verify"))
    return render_template_string(THEME_HEADER + AUTH_TEMPLATE, title="Login", action="login")

@app.route("/2fa", methods=["GET", "POST"])
def twofa_verify():
    username = session.get("pending_user")
    is_admin = session.get("is_admin", False)
    
    if not username:
        flash("Session expired. Please login again.", "error")
        return redirect(url_for("login"))
    
    if is_admin:
        data = load_admin_data(username)
    else:
        data = load_data(username)
        
    if request.method == "POST":
        code = request.form["code"]
        if not code or len(code) != 6:
            flash("Please enter a valid 6-digit code", "error")
            return render_template_string(THEME_HEADER + TWOFA_TEMPLATE)
            
        if pyotp.TOTP(data["2fa_secret"]).verify(code):
            user = User(username, is_admin=is_admin, role=data.get("role") if is_admin else None)
            login_user(user)
            
            # Update last login for admin users
            if is_admin:
                data["last_login"] = datetime.now().isoformat()
                save_admin_data(data, username)
            
            session.pop("pending_user")
            session.pop("is_admin", None)
            flash("Successfully logged in!", "success")
            
            if is_admin:
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("dashboard"))
        else:
            flash("Invalid 2FA code. Please try again.", "error")
            return render_template_string(THEME_HEADER + TWOFA_TEMPLATE)
    return render_template_string(THEME_HEADER + TWOFA_TEMPLATE)

@app.route("/2fa_setup")
def twofa_setup():
    username = session.get("pending_user")
    is_admin = session.get("is_admin", False)
    
    if not username:
        flash("Session expired. Please login again.", "error")
        return redirect(url_for("login"))
    
    if is_admin:
        data = load_admin_data(username)
    else:
        data = load_data(username)
        
    uri = pyotp.TOTP(data["2fa_secret"]).provisioning_uri(
        name=username,
        issuer_name="SenolyticTracker"
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
    session.clear()
    return redirect(url_for("login"))

@app.route("/admin")
@admin_required("operator")
def admin_dashboard():
    users = []
    admins = []
    
    # Load regular users
    for user_file in USER_DIR.glob("*.json"):
        try:
            with open(user_file) as f:
                user_data = json.load(f)
            users.append({
                "username": user_file.stem,
                "protocols": len(user_data.get("protocols", {})),
                "email": user_data.get("email", ""),
                "created_at": user_data.get("created_at", "Unknown")
            })
        except:
            continue
    
    # Load admin users
    for admin_file in ADMIN_DIR.glob("*.json"):
        try:
            with open(admin_file) as f:
                admin_data = json.load(f)
            admins.append({
                "username": admin_file.stem,
                "role": admin_data.get("role", "operator"),
                "email": admin_data.get("email", ""),
                "created_at": admin_data.get("created_at", "Unknown"),
                "last_login": admin_data.get("last_login", "Never")
            })
        except:
            continue
    
    config = load_app_config()
    
    return render_template_string(THEME_HEADER + ADMIN_DASHBOARD_TEMPLATE, 
                                users=users, admins=admins, config=config, 
                                current_role=current_user.role, roles=ROLES)

@app.route("/admin/config", methods=["POST"])
@admin_required("admin")
def admin_update_config():
    config = load_app_config()
    
    config["app_name"] = request.form.get("app_name", config["app_name"])
    config["max_protocols_per_user"] = int(request.form.get("max_protocols_per_user", config["max_protocols_per_user"]))
    config["default_compounds"] = [c.strip() for c in request.form.get("default_compounds", "").split(",") if c.strip()]
    config["email_reminders_enabled"] = "email_reminders_enabled" in request.form
    config["registration_enabled"] = "registration_enabled" in request.form
    config["data_export_enabled"] = "data_export_enabled" in request.form
    config["analytics_enabled"] = "analytics_enabled" in request.form
    
    save_app_config(config)
    flash("Configuration updated successfully!", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/users/<username>/delete", methods=["POST"])
@admin_required("admin")
def admin_delete_user(username):
    user_path = USER_DIR / f"{username}.json"
    if user_path.exists():
        user_path.unlink()
        flash(f"User '{username}' deleted successfully", "success")
    else:
        flash(f"User '{username}' not found", "error")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/admins/<username>/delete", methods=["POST"])
@admin_required("super_admin")
def admin_delete_admin(username):
    if username == current_user.id:
        flash("You cannot delete your own admin account", "error")
        return redirect(url_for("admin_dashboard"))
        
    admin_path = ADMIN_DIR / f"{username}.json"
    if admin_path.exists():
        admin_path.unlink()
        flash(f"Admin '{username}' deleted successfully", "success")
    else:
        flash(f"Admin '{username}' not found", "error")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/admins/<username>/role", methods=["POST"])
@admin_required("super_admin")
def admin_change_role(username):
    new_role = request.form.get("role")
    if new_role not in ROLES:
        flash("Invalid role", "error")
        return redirect(url_for("admin_dashboard"))
    
    if username == current_user.id:
        flash("You cannot change your own role", "error")
        return redirect(url_for("admin_dashboard"))
        
    admin_data = load_admin_data(username)
    admin_data["role"] = new_role
    save_admin_data(admin_data, username)
    flash(f"Role updated to {ROLES[new_role]['name']} for '{username}'", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/")
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for("admin_dashboard"))
        
    data = load_data()
    config = load_app_config()
    return render_template_string(THEME_HEADER + DASHBOARD_TEMPLATE, 
                                protocols=data["protocols"].keys(), 
                                user=current_user.id, 
                                config=config)

@app.route("/create", methods=["POST"])
@login_required
def create_protocol():
    if current_user.is_admin:
        flash("Admin users cannot create protocols", "error")
        return redirect(url_for("admin_dashboard"))
        
    name = request.form.get("protocol_name", "").strip()
    if not name:
        flash("Protocol name is required", "error")
        return redirect(url_for("dashboard"))
    if len(name) > 50:
        flash("Protocol name too long (max 50 characters)", "error")
        return redirect(url_for("dashboard"))

    data = load_data()
    config = load_app_config()
    
    if len(data["protocols"]) >= config.get("max_protocols_per_user", 10):
        flash(f"Maximum {config['max_protocols_per_user']} protocols allowed per user", "error")
        return redirect(url_for("dashboard"))

    if name not in data["protocols"]:
        data["protocols"][name] = {
            "compounds": config.get("default_compounds", ["FOXO4-DRI", "Fisetin", "Quercetin"]),
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
    if current_user.is_admin:
        flash("Admin users cannot modify protocols", "error")
        return redirect(url_for("admin_dashboard"))
        
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
    if current_user.is_admin:
        flash("Admin users cannot access user protocols", "error")
        return redirect(url_for("admin_dashboard"))
        
    today = date.today().isoformat()
    data = load_data()
    
    if name not in data["protocols"]:
        flash(f"Protocol '{name}' not found", "error")
        return redirect(url_for("dashboard"))
        
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
    if current_user.is_admin:
        flash("Admin users cannot modify protocols", "error")
        return redirect(url_for("admin_dashboard"))
        
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
    if current_user.is_admin:
        flash("Admin users cannot access user protocols", "error")
        return redirect(url_for("admin_dashboard"))
    return render_template_string(THEME_HEADER + CAL_TEMPLATE, name=name)

@app.route("/protocol/<name>/logs.json")
@login_required
def logs_json(name):
    if current_user.is_admin:
        return jsonify([])
        
    logs = []
    data = load_data()
    if name not in data["protocols"]:
        return jsonify([])
        
    prot = data["protocols"][name]
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
    if current_user.is_admin:
        flash("Admin users cannot access user protocols", "error")
        return redirect(url_for("admin_dashboard"))
        
    data = load_data()
    if name not in data["protocols"]:
        flash(f"Protocol '{name}' not found", "error")
        return redirect(url_for("dashboard"))
        
    logs = data["protocols"][name]["logs"]
    return render_template_string(THEME_HEADER + HIST_TEMPLATE, name=name, logs=logs)

@app.route("/protocol/<name>/reminder")
@login_required
def reminder(name):
    if current_user.is_admin:
        flash("Admin users cannot send reminders", "error")
        return redirect(url_for("admin_dashboard"))
        
    config = load_app_config()
    if not config.get("email_reminders_enabled", True):
        flash("Email reminders are disabled", "error")
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
def analytics(name):
    if current_user.is_admin:
        flash("Admin users cannot access analytics", "error")
        return redirect(url_for("admin_dashboard"))
        
    config = load_app_config()
    if not config.get("analytics_enabled", True):
        flash("Analytics are disabled", "error")
        return redirect(url_for("tracker", name=name))
        
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
    if current_user.is_admin:
        flash("Admin users cannot export data", "error")
        return redirect(url_for("admin_dashboard"))
        
    config = load_app_config()
    if not config.get("data_export_enabled", True):
        flash("Data export is disabled", "error")
        return redirect(url_for("tracker", name=name))
        
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
    if current_user.is_admin:
        flash("Admin users cannot access enhanced tracking", "error")
        return redirect(url_for("admin_dashboard"))
        
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
      <a href="/admin/register">Admin Register</a>
    </div>
  </div>
</div>
"""

ADMIN_REGISTER_TEMPLATE = """
<div class="container">
  <div class="card" style="max-width: 400px; margin: 80px auto;">
    <h2>🔑 Admin Registration</h2>
    <form method="POST">
      <div class="form-group">
        <label>Username</label>
        <input name="username" required>
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" required>
      </div>
      <div class="form-group">
        <label>Role</label>
        <select name="role" required>
          {% for role_key, role_info in roles.items() %}
            <option value="{{role_key}}">{{role_info.name}}</option>
          {% endfor %}
        </select>
      </div>
      <button type="submit" class="btn-primary">Create Admin Account</button>
    </form>
    <div class="nav-links" style="justify-content: center; margin-top: 24px;">
      <a href="/login">Back to Login</a>
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
.btn-warning { 
  background: var(--warning); 
  color: white; 
  border-color: var(--warning);
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
.status-warning { 
  background: var(--warning); 
  color: white;
}
.status-info { 
  background: var(--info); 
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
.role-badge {
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}
.role-super_admin { background: var(--danger); color: white; }
.role-admin { background: var(--warning); color: white; }
.role-operator { background: var(--info); color: white; }
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

ADMIN_DASHBOARD_TEMPLATE = """
<div class="container">
  <div class="card">
    <h1>🔑 Admin Dashboard</h1>
    <p>Welcome, <strong>{{current_role.title().replace('_', ' ')}}</strong> {{current_user.id}}!</p>
    <div class="nav-links">
      <a href="/logout">🚪 Logout</a>
      <a href="/admin/register">➕ Add Admin</a>
    </div>
  </div>

  <div class="card">
    <h2>⚙️ App Configuration</h2>
    {% if current_user.has_role('admin') %}
    <form method="POST" action="/admin/config">
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
        <div class="form-group">
          <label>App Name</label>
          <input name="app_name" value="{{config.app_name}}" required>
        </div>
        <div class="form-group">
          <label>Max Protocols Per User</label>
          <input type="number" name="max_protocols_per_user" value="{{config.max_protocols_per_user}}" min="1" max="50">
        </div>
      </div>
      <div class="form-group">
        <label>Default Compounds (comma-separated)</label>
        <textarea name="default_compounds" rows="2">{{config.default_compounds | join(', ')}}</textarea>
      </div>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 16px 0;">
        <label style="display: flex; align-items: center; gap: 8px;">
          <input type="checkbox" name="email_reminders_enabled" {{'checked' if config.email_reminders_enabled}}>
          Email Reminders Enabled
        </label>
        <label style="display: flex; align-items: center; gap: 8px;">
          <input type="checkbox" name="registration_enabled" {{'checked' if config.registration_enabled}}>
          User Registration Enabled
        </label>
        <label style="display: flex; align-items: center; gap: 8px;">
          <input type="checkbox" name="data_export_enabled" {{'checked' if config.data_export_enabled}}>
          Data Export Enabled
        </label>
        <label style="display: flex; align-items: center; gap: 8px;">
          <input type="checkbox" name="analytics_enabled" {{'checked' if config.analytics_enabled}}>
          Analytics Enabled
        </label>
      </div>
      <button type="submit" class="btn-primary">💾 Update Configuration</button>
    </form>
    {% else %}
      <p>Current Configuration:</p>
      <ul>
        <li><strong>App Name:</strong> {{config.app_name}}</li>
        <li><strong>Max Protocols:</strong> {{config.max_protocols_per_user}}</li>
        <li><strong>Default Compounds:</strong> {{config.default_compounds | join(', ')}}</li>
        <li><strong>Features:</strong> 
          {{'Email ✓' if config.email_reminders_enabled else 'Email ✗'}}
          {{'Registration ✓' if config.registration_enabled else 'Registration ✗'}}
          {{'Export ✓' if config.data_export_enabled else 'Export ✗'}}
          {{'Analytics ✓' if config.analytics_enabled else 'Analytics ✗'}}
        </li>
      </ul>
    {% endif %}
  </div>

  <div class="card">
    <h2>👥 User Management</h2>
    <p><strong>{{users|length}}</strong> registered users</p>
    {% if users %}
      <table>
        <thead>
          <tr>
            <th>Username</th>
            <th>Protocols</th>
            <th>Email</th>
            <th>Created</th>
            {% if current_user.has_role('admin') %}
            <th>Actions</th>
            {% endif %}
          </tr>
        </thead>
        <tbody>
          {% for user in users %}
          <tr>
            <td><strong>{{user.username}}</strong></td>
            <td>{{user.protocols}}</td>
            <td>{{user.email or 'Not set'}}</td>
            <td>{{user.created_at[:10] if user.created_at else 'Unknown'}}</td>
            {% if current_user.has_role('admin') %}
            <td>
              <form method="POST" action="/admin/users/{{user.username}}/delete" 
                    onsubmit="return confirm('Delete user {{user.username}}?')" style="display: inline;">
                <button type="submit" class="btn-danger btn-small">🗑️ Delete</button>
              </form>
            </td>
            {% endif %}
          </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <p>No users registered yet.</p>
    {% endif %}
  </div>

  <div class="card">
    <h2>🔑 Admin Management</h2>
    <p><strong>{{admins|length}}</strong> admin users</p>
    {% if admins %}
      <table>
        <thead>
          <tr>
            <th>Username</th>
            <th>Role</th>
            <th>Email</th>
            <th>Created</th>
            <th>Last Login</th>
            {% if current_user.has_role('super_admin') %}
            <th>Actions</th>
            {% endif %}
          </tr>
        </thead>
        <tbody>
          {% for admin in admins %}
          <tr>
            <td>
              <strong>{{admin.username}}</strong>
              {% if admin.username == current_user.id %}<em>(You)</em>{% endif %}
            </td>
            <td>
              <span class="role-badge role-{{admin.role}}">
                {{roles[admin.role].name}}
              </span>
            </td>
            <td>{{admin.email or 'Not set'}}</td>
            <td>{{admin.created_at[:10] if admin.created_at else 'Unknown'}}</td>
            <td>{{admin.last_login[:10] if admin.last_login else 'Never'}}</td>
            {% if current_user.has_role('super_admin') and admin.username != current_user.id %}
            <td>
              <form method="POST" action="/admin/admins/{{admin.username}}/role" style="display: inline; margin-right: 8px;">
                <select name="role" onchange="this.form.submit()">
                  {% for role_key, role_info in roles.items() %}
                    <option value="{{role_key}}" {{'selected' if role_key == admin.role}}>
                      {{role_info.name}}
                    </option>
                  {% endfor %}
                </select>
              </form>
              <form method="POST" action="/admin/admins/{{admin.username}}/delete" 
                    onsubmit="return confirm('Delete admin {{admin.username}}?')" style="display: inline;">
                <button type="submit" class="btn-danger btn-small">🗑️ Delete</button>
              </form>
            </td>
            {% endif %}
          </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <p>No admin users found.</p>
    {% endif %}
  </div>
</div>
"""

DASHBOARD_TEMPLATE = """
<div class="container">
  <div class="card">
    <h1>💊 {{config.app_name}}</h1>
    <p>Welcome back, <strong>{{user}}</strong>!</p>
    <div class="nav-links">
      <a href="/logout">🚪 Logout</a>
      <a href="/2fa_setup">🔒 2FA Setup</a>
    </div>
  </div>

  <div class="card">
    <h2>📋 Create New Protocol</h2>
    <p>Maximum {{config.max_protocols_per_user}} protocols allowed</p>
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
                {% if config.analytics_enabled %}
                <a href="/protocol/{{p}}/analytics">📈 Analytics</a>
                {% endif %}
                {% if config.data_export_enabled %}
                <a href="/protocol/{{p}}/export/csv">Export CSV</a>
                {% endif %}
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
