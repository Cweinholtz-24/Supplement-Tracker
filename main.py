import os, json, io, base64
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, datetime
from pathlib import Path
import pyotp
import qrcode

app = Flask(__name__)
app.secret_key = "super_secure_key"
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

DATA_DIR = Path("data")
USER_DIR = DATA_DIR / "users"
USER_DIR.mkdir(parents=True, exist_ok=True)

class User(UserMixin):
    def __init__(self, username):
        self.id = username

    @staticmethod
    def get(username):
        path = USER_DIR / f"{username}.json"
        if path.exists():
            return User(username)
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

def user_file(username=None):
    u = username or current_user.id
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

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]
        path = user_file(username)
        if path.exists(): return "User already exists"
        secret = pyotp.random_base32()
        with open(path, "w") as f:
            json.dump({
                "password": generate_password_hash(password),
                "2fa_secret": secret,
                "protocols": {},
                "email": ""
            }, f)
        session["pending_user"] = username
        return redirect(url_for("twofa_setup"))
    return render_template_string(AUTH_TEMPLATE, title="Register", action="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]
        path = user_file(username)
        if not path.exists(): return "User not found"
        data = load_data(username)
        if not check_password_hash(data["password"], password): return "Incorrect password"
        session["pending_user"] = username
        return redirect(url_for("twofa_verify"))
    return render_template_string(AUTH_TEMPLATE, title="Login", action="login")

@app.route("/2fa", methods=["GET", "POST"])
def twofa_verify():
    username = session.get("pending_user")
    if not username:
        return redirect(url_for("login"))
    data = load_data(username)
    if request.method == "POST":
        code = request.form["code"]
        if pyotp.TOTP(data["2fa_secret"]).verify(code):
            login_user(User(username))
            session.pop("pending_user")
            return redirect(url_for("dashboard"))
        else:
            return "Invalid 2FA code"
    return render_template_string(TWOFA_TEMPLATE)

@app.route("/2fa_setup")
def twofa_setup():
    username = session.get("pending_user")
    if not username:
        return redirect(url_for("login"))
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
    return f"""
        <h2>Scan QR Code in Google Authenticator</h2>
        <img src='data:image/png;base64,{encoded}'><br><br>
        Manual entry code: <code>{data['2fa_secret']}</code><br><br>
        <a href='/2fa'>Continue to verify</a>
    """

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
        return "Protocol name is required", 400
    if len(name) > 50:
        return "Protocol name too long", 400
    
    data = load_data()
    if name not in data["protocols"]:
        data["protocols"][name] = {
            "compounds": ["FOXO4-DRI", "Fisetin", "Quercetin"],
            "logs": {}
        }
        save_data(data)
    return redirect(url_for("tracker", name=name))

@app.route("/delete_protocol/<name>", methods=["POST"])
@login_required
def delete_protocol(name):
    data = load_data()
    if name in data["protocols"]:
        del data["protocols"][name]
        save_data(data)
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
        return redirect(url_for("tracker", name=name))
    return render_template_string(THEME_HEADER + TRACKER_TEMPLATE,
        name=name, compounds=prot["compounds"], log=prot["logs"].get(today, {}),
        today=today, email=data.get("email", ""))

@app.route("/protocol/<name>/edit_compounds", methods=["POST"])
@login_required
def edit_compounds(name):
    data = load_data()
    compounds = request.form.get("new_compounds", "")
    data["protocols"][name]["compounds"] = [c.strip() for c in compounds.split(",") if c.strip()]
    save_data(data)
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
    msg = f"Reminder: Log today’s dose for '{name}'\\nLast log: {last} ({days_since} days ago)"

    email = data.get("email", "")
    if email:
        send_email(email, f"Reminder: {name}", msg)

    return f"<pre>{msg}</pre><a href='/protocol/{name}'>← Back</a>"


import smtplib
from email.mime.text import MIMEText

def send_email(to_email, subject, body):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    from_email = "your_email@gmail.com"
    password = "your_app_password"  # Not your real Gmail password

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
    except Exception as e:
        print("❌ Email error:", e)


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
</style>
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
    <h1>💊 Senolytic Tracker</h1>
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
<link href="https://cdn.jsdelivr.net/npm/fullcalendar@6.1.10/main.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/fullcalendar@6.1.10/main.min.js"></script>
<a href="/protocol/{{name}}">← Back</a>
<div id="calendar"></div><div id="logDetails"></div>
<script>
document.addEventListener('DOMContentLoaded', function() {
  const calendar = new FullCalendar.Calendar(document.getElementById('calendar'), {
    initialView: 'dayGridMonth',
    events: '/protocol/{{name}}/logs.json',
    eventClick(info) {
      const e = info.event.extendedProps.entries;
      let html = '<h3>' + info.event.startStr + '</h3><ul>';
      for (const [k,v] of Object.entries(e)) {
        html += `<li><b>${k}</b>: ${v.taken ? '✅' : '❌'} - ${v.note}</li>`;
      }
      html += '</ul>';
      document.getElementById("logDetails").innerHTML = html;
    }
  });
  calendar.render();
});
</script>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
