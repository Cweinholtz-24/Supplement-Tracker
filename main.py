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
    with open(user_file(username)) as f:
        return json.load(f)

def save_data(data, username=None):
    with open(user_file(username), "w") as f:
        json.dump(data, f, indent=2)

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
    name = request.form["protocol_name"]
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
<h2>{{title}}</h2>
<form method="POST">
  Username: <input name="username"><br>
  Password: <input type="password" name="password"><br>
  <button type="submit">{{title}}</button>
</form>
<a href="/login">Login</a> | <a href="/register">Register</a>
"""

TWOFA_TEMPLATE = """
<h2>Two-Factor Authentication</h2>
<form method="POST">
  Code: <input name="code" required>
  <button type="submit">Verify</button>
</form>
"""

THEME_HEADER = """
<style>
:root { --bg: #fff; --text: #111; --border: #ccc; --input-bg: #fff; }
body.dark { --bg: #111; --text: #eee; --border: #555; --input-bg: #222; }
body { 
  background: var(--bg); 
  color: var(--text); 
  font-family: sans-serif; 
  transition: 0.3s; 
}
a { color: #007bff; text-decoration: none; }
body.dark a { color: #66b3ff; }
a:hover { text-decoration: underline; }
input, button { 
  background: var(--input-bg); 
  color: var(--text); 
  border: 1px solid var(--border); 
  padding: 4px; 
  margin: 2px; 
  border-radius: 3px;
}
button { cursor: pointer; }
button:hover { opacity: 0.8; }
table { border-collapse: collapse; }
table, th, td { border: 1px solid var(--border); }
th, td { padding: 8px; }
.theme-toggle { 
  position: absolute; 
  top: 8px; 
  right: 12px; 
  font-size: 14px; 
  background: var(--input-bg);
}
</style>
<script>
document.addEventListener('DOMContentLoaded', () => {
  const btn = document.createElement('button');
  btn.innerText = "🌙 Toggle Theme";
  btn.className = "theme-toggle";
  btn.onclick = () => {
    document.body.classList.toggle('dark');
    localStorage.setItem('darkmode', document.body.classList.contains('dark'));
  };
  document.body.appendChild(btn);
  if (localStorage.getItem('darkmode') === 'true') {
    document.body.classList.add('dark');
  }
});
</script>
"""


DASHBOARD_TEMPLATE = """
<h2>Welcome, {{user}}</h2>
<a href="/logout">Logout</a> | <a href="/2fa_setup">2FA Setup</a>
<form method="POST" action="/create">
  <input name="protocol_name" placeholder="New protocol name" required>
  <button type="submit">Create</button>
</form>
<ul>
{% for p in protocols %}
  <li>
    <a href="/protocol/{{p}}">{{p}}</a> — 
    <a href="/protocol/{{p}}/history">History</a> — 
    <a href="/protocol/{{p}}/calendar">Calendar</a>
    <form method="POST" action="/delete_protocol/{{p}}" style="display:inline;" onsubmit="return confirm('Delete protocol {{p}}?')">
      <button type="submit">🗑️</button>
    </form>
  </li>
{% endfor %}
</ul>
"""

TRACKER_TEMPLATE = """
<h2>Protocol: {{name}}</h2>
<a href="/">← Back</a>
<form method="POST">
  <p>Email for reminders: <input name="email" value="{{email}}"></p>
  <p>📅 Today: {{today}}</p>
  <table><tr><th>Compound</th><th>Taken?</th><th>Notes</th></tr>
  {% for c in compounds %}
    <tr>
      <td>{{c}}</td>
      <td><input type="checkbox" name="check_{{c}}" {% if log.get(c, {}).get('taken') %}checked{% endif %}></td>
      <td><input name="note_{{c}}" value="{{log.get(c, {}).get('note','')}}"></td>
    </tr>
  {% endfor %}
  </table><br>
  <button type="submit">💾 Save</button>
</form>
<h3>🧪 Edit Compounds</h3>
<form method="POST" action="/protocol/{{name}}/edit_compounds">
  <textarea name="new_compounds" rows="2" cols="60">{{ compounds | join(', ') }}</textarea><br>
  <button type="submit">💾 Update Compounds</button>
</form>
<a href="/protocol/{{name}}/reminder">📧 Simulate Reminder</a>
"""

HIST_TEMPLATE = """
<h2>📜 History for {{name}}</h2>
<a href="/protocol/{{name}}">← Back</a>
{% for d, entries in logs.items() %}
  <h4>{{d}}</h4><ul>
  {% for compound, e in entries.items() %}
    <li>{{compound}}: {{'✅' if e.taken else '❌'}} - {{e.note}}</li>
  {% endfor %}
  </ul>
{% endfor %}
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
    app.run(host="0.0.0.0", port=3000)
