"""College Complaint Manager - Smart Campus Grievance Portal (Flask + SQLite)."""
import csv, io, os, random, re, secrets, sqlite3, string, time
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "complaints.db")
UPLOADS = os.path.join(BASE, "static", "uploads")
os.makedirs(UPLOADS, exist_ok=True)

CATEGORIES = ["Infrastructure", "Hostel", "Transportation", "Canteen", "Faculty", "Library", "Cleanliness", "Other"]
PRIORITIES = ["Low", "Medium", "High"]
STATUSES = ["Submitted", "Under Review", "In Progress", "Resolved", "Rejected"]
DEPARTMENTS = ["Computer Science", "Electronics", "Mechanical", "Civil", "Electrical", "Information Technology", "MBA", "Administration"]
ASSIGN_TO = ["Maintenance", "Hostel Warden Office", "Transport Office", "Canteen Management", "Academic Affairs", "Library Staff", "Housekeeping", "Administration"]
IMG_EXT = {"png", "jpg", "jpeg", "gif", "webp"}

def secret_key():
    p = os.path.join(BASE, ".secret_key")
    if not os.path.exists(p):
        with open(p, "w") as f: f.write(secrets.token_hex(32))
    return open(p).read()

app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get("SECRET_KEY") or secret_key(),
                  MAX_CONTENT_LENGTH=2 * 1024 * 1024,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=timedelta(hours=8))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT,
  role TEXT DEFAULT 'student', student_id TEXT, department TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS complaints(id INTEGER PRIMARY KEY, cid TEXT UNIQUE, user_id INTEGER, name TEXT,
  student_id TEXT, department TEXT, title TEXT, description TEXT, category TEXT, priority TEXT, image TEXT,
  status TEXT DEFAULT 'Submitted', assigned_to TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS updates(id INTEGER PRIMARY KEY, complaint_id INTEGER, status TEXT, note TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS feedback(id INTEGER PRIMARY KEY, name TEXT, email TEXT, message TEXT, created_at TEXT);
"""

def now(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH); g.db.row_factory = sqlite3.Row
    return g.db

def q(sql, args=(), one=False):
    cur = db().execute(sql, args); rows = cur.fetchall(); cur.close()
    return (rows[0] if rows else None) if one else rows

def run(sql, args=()):
    cur = db().execute(sql, args); db().commit(); return cur.lastrowid

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

def new_cid():
    while True:
        cid = f"CMP-{datetime.now().year}-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
        if not q("SELECT 1 FROM complaints WHERE cid=?", (cid,), one=True): return cid

def init_db():
    c = sqlite3.connect(DB_PATH); c.executescript(SCHEMA)
    if not c.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
        c.execute("INSERT INTO users(name,email,password,role,created_at) VALUES(?,?,?,?,?)",
                  ("Campus Administrator", "admin@college.edu", generate_password_hash("Admin@123"), "admin", now()))
        cur = c.execute("INSERT INTO users(name,email,password,role,student_id,department,created_at) VALUES(?,?,?,?,?,?,?)",
                  ("Demo Student", "student@college.edu", generate_password_hash("Student123"), "student", "BT21CS001", "Computer Science", now()))
        uid, rnd = cur.lastrowid, random.Random(7)
        titles = {"Infrastructure": "Broken projector in lecture hall", "Hostel": "Water supply problem in Block B",
                  "Transportation": "Bus 4 arrives late every morning", "Canteen": "Hygiene issue in canteen",
                  "Faculty": "Lab sessions are frequently cancelled", "Library": "Not enough copies of reference books",
                  "Cleanliness": "Washrooms need regular cleaning", "Other": "Wi-Fi is slow near the sports complex"}
        for i in range(26):
            cat = rnd.choice(CATEGORIES); dt = datetime.now() - timedelta(days=rnd.randint(0, 170), hours=rnd.randint(0, 20))
            st = rnd.choices(STATUSES, [3, 3, 3, 5, 1])[0]; ts = dt.strftime("%Y-%m-%d %H:%M:%S")
            cur = c.execute("INSERT INTO complaints(cid,user_id,name,student_id,department,title,description,category,priority,status,assigned_to,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f"CMP-{dt.year}-DEMO{i:02d}", uid, "Demo Student", "BT21CS001", rnd.choice(DEPARTMENTS[:6]), titles[cat],
                 "This issue has been affecting many students for the past few weeks and needs attention from the concerned team.",
                 cat, rnd.choice(PRIORITIES), st, ASSIGN_TO[CATEGORIES.index(cat)] if st != "Submitted" else None, ts, ts))
            c.execute("INSERT INTO updates(complaint_id,status,note,created_at) VALUES(?,?,?,?)", (cur.lastrowid, "Submitted", "Complaint received.", ts))
    c.commit(); c.close()

# ---------- security helpers ----------
@app.context_processor
def inject():
    if "csrf" not in session: session["csrf"] = secrets.token_hex(16)
    return dict(csrf_token=lambda: session["csrf"], CATEGORIES=CATEGORIES, PRIORITIES=PRIORITIES, STATUSES=STATUSES,
                DEPARTMENTS=DEPARTMENTS, ASSIGN_TO=ASSIGN_TO, role=session.get("role"), user_name=session.get("name"))

@app.before_request
def csrf_protect():
    if request.method == "POST" and not secrets.compare_digest(request.form.get("csrf_token", ""), session.get("csrf", "x")):
        abort(400, "Invalid or expired form token. Please reload the page and try again.")

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"; r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "same-origin"; return r

def login_required(role=None):
    def deco(f):
        @wraps(f)
        def wrap(*a, **k):
            if "uid" not in session:
                flash("Please log in to continue.", "danger")
                return redirect(url_for("admin_login" if role == "admin" else "login"))
            if role and session.get("role") != role: abort(403)
            return f(*a, **k)
        return wrap
    return deco

ATTEMPTS = {}
def locked(key):
    n, t = ATTEMPTS.get(key, (0, 0)); return n >= 5 and time.time() - t < 300
def fail(key): n, _ = ATTEMPTS.get(key, (0, 0)); ATTEMPTS[key] = (n + 1, time.time())

def stats():
    r = lambda s: q("SELECT COUNT(*) c FROM complaints WHERE status IN (%s)" % s, one=True)["c"]
    return dict(total=q("SELECT COUNT(*) c FROM complaints", one=True)["c"], resolved=r("'Resolved'"),
                pending=r("'Submitted','Under Review'"), progress=r("'In Progress'"), rejected=r("'Rejected'"))

# ---------- public pages ----------
@app.route("/")
def index(): return render_template("index.html", s=stats())

@app.route("/contact", methods=["POST"])
def contact():
    n, e, m = (request.form.get(k, "").strip() for k in ("name", "email", "message"))
    if not n or not re.match(r"[^@\s]+@[^@\s]+\.[^@\s]+$", e) or len(m) < 10:
        flash("Enter your name, a valid email and a message of at least 10 characters.", "danger")
    else:
        run("INSERT INTO feedback(name,email,message,created_at) VALUES(?,?,?,?)", (n[:80], e[:120], m[:1000], now()))
        flash("Thanks! Your message has reached the grievance cell.", "success")
    return redirect(url_for("index") + "#contact")

@app.route("/track")
def track():
    cid = request.args.get("cid", "").strip().upper(); c = hist = None
    if cid:
        c = q("SELECT * FROM complaints WHERE cid=?", (cid,), one=True)
        if c: hist = q("SELECT * FROM updates WHERE complaint_id=? ORDER BY id DESC", (c["id"],))
        else: flash(f"No complaint found with ID {cid}. Check the ID and try again.", "danger")
    return render_template("track.html", c=c, hist=hist, cid=cid)

# ---------- auth ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = {k: request.form.get(k, "").strip() for k in ("name", "email", "student_id", "department", "password", "confirm")}
        err = None
        if len(f["name"]) < 3: err = "Enter your full name."
        elif not re.match(r"[^@\s]+@[^@\s]+\.[^@\s]+$", f["email"]): err = "Enter a valid email address."
        elif not re.match(r"^[A-Za-z0-9\-/]{4,20}$", f["student_id"]): err = "Student ID must be 4-20 letters or digits."
        elif f["department"] not in DEPARTMENTS: err = "Select your department."
        elif len(f["password"]) < 8 or not re.search(r"\d", f["password"]) or not re.search(r"[A-Za-z]", f["password"]): err = "Password needs 8+ characters with letters and digits."
        elif f["password"] != f["confirm"]: err = "Passwords do not match."
        elif q("SELECT 1 FROM users WHERE email=?", (f["email"].lower(),), one=True): err = "That email is already registered. Log in instead."
        if err: flash(err, "danger"); return render_template("register.html", f=f)
        run("INSERT INTO users(name,email,password,role,student_id,department,created_at) VALUES(?,?,?,?,?,?,?)",
            (f["name"], f["email"].lower(), generate_password_hash(f["password"]), "student", f["student_id"].upper(), f["department"], now()))
        flash("Account created. You can log in now.", "success"); return redirect(url_for("login"))
    return render_template("register.html", f={})

def do_login(role, template, dest):
    if request.method == "POST":
        email, pw = request.form.get("email", "").strip().lower(), request.form.get("password", "")
        key = request.remote_addr + email
        if locked(key): flash("Too many failed attempts. Try again in 5 minutes.", "danger"); return render_template(template)
        u = q("SELECT * FROM users WHERE email=? AND role=?", (email, role), one=True)
        if u and check_password_hash(u["password"], pw):
            session.clear(); session.permanent = True
            session.update(uid=u["id"], role=u["role"], name=u["name"]); ATTEMPTS.pop(key, None)
            flash(f"Welcome back, {u['name'].split()[0]}!", "success"); return redirect(url_for(dest))
        fail(key); flash("Incorrect email or password.", "danger")
    return render_template(template)

@app.route("/login", methods=["GET", "POST"])
def login(): return do_login("student", "login.html", "dashboard")

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login(): return do_login("admin", "admin_login.html", "admin")

@app.route("/logout")
def logout(): session.clear(); flash("You have been logged out.", "success"); return redirect(url_for("index"))

# ---------- student ----------
@app.route("/dashboard")
@login_required("student")
def dashboard():
    u = q("SELECT * FROM users WHERE id=?", (session["uid"],), one=True)
    cs = q("SELECT * FROM complaints WHERE user_id=? ORDER BY id DESC", (u["id"],))
    mine = {k: sum(1 for c in cs if c["status"] in v) for k, v in
            dict(total=STATUSES, open=STATUSES[:3], resolved=["Resolved"]).items()}
    return render_template("dashboard.html", u=u, cs=cs, mine=mine)

@app.route("/submit", methods=["GET", "POST"])
@login_required("student")
def submit():
    u = q("SELECT * FROM users WHERE id=?", (session["uid"],), one=True)
    if request.method == "POST":
        f = {k: request.form.get(k, "").strip() for k in ("name", "student_id", "department", "title", "description", "category", "priority")}
        err = None
        if len(f["name"]) < 3: err = "Enter your name."
        elif not f["student_id"]: err = "Enter your student ID."
        elif f["department"] not in DEPARTMENTS: err = "Select a department."
        elif not 5 <= len(f["title"]) <= 120: err = "Title must be 5-120 characters."
        elif len(f["description"]) < 20: err = "Describe the problem in at least 20 characters."
        elif f["category"] not in CATEGORIES: err = "Select a category."
        elif f["priority"] not in PRIORITIES: err = "Select a priority."
        img, file = None, request.files.get("image")
        if not err and file and file.filename:
            ext = secure_filename(file.filename).rsplit(".", 1)[-1].lower()
            if ext not in IMG_EXT: err = "Upload a PNG, JPG, GIF or WEBP image."
            else:
                img = secrets.token_hex(8) + "." + ext; file.save(os.path.join(UPLOADS, img))
        if err: flash(err, "danger"); return render_template("submit.html", f=f)
        cid, ts = new_cid(), now()
        cur = run("INSERT INTO complaints(cid,user_id,name,student_id,department,title,description,category,priority,image,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (cid, u["id"], f["name"], f["student_id"].upper(), f["department"], f["title"], f["description"], f["category"], f["priority"], img, "Submitted", ts, ts))
        run("INSERT INTO updates(complaint_id,status,note,created_at) VALUES(?,?,?,?)", (cur, "Submitted", "Complaint received.", ts))
        flash(f"Complaint submitted. Your complaint ID is {cid}. Save it to track progress.", "success")
        return redirect(url_for("track", cid=cid))
    return render_template("submit.html", f=dict(name=u["name"], student_id=u["student_id"], department=u["department"]))

# ---------- admin ----------
def filtered():
    a, w, p = request.args, [], []
    if a.get("q"):
        like = f"%{a['q'].strip()}%"; w.append("(cid LIKE ? OR title LIKE ? OR description LIKE ? OR name LIKE ? OR student_id LIKE ?)"); p += [like] * 5
    for col in ("category", "department", "priority", "status"):
        if a.get(col): w.append(f"{col}=?"); p.append(a[col])
    sql = "SELECT * FROM complaints" + (" WHERE " + " AND ".join(w) if w else "") + " ORDER BY id DESC"
    return q(sql, p)

@app.route("/admin")
@login_required("admin")
def admin():
    return render_template("admin.html", s=stats(), rows=filtered(), a=request.args, qs=request.query_string.decode())

@app.route("/admin/complaint/<cid>", methods=["GET", "POST"])
@login_required("admin")
def admin_complaint(cid):
    c = q("SELECT * FROM complaints WHERE cid=?", (cid,), one=True) or abort(404)
    if request.method == "POST":
        st, to, note = request.form.get("status"), request.form.get("assigned_to", ""), request.form.get("note", "").strip()[:500]
        if st not in STATUSES or (to and to not in ASSIGN_TO): abort(400)
        run("UPDATE complaints SET status=?, assigned_to=?, updated_at=? WHERE id=?", (st, to or None, now(), c["id"]))
        run("INSERT INTO updates(complaint_id,status,note,created_at) VALUES(?,?,?,?)",
            (c["id"], st, note or f"Status changed to {st}." + (f" Assigned to {to}." if to else ""), now()))
        flash("Complaint updated.", "success"); return redirect(url_for("admin_complaint", cid=cid))
    stu = q("SELECT email FROM users WHERE id=?", (c["user_id"],), one=True)
    return render_template("admin_complaint.html", c=c, hist=q("SELECT * FROM updates WHERE complaint_id=? ORDER BY id DESC", (c["id"],)), stu=stu)

@app.route("/admin/export.csv")
@login_required("admin")
def export_csv():
    out = io.StringIO(); w = csv.writer(out)
    w.writerow(["Complaint ID", "Student", "Student ID", "Department", "Title", "Category", "Priority", "Status", "Assigned To", "Submitted", "Updated"])
    for c in filtered():
        w.writerow([c[k] for k in ("cid", "name", "student_id", "department", "title", "category", "priority", "status", "assigned_to", "created_at", "updated_at")])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=complaints_{datetime.now():%Y%m%d}.csv"})

@app.route("/admin/analytics")
@login_required("admin")
def analytics(): return render_template("analytics.html", s=stats())

@app.route("/admin/api/analytics")
@login_required("admin")
def api_analytics():
    grp = lambda col: {r["k"] or "Unassigned": r["n"] for r in q(f"SELECT {col} k, COUNT(*) n FROM complaints GROUP BY {col} ORDER BY n DESC")}
    months = {r["k"]: r["n"] for r in q("SELECT strftime('%Y-%m', created_at) k, COUNT(*) n FROM complaints GROUP BY k ORDER BY k DESC LIMIT 12")}
    return jsonify(category=grp("category"), status=grp("status"), department=grp("department"), assigned=grp("assigned_to"),
                   monthly=dict(sorted(months.items())), priority=grp("priority"))

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def err(e):
    msg = "Image too large (max 2 MB)." if e.code == 413 else getattr(e, "description", "Something went wrong.")
    return render_template("error.html", code=e.code, msg=msg), e.code

init_db()
if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=5000)
