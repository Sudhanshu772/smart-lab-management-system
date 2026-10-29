import csv
import io
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
SUBMISSIONS_DIR = DATA_DIR / "submissions"
DB_PATH = DATA_DIR / "smart_lab.db"
DATA_DIR.mkdir(exist_ok=True)
SUBMISSIONS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-development-secret")
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB request limit

LANGUAGES = {
    "Python": {"extension": ".py"},
    "C": {"extension": ".c"},
    "C++": {"extension": ".cpp"},
    "Java": {"extension": ".java"},
    "HTML": {"extension": ".html"},
}
RUN_TIMEOUT_SECONDS = 5


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('teacher','student')),
            teacher_code TEXT UNIQUE,
            teacher_id INTEGER REFERENCES users(id),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS labs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL REFERENCES users(id),
            lab_code TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            language TEXT NOT NULL,
            duration_minutes INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            ends_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS lab_students (
            lab_id INTEGER NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
            student_id INTEGER NOT NULL REFERENCES users(id),
            joined_at TEXT NOT NULL,
            PRIMARY KEY(lab_id, student_id)
        );
        CREATE TABLE IF NOT EXISTS run_checks (
            lab_id INTEGER NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
            student_id INTEGER NOT NULL REFERENCES users(id),
            code TEXT NOT NULL,
            output TEXT NOT NULL DEFAULT '',
            success INTEGER NOT NULL DEFAULT 0,
            checked_at TEXT NOT NULL,
            PRIMARY KEY(lab_id, student_id)
        );
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lab_id INTEGER NOT NULL REFERENCES labs(id),
            student_id INTEGER NOT NULL REFERENCES users(id),
            code TEXT NOT NULL,
            language TEXT NOT NULL,
            output TEXT NOT NULL DEFAULT '',
            run_success INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'Pending',
            marks INTEGER NOT NULL DEFAULT 0,
            teacher_feedback TEXT NOT NULL DEFAULT '',
            submitted_at TEXT NOT NULL,
            UNIQUE(lab_id, student_id)
        );
        """)


def now():
    return datetime.now()


def timestamp(dt=None):
    return (dt or now()).isoformat(timespec="seconds")


def make_unique_code(db, column, table, length=6):
    # Codes are generated from digits only for teacher codes and alphanumeric for lab codes.
    alphabet = "0123456789" if table == "users" else "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    while True:
        code = "".join(secrets.choice(alphabet) for _ in range(length))
        if not db.execute(f"SELECT 1 FROM {table} WHERE {column}=?", (code,)).fetchone():
            return code


def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def current_user():
    if "user_id" not in session:
        return None
    with get_db() as db:
        return db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()


def get_lab_for_teacher(lab_id, teacher_id):
    with get_db() as db:
        lab = db.execute("SELECT * FROM labs WHERE id=? AND teacher_id=?", (lab_id, teacher_id)).fetchone()
    if not lab:
        abort(404)
    return lab


def get_lab_for_student(lab_id, student_id):
    with get_db() as db:
        lab = db.execute("""
            SELECT l.* FROM labs l JOIN lab_students ls ON ls.lab_id=l.id
            WHERE l.id=? AND ls.student_id=?
        """, (lab_id, student_id)).fetchone()
    if not lab:
        abort(403)
    return lab


def run_code(language, code):
    """
    LOCAL-DEMO RUNNER ONLY. subprocess is not a secure sandbox for hostile code.
    For real deployment, run every submission in a disposable, unprivileged Docker
    container with no network, strict CPU/memory/process limits, and a read-only
    filesystem. Do not expose this demo server to the public internet.
    """
    if language not in LANGUAGES:
        return False, "Unsupported language."
    workdir = Path(tempfile.mkdtemp(prefix="labrun_"))
    try:
        if language == "HTML":
            # HTML is rendered as source text/output in this starter; it is not executed.
            return True, "HTML file saved successfully. Preview it from the editor."
        if language == "Python":
            source = workdir / "main.py"
            source.write_text(code, encoding="utf-8")
            command = ["python", str(source)]
        elif language == "C":
            source = workdir / "main.c"
            binary = workdir / "main"
            source.write_text(code, encoding="utf-8")
            compiled = subprocess.run(["gcc", str(source), "-o", str(binary)],
                                      capture_output=True, text=True, timeout=RUN_TIMEOUT_SECONDS,
                                      cwd=workdir)
            if compiled.returncode != 0:
                return False, (compiled.stderr or compiled.stdout or "Compilation failed.")[:8000]
            command = [str(binary)]
        elif language == "C++":
            source = workdir / "main.cpp"
            binary = workdir / "main"
            source.write_text(code, encoding="utf-8")
            compiled = subprocess.run(["g++", str(source), "-o", str(binary)],
                                      capture_output=True, text=True, timeout=RUN_TIMEOUT_SECONDS,
                                      cwd=workdir)
            if compiled.returncode != 0:
                return False, (compiled.stderr or compiled.stdout or "Compilation failed.")[:8000]
            command = [str(binary)]
        else:  # Java
            source = workdir / "Main.java"
            source.write_text(code, encoding="utf-8")
            compiled = subprocess.run(["javac", str(source)], capture_output=True, text=True,
                                      timeout=RUN_TIMEOUT_SECONDS, cwd=workdir)
            if compiled.returncode != 0:
                return False, (compiled.stderr or compiled.stdout or "Compilation failed.")[:8000]
            command = ["java", "-cp", str(workdir), "Main"]

        result = subprocess.run(command, capture_output=True, text=True, timeout=RUN_TIMEOUT_SECONDS,
                                cwd=workdir, input="", env={"PATH": os.environ.get("PATH", "")})
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0:
            return True, output[:8000] or "Program ran successfully (no output)."
        return False, output[:8000] or f"Program exited with code {result.returncode}."
    except subprocess.TimeoutExpired:
        return False, f"Execution timed out after {RUN_TIMEOUT_SECONDS} seconds."
    except FileNotFoundError as exc:
        return False, f"Required compiler/interpreter not found: {exc.filename}. Install it and restart."
    except Exception as exc:
        return False, f"Could not run code: {exc}"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@app.route("/")
def index():
    if session.get("role") == "teacher":
        return redirect(url_for("teacher_dashboard"))
    if session.get("role") == "student":
        return redirect(url_for("student_dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "")
        teacher_code = request.form.get("teacher_code", "").strip()
        if not name or not email or len(password) < 8 or role not in ("teacher", "student"):
            flash("Enter all details. Password must be at least 8 characters.", "danger")
            return render_template("register.html")
        with get_db() as db:
            teacher_id = None
            if role == "student":
                if not re.fullmatch(r"\d{6}", teacher_code):
                    flash("Enter the teacher's 6-digit code.", "danger")
                    return render_template("register.html")
                teacher = db.execute("SELECT id FROM users WHERE role='teacher' AND teacher_code=?",
                                     (teacher_code,)).fetchone()
                if not teacher:
                    flash("That Teacher Code was not found.", "danger")
                    return render_template("register.html")
                teacher_id = teacher["id"]
            try:
                code = make_unique_code(db, "teacher_code", "users") if role == "teacher" else None
                cur = db.execute("""
                    INSERT INTO users(name,email,password_hash,role,teacher_code,teacher_id,created_at)
                    VALUES(?,?,?,?,?,?,?)
                """, (name, email, generate_password_hash(password), role, code, teacher_id, timestamp()))
                user_id = cur.lastrowid
            except sqlite3.IntegrityError:
                flash("That email is already registered.", "danger")
                return render_template("register.html")
        flash(f"Registration successful. Your Teacher Code is {code}." if code else
              "Registration successful. Log in to continue.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.", "danger")
            return render_template("login.html")
        session.clear()
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        session["name"] = user["name"]
        return redirect(url_for("teacher_dashboard" if user["role"] == "teacher" else "student_dashboard"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.route("/teacher")
@login_required("teacher")
def teacher_dashboard():
    with get_db() as db:
        labs = db.execute("""
            SELECT l.*, (SELECT COUNT(*) FROM lab_students ls WHERE ls.lab_id=l.id) AS student_count,
            (SELECT COUNT(*) FROM submissions s WHERE s.lab_id=l.id) AS submission_count
            FROM labs l WHERE l.teacher_id=? ORDER BY l.id DESC
        """, (session["user_id"],)).fetchall()
        user = db.execute("SELECT teacher_code FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return render_template("teacher_dashboard.html", labs=labs, teacher_code=user["teacher_code"], now=now())


@app.route("/teacher/labs/create", methods=["GET", "POST"])
@login_required("teacher")
def create_lab():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        language = request.form.get("language", "")
        try:
            duration = int(request.form.get("duration", "0"))
        except ValueError:
            duration = 0
        if not name or language not in LANGUAGES or not 1 <= duration <= 360:
            flash("Enter a lab name, supported language, and duration from 1 to 360 minutes.", "danger")
            return render_template("create_lab.html", languages=LANGUAGES)
        with get_db() as db:
            code = make_unique_code(db, "lab_code", "labs", 8)
            start = now()
            end = start + timedelta(minutes=duration)
            db.execute("""INSERT INTO labs(teacher_id,lab_code,name,language,duration_minutes,created_at,ends_at)
                          VALUES(?,?,?,?,?,?,?)""",
                       (session["user_id"], code, name, language, duration, timestamp(start), timestamp(end)))
        flash(f"Lab created. Share Lab Code: {code}", "success")
        return redirect(url_for("teacher_dashboard"))
    return render_template("create_lab.html", languages=LANGUAGES)


@app.route("/student")
@login_required("student")
def student_dashboard():
    with get_db() as db:
        labs = db.execute("""
            SELECT l.*, u.name AS teacher_name,
            s.status AS submission_status, s.marks AS marks
            FROM labs l JOIN lab_students ls ON ls.lab_id=l.id
            JOIN users u ON u.id=l.teacher_id
            LEFT JOIN submissions s ON s.lab_id=l.id AND s.student_id=?
            WHERE ls.student_id=? ORDER BY l.id DESC
        """, (session["user_id"], session["user_id"])).fetchall()
    return render_template("student_dashboard.html", labs=labs, now=now())


@app.route("/student/join", methods=["POST"])
@login_required("student")
def join_lab():
    code = request.form.get("lab_code", "").strip().upper()
    with get_db() as db:
        lab = db.execute("SELECT * FROM labs WHERE lab_code=?", (code,)).fetchone()
        if not lab:
            flash("Lab Code was not found.", "danger")
        elif lab["teacher_id"] != db.execute("SELECT teacher_id FROM users WHERE id=?",
                                             (session["user_id"],)).fetchone()["teacher_id"]:
            flash("This lab belongs to a different teacher than the one linked to your account.", "danger")
        elif not lab["is_active"] or now() > datetime.fromisoformat(lab["ends_at"]):
            flash("This lab session has ended.", "warning")
        else:
            db.execute("INSERT OR IGNORE INTO lab_students(lab_id,student_id,joined_at) VALUES(?,?,?)",
                       (lab["id"], session["user_id"], timestamp()))
            flash("You joined the lab.", "success")
            return redirect(url_for("student_lab", lab_id=lab["id"]))
    return redirect(url_for("student_dashboard"))


@app.route("/student/lab/<int:lab_id>")
@login_required("student")
def student_lab(lab_id):
    lab = get_lab_for_student(lab_id, session["user_id"])
    with get_db() as db:
        submission = db.execute("SELECT * FROM submissions WHERE lab_id=? AND student_id=?",
                                (lab_id, session["user_id"])).fetchone()
    default_code = {
        "Python": 'print("Hello, world!")',
        "C": '#include <stdio.h>\nint main(void) {\n    printf("Hello, world!\\\\n");\n    return 0;\n}',
        "C++": '#include <iostream>\nint main() {\n    std::cout << "Hello, world!" << std::endl;\n    return 0;\n}',
        "Java": 'public class Main {\n    public static void main(String[] args) {\n        System.out.println("Hello, world!");\n    }\n}',
        "HTML": '<!doctype html>\n<html><head><title>My page</title></head><body><h1>Hello, world!</h1></body></html>',
    }
    return render_template("student_lab.html", lab=lab, submission=submission,
                           default_code=default_code[lab["language"]],
                           expired=(now() > datetime.fromisoformat(lab["ends_at"]) or not lab["is_active"]))


@app.route("/student/lab/<int:lab_id>/run", methods=["POST"])
@login_required("student")
def run_student_code(lab_id):
    lab = get_lab_for_student(lab_id, session["user_id"])
    if now() > datetime.fromisoformat(lab["ends_at"]) or not lab["is_active"]:
        return {"success": False, "output": "This lab session has ended."}, 400
    payload = request.get_json(silent=True) or {}
    code = payload.get("code", "")
    if not isinstance(code, str) or not code.strip() or len(code) > 50000:
        return {"success": False, "output": "Enter code (maximum 50,000 characters)."}, 400
    success, output = run_code(lab["language"], code)
    # Store run validation server-side; do not put submitted source code in the cookie session.
    with get_db() as db:
        db.execute("""
            INSERT INTO run_checks(lab_id,student_id,code,output,success,checked_at)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(lab_id,student_id) DO UPDATE SET
              code=excluded.code, output=excluded.output, success=excluded.success,
              checked_at=excluded.checked_at
        """, (lab_id, session["user_id"], code, output, int(success), timestamp()))
    return {"success": success, "output": output}


@app.route("/student/lab/<int:lab_id>/submit", methods=["POST"])
@login_required("student")
def submit_student_code(lab_id):
    lab = get_lab_for_student(lab_id, session["user_id"])
    if now() > datetime.fromisoformat(lab["ends_at"]) or not lab["is_active"]:
        flash("This lab session has ended.", "danger")
        return redirect(url_for("student_lab", lab_id=lab_id))
    code = request.form.get("code", "")
    with get_db() as db:
        check = db.execute("SELECT * FROM run_checks WHERE lab_id=? AND student_id=?",
                           (lab_id, session["user_id"])).fetchone()
    if not check or not check["success"] or check["code"] != code:
        flash("Run the current version successfully before submitting.", "danger")
        return redirect(url_for("student_lab", lab_id=lab_id))
    output = check["output"] or ""
    student_dir = SUBMISSIONS_DIR / f"student_{session['user_id']}" / f"lab_{lab_id}"
    student_dir.mkdir(parents=True, exist_ok=True)
    filename = "submission" + LANGUAGES[lab["language"]]["extension"]
    (student_dir / filename).write_text(code, encoding="utf-8")
    with get_db() as db:
        db.execute("""
            INSERT INTO submissions(lab_id,student_id,code,language,output,run_success,status,submitted_at)
            VALUES(?,?,?,?,?,1,'Pending',?)
            ON CONFLICT(lab_id,student_id) DO UPDATE SET
              code=excluded.code, language=excluded.language, output=excluded.output,
              run_success=1, status='Pending', marks=0, teacher_feedback='', submitted_at=excluded.submitted_at
        """, (lab_id, session["user_id"], code, lab["language"], output, timestamp()))
    with get_db() as db:
        db.execute("DELETE FROM run_checks WHERE lab_id=? AND student_id=?",
                   (lab_id, session["user_id"]))
    flash("Code submitted successfully.", "success")
    return redirect(url_for("student_lab", lab_id=lab_id))


@app.route("/teacher/lab/<int:lab_id>")
@login_required("teacher")
def teacher_lab(lab_id):
    lab = get_lab_for_teacher(lab_id, session["user_id"])
    with get_db() as db:
        students = db.execute("""
            SELECT u.id AS student_id, u.name, u.email, s.id AS submission_id, s.code,
                   s.output, s.status, s.marks, s.teacher_feedback, s.submitted_at
            FROM lab_students ls JOIN users u ON u.id=ls.student_id
            LEFT JOIN submissions s ON s.lab_id=ls.lab_id AND s.student_id=ls.student_id
            WHERE ls.lab_id=? ORDER BY u.name
        """, (lab_id,)).fetchall()
        submitted = db.execute("SELECT COUNT(*) FROM submissions WHERE lab_id=?", (lab_id,)).fetchone()[0]
    return render_template("teacher_lab.html", lab=lab, students=students,
                           submitted=submitted, total=len(students))


@app.route("/teacher/lab/<int:lab_id>/grade/<int:student_id>", methods=["POST"])
@login_required("teacher")
def grade_submission(lab_id, student_id):
    get_lab_for_teacher(lab_id, session["user_id"])
    status = request.form.get("status", "")
    feedback = request.form.get("feedback", "").strip()[:1000]
    if status not in ("Correct", "Incorrect"):
        flash("Choose Correct or Incorrect.", "danger")
    else:
        marks = 1 if status == "Correct" else 0
        with get_db() as db:
            result = db.execute("""
                UPDATE submissions SET status=?, marks=?, teacher_feedback=?
                WHERE lab_id=? AND student_id=?
            """, (status, marks, feedback, lab_id, student_id))
        flash("Grade saved." if result.rowcount else "This student has not submitted code.", 
              "success" if result.rowcount else "warning")
    return redirect(url_for("teacher_lab", lab_id=lab_id))


@app.route("/teacher/lab/<int:lab_id>/marks.csv")
@login_required("teacher")
def export_marks(lab_id):
    lab = get_lab_for_teacher(lab_id, session["user_id"])
    with get_db() as db:
        rows = db.execute("""
            SELECT u.name, u.email, COALESCE(s.status,'Not submitted') AS status,
                   COALESCE(s.marks,0) AS marks, COALESCE(s.teacher_feedback,'') AS feedback,
                   COALESCE(s.submitted_at,'') AS submitted_at
            FROM lab_students ls JOIN users u ON u.id=ls.student_id
            LEFT JOIN submissions s ON s.lab_id=ls.lab_id AND s.student_id=ls.student_id
            WHERE ls.lab_id=? ORDER BY u.name
        """, (lab_id,)).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Student Name", "Email", "Status", "Marks (out of 1)", "Teacher Feedback", "Submitted At"])
    for row in rows:
        writer.writerow(list(row))
    binary = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    binary.seek(0)
    return send_file(binary, mimetype="text/csv", as_attachment=True,
                     download_name=f"{secure_filename(lab['name'])}_marks.csv")


@app.route("/teacher/lab/<int:lab_id>/close", methods=["POST"])
@login_required("teacher")
def close_lab(lab_id):
    get_lab_for_teacher(lab_id, session["user_id"])
    with get_db() as db:
        db.execute("UPDATE labs SET is_active=0 WHERE id=?", (lab_id,))
    flash("Lab session closed.", "success")
    return redirect(url_for("teacher_lab", lab_id=lab_id))


@app.route("/api/teacher/lab/<int:lab_id>/stats")
@login_required("teacher")
def lab_stats(lab_id):
    get_lab_for_teacher(lab_id, session["user_id"])
    with get_db() as db:
        total = db.execute("SELECT COUNT(*) FROM lab_students WHERE lab_id=?", (lab_id,)).fetchone()[0]
        submitted = db.execute("SELECT COUNT(*) FROM submissions WHERE lab_id=?", (lab_id,)).fetchone()[0]
        graded = db.execute("SELECT COUNT(*) FROM submissions WHERE lab_id=? AND status IN ('Correct','Incorrect')",
                            (lab_id,)).fetchone()[0]
    return {"total": total, "submitted": submitted, "not_submitted": total - submitted, "graded": graded}


@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="The requested page was not found."), 404


init_db()

if __name__ == "__main__":
    # For local development only. Do not use Flask's development server in production.
    app.run(debug=True)
