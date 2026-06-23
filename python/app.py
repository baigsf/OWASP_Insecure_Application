import base64
import hashlib
import os
import pickle
import random
import subprocess
import sqlite3
import urllib.request
import xml.etree.ElementTree as ET

from flask import Flask, request, render_template_string, make_response, redirect, send_file
import yaml

app = Flask(__name__)

# VULNERABILITY: Hardcoded secret key
app.secret_key = "hardcoded-secret-key-for-development"

# VULNERABILITY: Hardcoded credentials
DB_PATH = "/tmp/vuln.db"
API_KEY = "sk-1234567890abcdef"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PASSWORD = "password123"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


# VULNERABILITY: SQL Injection
@app.route("/user")
def get_user():
    username = request.args.get("username")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")
    rows = cursor.fetchall()
    return str(rows)


# VULNERABILITY: SQL Injection
@app.route("/users/search")
def search_users():
    term = request.args.get("term")
    conn = get_db()
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name LIKE '%" + term + "%'"
    cursor.execute(query)
    return str(cursor.fetchall())


# VULNERABILITY: SQL Injection
@app.route("/users/order")
def order_users():
    column = request.args.get("column")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users ORDER BY " + column)
    return str(cursor.fetchall())


# VULNERABILITY: SQL Injection
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'")
    user = cursor.fetchone()
    if user:
        return "Logged in"
    return "Invalid"


# VULNERABILITY: Command Injection
@app.route("/ping")
def ping():
    host = request.args.get("host")
    result = subprocess.check_output("ping -c 1 " + host, shell=True)
    return result


# VULNERABILITY: Command Injection
@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    output = os.popen(cmd).read()
    return output


# VULNERABILITY: Path Traversal
@app.route("/read")
def read_file():
    filename = request.args.get("file")
    with open("/var/app/data/" + filename, "r") as f:
        return f.read()


# VULNERABILITY: Path Traversal
@app.route("/download")
def download_file():
    filename = request.args.get("file")
    return send_file("/var/app/uploads/" + filename)


# VULNERABILITY: SSRF
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    return urllib.request.urlopen(url).read()


# VULNERABILITY: Reflected XSS
@app.route("/greet")
def greet():
    name = request.args.get("name")
    return render_template_string("<h1>Hello " + name + "</h1>")


# VULNERABILITY: Reflected XSS
@app.route("/welcome")
def welcome():
    name = request.args.get("name")
    return "<script>alert('Welcome " + name + "');</script>"


# VULNERABILITY: Stored XSS
@app.route("/comment", methods=["POST"])
def comment():
    comment_text = request.form["comment"]
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO comments (text) VALUES ('" + comment_text + "')")
    conn.commit()
    return "Comment saved"


# VULNERABILITY: Stored XSS returned
@app.route("/comments")
def get_comments():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT text FROM comments")
    rows = cursor.fetchall()
    return "<br>".join([row[0] for row in rows])


# VULNERABILITY: Insecure deserialization (pickle)
@app.route("/load", methods=["POST"])
def load_pickle():
    data = base64.b64decode(request.data)
    obj = pickle.loads(data)
    return str(obj)


# VULNERABILITY: Unsafe YAML load
@app.route("/yaml", methods=["POST"])
def parse_yaml():
    obj = yaml.load(request.data, Loader=yaml.Loader)
    return str(obj)


# VULNERABILITY: XML External Entity (XXE)
@app.route("/xml", methods=["POST"])
def parse_xml():
    tree = ET.parse(request.files["file"])
    return tree.getroot().text


# VULNERABILITY: Open redirect
@app.route("/redirect")
def open_redirect():
    url = request.args.get("url")
    return redirect(url)


# VULNERABILITY: Weak password hashing (MD5)
@app.route("/hash", methods=["POST"])
def hash_md5():
    data = request.form["data"]
    return hashlib.md5(data.encode()).hexdigest()


# VULNERABILITY: Weak password hashing (SHA1)
@app.route("/hash/sha1", methods=["POST"])
def hash_sha1():
    data = request.form["data"]
    return hashlib.sha1(data.encode()).hexdigest()


# VULNERABILITY: Insecure random token
@app.route("/token")
def token():
    return str(random.randint(0, 1000000))


# VULNERABILITY: Hardcoded secret / weak JWT-like token
@app.route("/admin")
def admin():
    key = request.args.get("key")
    if key == "supersecretadminkey":
        return "Admin panel"
    return "Forbidden"


# VULNERABILITY: Verbose error / information disclosure
@app.route("/error")
def error():
    raise Exception("Detailed stack trace: " + str(request.__dict__))


# VULNERABILITY: Insecure cookie settings
@app.route("/setcookie")
def set_cookie():
    resp = make_response("Cookie set")
    resp.set_cookie("session", "insecure-value", secure=False, httponly=False, samesite=None)
    return resp


# VULNERABILITY: Missing authorization
@app.route("/admin/users")
def admin_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    return str(cursor.fetchall())


# VULNERABILITY: Insecure direct object reference
@app.route("/account/<int:id>")
def account(id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM accounts WHERE id = " + str(id))
    return str(cursor.fetchone())


# VULNERABILITY: Mass assignment
@app.route("/register", methods=["POST"])
def register():
    data = request.form
    conn = get_db()
    cursor = conn.cursor()
    # Allows setting 'admin' from form data
    cursor.execute(
        "INSERT INTO users (username, password, admin) VALUES (?, ?, ?)",
        (data["username"], data["password"], data.get("admin", "false"))
    )
    conn.commit()
    return "Registered"


# VULNERABILITY: Unrestricted file upload
@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    f.save("/var/app/uploads/" + f.filename)
    return "Uploaded"


# VULNERABILITY: Eval / code execution
@app.route("/eval", methods=["POST"])
def eval_code():
    code = request.form["code"]
    result = eval(code)
    return str(result)


# VULNERABILITY: Exec / code execution
@app.route("/exec", methods=["POST"])
def exec_code():
    code = request.form["code"]
    exec(code)
    return "Executed"


if __name__ == "__main__":
    # VULNERABILITY: Debug mode enabled
    app.run(debug=True, host="0.0.0.0", port=5000)
