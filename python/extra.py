import base64
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import urllib.request

import yaml
from flask import Blueprint, request, jsonify, redirect

extra_bp = Blueprint("extra", __name__)


def get_db():
    return sqlite3.connect("/tmp/vuln.db")


# VULNERABILITY: SQL Injection
@extra_bp.route("/extra/users", methods=["GET"])
def extra_users():
    name = request.args.get("name")
    cursor = get_db().cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return jsonify(cursor.fetchall())


# VULNERABILITY: SQL Injection
@extra_bp.route("/extra/delete", methods=["POST"])
def extra_delete():
    user_id = request.form["id"]
    cursor = get_db().cursor()
    cursor.execute("DELETE FROM users WHERE id = " + user_id)
    get_db().commit()
    return jsonify({"status": "deleted"})


# VULNERABILITY: Command Injection
@extra_bp.route("/extra/ping", methods=["GET"])
def extra_ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


# VULNERABILITY: Path Traversal
@extra_bp.route("/extra/read", methods=["GET"])
def extra_read():
    filename = request.args.get("file")
    with open("/var/app/data/" + filename) as f:
        return f.read()


# VULNERABILITY: SSRF
@extra_bp.route("/extra/fetch", methods=["GET"])
def extra_fetch():
    url = request.args.get("url")
    return urllib.request.urlopen(url).read()


# VULNERABILITY: Reflected XSS
@extra_bp.route("/extra/greet", methods=["GET"])
def extra_greet():
    name = request.args.get("name")
    return "<h1>Hello " + name + "</h1>"


# VULNERABILITY: Open redirect
@extra_bp.route("/extra/redirect", methods=["GET"])
def extra_redirect():
    return redirect(request.args.get("url"))


# VULNERABILITY: Insecure deserialization
@extra_bp.route("/extra/load", methods=["POST"])
def extra_load():
    return str(pickle.loads(base64.b64decode(request.data)))


# VULNERABILITY: Unsafe YAML
@extra_bp.route("/extra/yaml", methods=["POST"])
def extra_yaml():
    return str(yaml.load(request.data, Loader=yaml.Loader))


# VULNERABILITY: Weak hashing
@extra_bp.route("/extra/hash", methods=["POST"])
def extra_hash():
    return hashlib.md5(request.form["data"].encode()).hexdigest()


# VULNERABILITY: Insecure random
@extra_bp.route("/extra/token", methods=["GET"])
def extra_token():
    return str(random.randint(0, 1000000))


# VULNERABILITY: Eval
@extra_bp.route("/extra/eval", methods=["POST"])
def extra_eval():
    return str(eval(request.form["code"]))


# VULNERABILITY: Hardcoded admin key
@extra_bp.route("/extra/admin", methods=["GET"])
def extra_admin():
    if request.headers.get("X-Admin-Key") == "hardcodedadminkey":
        return jsonify({"secret": "classified"})
    return jsonify({"error": "forbidden"}), 403
