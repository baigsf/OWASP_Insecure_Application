import base64
import hashlib
import os
import pickle
import random

import requests
import xml.etree.ElementTree as ET

from flask import Blueprint, request, jsonify, redirect
import yaml

api_bp = Blueprint("api", __name__)


# VULNERABILITY: SQL Injection
@api_bp.route("/api/users", methods=["GET"])
def api_users():
    name = request.args.get("name")
    import sqlite3
    conn = sqlite3.connect("/tmp/vuln.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return jsonify(cursor.fetchall())


# VULNERABILITY: SQL Injection
@api_bp.route("/api/delete_user", methods=["POST"])
def api_delete_user():
    user_id = request.form["id"]
    import sqlite3
    conn = sqlite3.connect("/tmp/vuln.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = " + user_id)
    conn.commit()
    return jsonify({"status": "deleted"})


# VULNERABILITY: Command Injection
@api_bp.route("/api/dns", methods=["GET"])
def api_dns():
    host = request.args.get("host")
    output = os.popen("nslookup " + host).read()
    return jsonify({"result": output})


# VULNERABILITY: Path Traversal
@api_bp.route("/api/read", methods=["GET"])
def api_read():
    path = request.args.get("path")
    with open("/var/app/data/" + path) as f:
        return jsonify({"content": f.read()})


# VULNERABILITY: SSRF
@api_bp.route("/api/proxy", methods=["GET"])
def api_proxy():
    url = request.args.get("url")
    r = requests.get(url)
    return jsonify({"body": r.text})


# VULNERABILITY: Reflected XSS
@api_bp.route("/api/greet", methods=["GET"])
def api_greet():
    name = request.args.get("name")
    return "<h1>Hello " + name + "</h1>"


# VULNERABILITY: Stored XSS
@api_bp.route("/api/comments", methods=["POST"])
def api_comments():
    text = request.form["text"]
    import sqlite3
    conn = sqlite3.connect("/tmp/vuln.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO comments (text) VALUES ('" + text + "')")
    conn.commit()
    return jsonify({"status": "ok"})


# VULNERABILITY: Open redirect
@api_bp.route("/api/redirect", methods=["GET"])
def api_redirect():
    url = request.args.get("url")
    return redirect(url)


# VULNERABILITY: Insecure deserialization
@api_bp.route("/api/load", methods=["POST"])
def api_load():
    data = base64.b64decode(request.data)
    obj = pickle.loads(data)
    return jsonify({"obj": str(obj)})


# VULNERABILITY: Unsafe YAML load
@api_bp.route("/api/yaml", methods=["POST"])
def api_yaml():
    obj = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify({"obj": str(obj)})


# VULNERABILITY: XXE
@api_bp.route("/api/xml", methods=["POST"])
def api_xml():
    tree = ET.parse(request.files["file"])
    return jsonify({"text": tree.getroot().text})


# VULNERABILITY: Weak hashing
@api_bp.route("/api/hash", methods=["POST"])
def api_hash():
    data = request.form["data"]
    return jsonify({"md5": hashlib.md5(data.encode()).hexdigest()})


# VULNERABILITY: Hardcoded admin key
@api_bp.route("/api/admin", methods=["GET"])
def api_admin():
    if request.headers.get("X-Admin-Key") == "hardcodedadminkey":
        return jsonify({"secret": "top secret"})
    return jsonify({"error": "forbidden"}), 403


# VULNERABILITY: Insecure random
@api_bp.route("/api/random", methods=["GET"])
def api_random():
    return jsonify({"value": random.randint(0, 1000000)})
