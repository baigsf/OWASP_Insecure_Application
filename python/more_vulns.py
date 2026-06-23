import hashlib
import os
import pickle
import random
import subprocess


# VULNERABILITY: Hardcoded secrets
DB_PASSWORD = "SuperSecretPassword123!"
API_KEY = "sk-1234567890abcdef"


def query_user(name):
    # VULNERABILITY: SQL injection
    import sqlite3
    conn = sqlite3.connect("/tmp/vuln.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cursor.fetchall()


def delete_user(user_id):
    # VULNERABILITY: SQL injection
    import sqlite3
    conn = sqlite3.connect("/tmp/vuln.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = " + user_id)
    conn.commit()


def exec_cmd(cmd):
    # VULNERABILITY: Command injection
    os.system(cmd)


def run_cmd_safe_check(cmd):
    # VULNERABILITY: Command injection
    subprocess.call(cmd, shell=True)


def read_config(name):
    # VULNERABILITY: Path traversal
    with open("/etc/app/" + name) as f:
        return f.read()


def deserialize(data):
    # VULNERABILITY: Insecure deserialization
    return pickle.loads(data)


def hash_weak(data):
    # VULNERABILITY: Weak hashing
    return hashlib.md5(data.encode()).hexdigest()


def generate_pin():
    # VULNERABILITY: Insecure random
    return random.randint(1000, 9999)


def eval_user_code(code):
    # VULNERABILITY: Code execution
    return eval(code)
