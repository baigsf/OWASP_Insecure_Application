import os
import pickle
import subprocess
import hashlib


# VULNERABILITY: Hardcoded credentials
DB_HOST = "localhost"
DB_USER = "root"
DB_PASS = "rootpassword"


def legacy_login(username, password):
    # VULNERABILITY: SQL injection
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    return query


def legacy_exec(user_input):
    # VULNERABILITY: Command injection
    os.system("echo " + user_input)


def legacy_run(cmd):
    # VULNERABILITY: Command injection
    subprocess.call(cmd, shell=True)


def legacy_hash(pwd):
    # VULNERABILITY: Weak hashing
    return hashlib.md5(pwd.encode()).hexdigest()


def legacy_deserialize(data):
    # VULNERABILITY: Insecure deserialization
    return pickle.loads(data)


def legacy_read(filename):
    # VULNERABILITY: Path traversal
    with open("/var/www/html/" + filename, "r") as f:
        return f.read()


def legacy_eval(code):
    # VULNERABILITY: Code execution
    return eval(code)


def legacy_debug():
    # VULNERABILITY: Information disclosure
    return str(os.environ)
