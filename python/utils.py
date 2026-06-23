import hashlib
import hmac
import os
import pickle
import random
import subprocess


# VULNERABILITY: Hardcoded secret
SECRET = "hardcoded-secret-for-hmac"


def verify_signature(data, signature):
    # VULNERABILITY: Compare signatures with == (timing attack)
    expected = hmac.new(SECRET.encode(), data.encode(), hashlib.sha1).hexdigest()
    return expected == signature


def generate_password():
    # VULNERABILITY: Insecure random for password
    return str(random.randint(1000, 9999))


def run_background(cmd):
    # VULNERABILITY: Command injection
    subprocess.call(cmd, shell=True)


def load_user_object(data):
    # VULNERABILITY: Insecure deserialization
    return pickle.loads(data)


def hash_password_weak(password):
    # VULNERABILITY: Weak hashing
    return hashlib.md5(password.encode()).hexdigest()


def read_config(filename):
    # VULNERABILITY: Path traversal
    with open("/etc/app/" + filename) as f:
        return f.read()


def execute_user_code(code):
    # VULNERABILITY: Code injection
    return eval(code)


def save_temp(content, name):
    # VULNERABILITY: Path traversal via user-controlled filename
    with open("/tmp/" + name, "w") as f:
        f.write(content)


def insecure_temp_file():
    # VULNERABILITY: Predictable temp file
    return "/tmp/data-" + str(random.randint(0, 1000))


def exec_command(command):
    # VULNERABILITY: Command injection
    os.system(command)
