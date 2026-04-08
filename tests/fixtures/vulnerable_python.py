"""Intentionally vulnerable Python code for testing VulnHawk."""

import hashlib
import os
import pickle
import sqlite3
import subprocess

import yaml

# --- IDOR / Missing Authorization ---

def get_user_profile(request):
    """Missing authorization check - any user can access any profile."""
    user_id = request.args.get("user_id")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return {"name": user["name"], "email": user["email"], "ssn": user["ssn"]}


def delete_account(request):
    """No auth check - anyone can delete any account."""
    account_id = request.json["account_id"]
    db = get_db()
    db.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
    db.commit()
    return {"status": "deleted"}


# --- SQL Injection ---

def search_users(query):
    """Classic SQL injection via string concatenation."""
    db = get_db()
    results = db.execute(f"SELECT * FROM users WHERE name LIKE '%{query}%'")
    return results.fetchall()


def login(username, password):
    """SQL injection in authentication."""
    db = get_db()
    sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    user = db.execute(sql).fetchone()
    return user


# --- Command Injection ---

def ping_host(hostname):
    """Command injection via shell=True."""
    result = subprocess.run(f"ping -c 1 {hostname}", shell=True, capture_output=True)
    return result.stdout.decode()


def convert_file(input_path, output_format):
    """Command injection via os.system."""
    os.system(f"convert {input_path} output.{output_format}")


# --- Hardcoded Secrets ---

API_KEY = "sk-ant-api03-real-key-here-1234567890abcdef"
DATABASE_URL = "postgresql://admin:SuperSecret123@prod-db.internal:5432/maindb"
JWT_SECRET = "my-jwt-secret-key-never-change-this"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


# --- Weak Cryptography ---

def hash_password(password):
    """MD5 for password hashing - critically weak."""
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password, stored_hash):
    """MD5 comparison for auth - trivially breakable."""
    return hashlib.md5(password.encode()).hexdigest() == stored_hash


# --- Insecure Deserialization ---

def load_user_data(serialized_data):
    """Pickle deserialization of untrusted data."""
    return pickle.loads(serialized_data)


def load_config(config_str):
    """Unsafe YAML load."""
    return yaml.load(config_str)


# --- Path Traversal ---

def serve_file(filename):
    """Path traversal via user-controlled filename."""
    base_dir = "/var/www/uploads"
    file_path = os.path.join(base_dir, filename)
    with open(file_path, "rb") as f:
        return f.read()


def download_attachment(request):
    """Path traversal - no sanitization of file parameter."""
    file_path = request.args.get("file")
    return open(f"/data/attachments/{file_path}", "rb").read()


# --- SSRF ---

def fetch_url(url):
    """SSRF - fetches arbitrary URLs from user input."""
    import requests
    response = requests.get(url)
    return response.text


def webhook_proxy(request):
    """SSRF via webhook URL."""
    import requests
    webhook_url = request.json["callback_url"]
    data = {"status": "complete", "result": request.json["data"]}
    requests.post(webhook_url, json=data)
    return {"sent": True}


# --- Helper (not vulnerable) ---

def get_db():
    return sqlite3.connect(":memory:")
