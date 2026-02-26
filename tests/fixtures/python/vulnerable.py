"""Vulnerable Python code for testing."""

import os
import pickle
import subprocess
import tempfile
import yaml
import zipfile


# PY-001: zip path traversal
def extract_zip(path):
    with zipfile.ZipFile(path) as zf:
        zf.extractall("/tmp/output")


# PY-002: yaml unsafe load
def load_config(path):
    with open(path) as f:
        return yaml.load(f)


# PY-003: eval/exec
def compute(expr):
    return eval(expr)


def run_code(code):
    exec(code)


# PY-004: startswith path check
def is_safe_path(filepath, base_dir):
    return str(filepath).startswith(base_dir)


# PY-005: subprocess shell=True
def run_command(cmd):
    subprocess.run(cmd, shell=True)


# PY-006: hardcoded secrets
api_key = "sk-live-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"

# PY-007: SQL injection
def get_user(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return query


# PY-008: pickle load
def load_data(path):
    with open(path, "rb") as f:
        return pickle.load(f)


# PY-009: tempfile.mktemp
def get_temp():
    return tempfile.mktemp()
