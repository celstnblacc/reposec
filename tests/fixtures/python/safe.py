"""Safe Python code for testing."""

import json
import os
import subprocess
import tempfile
from pathlib import Path

import yaml


# Safe: yaml.safe_load
def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f)


# Safe: yaml.load with SafeLoader
def load_config_v2(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.SafeLoader)


# Safe: is_relative_to for path checks
def is_safe_path(filepath, base_dir):
    return Path(filepath).resolve().is_relative_to(Path(base_dir).resolve())


# Safe: subprocess with list args
def run_command(args):
    subprocess.run(["ls", "-la"], shell=False)


# Safe: environment variable for secrets
api_key = os.environ.get("API_KEY")

# Safe: parameterized query
def get_user(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))


# Safe: json instead of pickle
def load_data(path):
    with open(path) as f:
        return json.load(f)


# Safe: NamedTemporaryFile
def get_temp():
    return tempfile.NamedTemporaryFile()
