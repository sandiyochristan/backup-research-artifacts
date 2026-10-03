#!/usr/bin/env python3
"""Minimal Obsidian Local REST API helper (no deps)."""
import json
import ssl
import sys
import urllib.request
import urllib.parse

API = "https://127.0.0.1:27124"
KEY = "9341a691f70b081860a8c23cfd60057d15add58928d51a393f3720f2fc99a202"
VAULT = "Android-Security-Research"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def _req(method, path, data=None):
    url = f"{API}{path}"
    body = data.encode() if isinstance(data, str) else data
    r = urllib.request.Request(url, data=body, method=method)
    r.add_header("Authorization", f"Bearer {KEY}")
    if body is not None:
        r.add_header("Content-Type", "text/markdown")
    with urllib.request.urlopen(r, context=CTX, timeout=30) as resp:
        return resp.read().decode("utf-8", "replace")


def read(path):
    """path relative to vault root (without VAULT prefix) or absolute with vault."""
    p = path.lstrip("/")
    if not p.startswith(VAULT):
        p = f"{VAULT}/{p}"
    raw = _req("GET", "/vault/" + urllib.parse.quote(p))
    try:
        return json.loads(raw).get("content", raw)
    except Exception:
        return raw


def ls(path=""):
    p = path.lstrip("/")
    if p and not p.startswith(VAULT):
        p = f"{VAULT}/{p}"
    if not p.endswith("/"):
        p += "/"
    try:
        raw = _req("GET", "/vault/" + urllib.parse.quote(p))
    except Exception:
        return []
    try:
        return json.loads(raw).get("files", [])
    except Exception:
        return []


def write(path, content):
    p = path.lstrip("/")
    if not p.startswith(VAULT):
        p = f"{VAULT}/{p}"
    return _req("PUT", "/vault/" + urllib.parse.quote(p), content)


def append(path, content):
    p = path.lstrip("/")
    if not p.startswith(VAULT):
        p = f"{VAULT}/{p}"
    return _req("POST", "/vault/" + urllib.parse.quote(p), content)


def search(q):
    raw = _req("POST", "/search/simple/", json.dumps({"query": q}))
    try:
        return json.loads(raw)
    except Exception:
        return []


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "read":
        print(read(sys.argv[2]))
    elif cmd == "ls":
        for f in ls(sys.argv[2] if len(sys.argv) > 2 else ""):
            print(f)
    elif cmd == "search":
        print(json.dumps(search(" ".join(sys.argv[2:])), indent=1)[:8000])