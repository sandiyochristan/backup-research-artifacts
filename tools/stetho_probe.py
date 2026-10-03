#!/usr/bin/env python3
"""Probe a local (on-device) Stetho DevTools abstract socket.

Stetho's server speaks the Chrome DevTools Protocol framed over the socket.
Abstract UNIX sockets live in a global namespace with no filesystem path, so
`nc -U /name` cannot reach them -- we connect to the raw abstract address.

Usage: pushed to /data/local/tmp, run as:  sh stetho_probe.sh <socket-name>
"""
import socket
import sys
import json

SOCK = sys.argv[1] if len(sys.argv) > 1 else \
    "stetho_com.google.android.apps.messaging_devtools_remote"

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(8)
try:
    s.connect("\0" + SOCK)
    print("CONNECTED %s" % SOCK)

    def send(obj):
        # Stetho frames CDP messages as a 4-byte big-endian length + JSON body
        body = json.dumps(obj).encode()
        s.sendall(len(body).to_bytes(4, "big") + body)

    def recv():
        hdr = b""
        while len(hdr) < 4:
            c = s.recv(4 - len(hdr))
            if not c:
                raise EOFError("short header")
            hdr += c
        n = int.from_bytes(hdr, "big")
        buf = b""
        while len(buf) < n:
            c = s.recv(n - len(buf))
            if not c:
                raise EOFError("short body")
            buf += c
        return buf.decode(errors="replace")

    send({"id": 1, "method": "Target.getTargets"})
    for _ in range(6):
        print("<<", recv()[:1200])
except Exception as e:
    print("ERR %s: %s" % (type(e).__name__, e))