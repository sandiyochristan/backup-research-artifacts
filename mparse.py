#!/usr/bin/env python3
"""aapt2 xmltree AndroidManifest.xml -> structured JSON (correct indent-aware parse)."""
import json
import re
import subprocess
import sys

import os
AAPT2 = os.path.expanduser("~/Library/Android/sdk/build-tools/35.0.1/aapt2")
E_RE = re.compile(r'^\s*E:\s*([^\s(]+)')
A_RE = re.compile(r'^\s*A:\s*([^(\s]+)[^=]*=\s*(.*)$')
NAME_RE = re.compile(r'^([A-Za-z_][\w.\-]*)=')

COMP_TAGS = {"activity", "activity-alias", "service", "receiver", "provider"}
PERM_TAGS = {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}
IF_TAGS = {"intent-filter"}
SCHEME_TAGS = {"data", "action", "category"}


def clean(v):
    v = v.strip()
    m = re.match(r'^"(.*)"\s*\(Raw:.*$', v, re.S)
    if m:
        return m.group(1)
    return v.strip('"')


def parse(xmltree_text):
    root = []
    stack = []  # list of (indent, node)
    for ln in xmltree_text.splitlines():
        m = E_RE.match(ln)
        if m:
            indent = len(ln) - len(ln.lstrip())
            while stack and stack[-1][0] >= indent:
                stack.pop()
            tag = m.group(1)
            node = {"tag": tag, "indent": indent, "attrs": {}, "children": []}
            if stack:
                stack[-1][1]["children"].append(node)
            else:
                root.append(node)
            stack.append((indent, node))
            continue
        m = A_RE.match(ln)
        if m and stack:
            key = m.group(1)
            key = key.split(":")[-1] if key.startswith("http") else key
            stack[-1][1]["attrs"][key] = clean(m.group(2))
    return root


def name_of(node):
    v = node["attrs"].get("name", "")
    if v.startswith("com.google.") or True:
        pass
    return v


def walk(node, cb):
    cb(node)
    for c in node["children"]:
        walk(c, cb)


def is_exported(node):
    """Android: explicit exported attr wins; else implicit true if intent-filter present."""
    ex = node["attrs"].get("exported")
    if ex in ("true", "false"):
        return ex == "true"
    has_if = any(c["tag"] == "intent-filter" for c in node["children"])
    return has_if


def component_record(node):
    rec = {
        "type": node["tag"],
        "name": name_of(node),
        "exported": is_exported(node),
        "permission": node["attrs"].get("permission"),
        "readPermission": node["attrs"].get("readPermission"),
        "writePermission": node["attrs"].get("writePermission"),
        "grantUriPermissions": node["attrs"].get("grantUriPermissions"),
        "directBootAware": node["attrs"].get("directBootAware"),
        "taskAffinity": node["attrs"].get("taskAffinity"),
        "launchMode": node["attrs"].get("launchMode"),
        "excludeFromRecents": node["attrs"].get("excludeFromRecents"),
        "process": node["attrs"].get("process"),
        "authorities": None,
        "actions": [],
        "categories": [],
        "schemes": [],
        "hosts": [],
        "paths": [],
        "mimes": [],
    }
    def visit(n):
        if n["tag"] == "intent-filter":
            for c in n["children"]:
                if c["tag"] == "action":
                    rec["actions"].append(c["attrs"].get("name", "?"))
                elif c["tag"] == "category":
                    rec["categories"].append(c["attrs"].get("name", "?"))
                elif c["tag"] == "data":
                    for k, dest in (("scheme", "schemes"), ("host", "hosts"),
                                    ("path", "paths"), ("pathPrefix", "paths"),
                                    ("pathPattern", "paths"),
                                    ("mimeType", "mimes")):
                        if k in c["attrs"]:
                            rec[dest].append(c["attrs"][k])
    for c in node["children"]:
        walk(c, visit)
    return rec


def dump(apk):
    r = subprocess.run([AAPT2, "dump", "xmltree",
                        "--file", "AndroidManifest.xml", apk],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return {"error": r.stderr[:300], "permissions": [], "components": []}
    root = parse(r.stdout)
    perms, comps, queries = [], [], []
    manifest_attrs = {}
    for top in root:
        if top["tag"] != "manifest":
            continue
        manifest_attrs = dict(top["attrs"])
        for c in top["children"]:
            if c["tag"] in PERM_TAGS:
                perms.append(c["attrs"].get("name", ""))
            elif c["tag"] == "queries":
                for q in c["children"]:
                    if q["tag"] == "package":
                        queries.append(q["attrs"].get("name"))
                    elif q["tag"] == "intent":
                        for ic in q["children"]:
                            if ic["tag"] == "action":
                                queries.append("action:" + ic["attrs"].get("name", ""))
            elif c["tag"] == "application":
                for comp in c["children"]:
                    if comp["tag"] in COMP_TAGS:
                        comps.append(component_record(comp))
    return {"package": manifest_attrs.get("package"),
            "versionName": manifest_attrs.get("versionName"),
            "targetSdk": manifest_attrs.get("targetSdkVersion"),
            "permissions": sorted(set(x for x in perms if x)),
            "components": comps,
            "queries": sorted(set(x for x in queries if x))}


if __name__ == "__main__":
    out = [dump(a) for a in sys.argv[1:]]
    json.dump(out, open("manifests/parsed.json", "w"), indent=1)
    for d in out:
        if "error" in d:
            print("ERR", d["error"])
            continue
        exp = [c for c in d["components"] if c["exported"]]
        print(f"\n{'='*100}\n### {d['package']}  v{d['versionName']}  targetSdk={d['targetSdk']}")
        print(f"    components={len(d['components'])} exported={len(exp)}")
        sens = [p for p in d["permissions"] if any(k in p for k in (
            "READ_", "WRITE_", "MANAGE_", "ACCESS_", "BIND_", "CALL_", "RECORD_",
            "CAMERA", "LOCATION", "CONTACTS", "SMS", "PHONE", "ACCOUNT",
            "AUTHENTICATE", "BODY_SENSORS", "ACTIVITY_RECOGNITION", "INJECT_EVENTS",
            "PACKAGE_USAGE_STATS", "BIND_DEVICE_ADMIN", "BIND_ACCESSIBILITY",
            "BIND_NOTIFICATION", "REQUEST_INSTALL"))]
        if sens:
            print("  SENSITIVE PERMS: " + ", ".join(s.split(".")[-1] for s in sens))
        for c in exp:
            print(f"  [{c['type']:14}] {c['name']}")
            det = " ".join(f"{k}={c[k]}" for k in (
                "permission", "readPermission", "writePermission",
                "grantUriPermissions", "directBootAware", "launchMode",
                "excludeFromRecents", "taskAffinity", "process") if c[k])
            print(f"       {det}")
            if c["actions"]:
                print(f"       actions={c['actions']}")
            if c["schemes"] or c["hosts"]:
                print(f"       data schemes={c['schemes']} hosts={c['hosts']} paths={c['paths']} mimes={c['mimes']}")
            if c["categories"]:
                print(f"       cats={c['categories']}")