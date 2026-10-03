#!/usr/bin/env python3
"""Parse `aapt2 dump xmltree` output into an attack-surface table.

Reports exported components and, critically, which ones carry NO permission --
those are the zero-permission entry points worth testing.

aapt2 emits an `E: <tag>` line followed by that element's `A: ...` attribute
lines. Attributes are either
    A: android:name(0x01010003)="com.foo.Bar"
    A: http://schemas.android.com/apk/res/android:exported(0x01010010)=true
Both shapes are matched by ATTR_RE.
"""
import re
import subprocess
import sys
from pathlib import Path

BUILD_TOOLS = Path.home() / "Library/Android/sdk/build-tools/35.0.1/aapt2"
TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

ATTR_RE = re.compile(
    r'A: (?:http://schemas\.android\.com/apk/res/android:|android:)(\w+)\(0x[0-9a-f]+\)=(.*)$'
)


def attr_value(raw):
    """Strip the (Raw: "...") suffix aapt2 appends to string values."""
    return re.sub(r'\s*\(Raw: .*\)$', '', raw).strip().strip('"') or "true"


def dump(apk):
    out = subprocess.run(
        [str(BUILD_TOOLS), "dump", "xmltree", apk, "--file", "AndroidManifest.xml"],
        capture_output=True, text=True,
    )
    return out.stdout


def parse(tree):
    """Walk the flat element/attribute stream, assembling components + intent-filters.

    Returns an ordered list of component dicts:
        {tag, name, attrs:{}, filters:[{actions:[], data:{}, categories:[]}]}
    """
    comps, cur, filt, open_el = [], None, None, None

    for raw in tree.splitlines():
        line = raw.strip()
        m = re.match(r"E: (\S+)", line)
        if m:
            tag = m.group(1)
            if tag in TAGS:
                cur = {"tag": tag, "name": None, "attrs": {},
                       "filters": [], "meta": []}
                comps.append(cur)
                filt = open_el = None
                continue
            if tag == "intent-filter" and cur is not None:
                filt = {"actions": [], "data": {}, "categories": []}
                cur["filters"].append(filt)
                open_el = None
                continue
            if tag in ("data", "action", "category") and filt is not None:
                open_el = tag
                continue
            if tag == "meta-data" and cur is not None:
                open_el = "meta-data"
                continue
            # <queries>, <uses-permission>, ... irrelevant to the surface table
            open_el = None
            continue

        if cur is None:
            continue
        attrs = {k: attr_value(v) for k, v in ATTR_RE.findall(line)}
        if not attrs:
            continue

        # attributes of an <action>/<category>/<data> element just opened
        if open_el == "action" and "name" in attrs:
            filt["actions"].append(attrs["name"])
            open_el = None
            continue
        if open_el == "category" and "name" in attrs:
            filt["categories"].append(attrs["name"])
            open_el = None
            continue
        if open_el == "data":
            for k in ("scheme", "host", "port", "path", "pathPrefix",
                      "pathPattern", "mimeType"):
                if k in attrs:
                    filt["data"][k] = attrs[k]
            open_el = None
            continue
        if open_el == "meta-data":
            cur["meta"].append(attrs.get("name"))
            open_el = None
            continue

        cur["attrs"].update(attrs)
        if "name" in attrs and cur["name"] is None:
            cur["name"] = attrs["name"]
    return comps


def describe_filter(f):
    bits = []
    if f["actions"]:
        bits.append("actions=" + ",".join(a.split("/")[-1] for a in f["actions"][:3] if a))
    if f["data"]:
        bits.append("data=" + " ".join(f"{k}={v}" for k, v in f["data"].items()))
    if f["categories"]:
        bits.append("cat=" + ",".join(c.split(".")[-1] for c in f["categories"][:2] if c))
    return "  ".join(bits)


def main(apk):
    comps = parse(dump(apk))
    exported = [c for c in comps if c["attrs"].get("exported") == "true"]
    zero = [c for c in exported if not c["attrs"].get("permission")]
    nonprov = [c for c in zero if c["tag"] != "provider"]
    print(f"### {Path(apk).name}: {len(comps)} components, {len(exported)} exported, "
          f"{len(zero)} exported+no-permission ({len(nonprov)} non-provider)\n")
    for c in zero:
        print(f"[{c['tag']}] {c['name']}")
        for k in ("authorities", "readPermission", "writePermission", "grantUriPermissions"):
            if k in c["attrs"]:
                print(f"      {k}={c['attrs'][k]}")
        for f in c["filters"]:
            d = describe_filter(f)
            if d:
                print(f"      > {d}")
    print(f"\n-> {len(nonprov)} non-provider zero-perm entry points, "
          f"{len(zero) - len(nonprov)} zero-perm providers")


if __name__ == "__main__":
    for a in sys.argv[1:]:
        main(a)
        print()