# Obsidian Research Tracker — Agent Reference

## Purpose

The Obsidian tracker prevents duplicate testing and maintains a persistent research journal across sessions. **Every test, finding, and chain MUST be logged.** Before running any test, the agent MUST check whether it was already done.

## Connection

The tracker connects to Obsidian's Local REST API running on the researcher's machine.

```
URL:  https://127.0.0.1:27124
Auth: Bearer 9341a691f70b081860a8c23cfd60057d15add58928d51a393f3720f2fc99a202
```

All notes are stored under the `Android-Security-Research/` vault folder.

## Vault Structure

```
Android-Security-Research/
  targets/
    <package_name>/
      index.md          ← Target overview, sessions, finding links
      coverage.md       ← Table of all tests run (class, technique, component, result)
      tests/
        <vuln_class>.md ← Detailed log of each test in this class
      findings/
        <finding_id>.md ← Individual finding with PoC, impact, chain potential
      chains/
        <chain_id>.md   ← Exploit chains linking multiple findings
      journal/
        <date>.md       ← Session journal (timestamped event log)
```

## Agent Workflow — MANDATORY

### Before EVERY test:

```bash
# Option 1: Python
python3 -c "
from harness.core.obsidian_tracker import ObsidianTracker
t = ObsidianTracker()
result = t.pre_test_check('com.google.android.gms', 'intent_vulnerabilities', 'Technique 1', '.ExportedActivity')
print(result['message'] if result['tested'] else 'NOT TESTED — proceed')
"

# Option 2: Direct API call
curl -sk -H "Authorization: Bearer 9341a691f70b081860a8c23cfd60057d15add58928d51a393f3720f2fc99a202" \
  "https://127.0.0.1:27124/vault/Android-Security-Research/targets/com.google.android.gms/tests/intent_vulnerabilities.md" \
  | grep -i "Technique 1"
```

**If already tested**: Skip and move to untested techniques or escalate existing findings.
**If not tested**: Proceed and log after completion.

### After EVERY test:

```bash
python3 -c "
from harness.core.obsidian_tracker import ObsidianTracker
t = ObsidianTracker()
t.post_test_log(
    'com.google.android.gms',
    'intent_vulnerabilities',
    'Technique 1: Intent Injection',
    '.ExportedActivity',
    'FINDING',  # or 'NO_FINDING', 'PARTIAL', 'ERROR'
    details='Intent injection via getStringExtra(\"url\") → loadUrl()',
    severity='high',
    finding_id='INTENT-001'
)
"
```

### When a finding is confirmed:

```bash
python3 -c "
from harness.core.obsidian_tracker import ObsidianTracker
t = ObsidianTracker()
t.log_finding(
    'com.google.android.gms',
    'INTENT-001',
    'Intent Redirect in ExportedActivity leads to arbitrary file read',
    'intent_vulnerabilities',
    'high',
    '.ExportedActivity',
    'Exported activity reads intent extra \"next\" and calls startActivity() without validation.',
    'Attacker can access any non-exported activity and read files via file:// URI.',
    poc='adb shell am start -n com.google.android.gms/.ExportedActivity --es next \"intent:#Intent;component=com.google.android.gms/.InternalFileViewer;S.path=/data/data/com.google.android.gms/databases/config.db;end\"',
    chain_potential='Chain with content provider for full database exfiltration'
)
"
```

### When a chain is built:

```bash
python3 -c "
from harness.core.obsidian_tracker import ObsidianTracker
t = ObsidianTracker()
t.log_chain(
    'com.google.android.gms',
    'CHAIN-001',
    'Intent redirect → file read → credential exfiltration',
    [
        {'finding_id': 'INTENT-001', 'title': 'Intent redirect in ExportedActivity', 'severity': 'high'},
        {'finding_id': 'STORAGE-003', 'title': 'Plaintext credentials in config.db', 'severity': 'moderate'}
    ],
    'critical',
    'Full credential exfiltration from GMS config database via intent redirect chain',
    poc='adb shell am start ...'
)
"
```

### Getting untested classes for a target:

```bash
python3 -c "
from harness.core.obsidian_tracker import ObsidianTracker
t = ObsidianTracker()
untested = t.get_untested_classes('com.google.android.gms')
print('Untested vulnerability classes:')
for cls in untested:
    print(f'  - {cls}')
"
```

### Getting full research summary:

```bash
python3 -c "
from harness.core.obsidian_tracker import ObsidianTracker
t = ObsidianTracker()
print(t.get_research_summary('com.google.android.gms'))
"
```

## Direct API Reference (for agents without Python)

### Read a note
```bash
curl -sk -H "Authorization: Bearer $OBSIDIAN_API_KEY" \
  "https://127.0.0.1:27124/vault/Android-Security-Research/targets/<pkg>/coverage.md"
```

### Write a note (create/replace)
```bash
curl -sk -X PUT \
  -H "Authorization: Bearer $OBSIDIAN_API_KEY" \
  -H "Content-Type: text/markdown" \
  -d "# Note content" \
  "https://127.0.0.1:27124/vault/Android-Security-Research/targets/<pkg>/tests/<class>.md"
```

### Append to a note
```bash
curl -sk -X POST \
  -H "Authorization: Bearer $OBSIDIAN_API_KEY" \
  -H "Content-Type: text/markdown" \
  -d "- New entry" \
  "https://127.0.0.1:27124/vault/Android-Security-Research/targets/<pkg>/tests/<class>.md"
```

### Search across all notes
```bash
curl -sk -X POST \
  -H "Authorization: Bearer $OBSIDIAN_API_KEY" \
  -H "Content-Type: application/json" \
  "https://127.0.0.1:27124/search/simple/?query=intent+injection+gms"
```

## What Gets Tracked

| Event | Logged To | Contains |
|-------|-----------|----------|
| Session start | `targets/<pkg>/index.md` | Device info, app version, timestamp |
| Every test | `targets/<pkg>/tests/<class>.md` + `coverage.md` | Class, technique, component, result, severity |
| Every finding | `targets/<pkg>/findings/<id>.md` | Full finding detail, PoC, impact, chain potential |
| Every chain | `targets/<pkg>/chains/<id>.md` | Chain links, combined severity, end-to-end PoC |
| Every event | `targets/<pkg>/journal/<date>.md` | Timestamped event log |

## Decision Tree

```
Start test for <package> / <vuln_class> / <technique> / <component>
  │
  ├─ Check Obsidian: was_tested(pkg, class, technique, component)
  │
  ├─ Already tested (same technique + component)?
  │   ├─ Had finding? → Read finding → Attempt ESCALATION or CHAIN
  │   └─ No finding?  → SKIP — move to next untested technique
  │
  ├─ Class partially tested (different techniques/components)?
  │   └─ Run ONLY the untested techniques/components
  │
  └─ Never tested?
      └─ Run full technique → Log result → Log finding if any
```
