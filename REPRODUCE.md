# Reproducing the derived artifacts
Excluded from this repo on purpose (regenerable, and too large for GitHub):

| Path        | What it is                                        | How to get it back                                  |
|-------------|---------------------------------------------------|-----------------------------------------------------|
| `apks/`     | 365 base APKs pulled from the device               | `python3 pull_all.py`                               |
| `smali/`    | apktool disassembly (473k files)                   | `apktool d -f -o smali/<app> apks/<pkg>-base.apk`    |
| `src/`      | jadx decompilation                                | `jadx --no-res -d src/<app> apks/<pkg>-base.apk`    |
| `kernel/common/` | AOSP android14-6.1 kernel source             | `git clone --depth 1 -b android14-6.1 https://android.googlesource.com/kernel/common` |

Everything you actually wrote — PoC harness, fuzzers, findings, evidence — IS committed here.
