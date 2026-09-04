# Mobile VRP Attack Surface Mapping & Testing Results

## Device
- **Model**: Pixel 6a (bluejay)
- **OS**: Android 15 (AP4A.250605.002)
- **Account**: sandiyotest@gmail.com

## Apps Analyzed (28 pulled, 5 deeply analyzed)

### Tier 1
| App | Size | Deep Analysis |
|-----|------|--------------|
| GMS Play Services | 233M (12 splits) | Manifest decoded |
| Gmail | 122M (4 splits) | Decompiled with jadx, full source audit |
| WebView | 241M | Manifest only |

### Tier 2
| App | Size | Deep Analysis |
|-----|------|--------------|
| Messages | 145M (4 splits) | Manifest decoded |
| Wallet | 40M | Manifest decoded |
| Gemini | 5.1M | Manifest decoded |
| + 22 more | Various | Not yet analyzed |

---

## Findings Summary

### [FINDING-1] Gmail Intent.parseUri Flag 0 in SmartMail URI_INTENT
- **Severity**: High (CVSS 7.1)
- **Status**: Documented, ready for submission
- **Details**: See MOBILE_VRP_FINDING_GMAIL_INTENT_PARSEURI.md

### [FINDING-2] GrowthKit TestingToolsBroadcastReceiver Exported (Messages)
- **Severity**: Low (gated by phenotype flag)
- **Component**: `com.google.android.libraries.internal.growth.growthkit.internal.debug.TestingToolsBroadcastReceiver`
- **Impact**: Promo injection if phenotype flag enabled
- **Evidence**: `GnpSdk: Testing Feature is not enabled. Override the phenotype flag?`
- **Status**: Gated by server-side config, not directly exploitable

### [FINDING-3] Multiple Intent.parseUri(str, 0) in Gmail
- **rdx.java:233**: Package tracking card click (AdViewController)
- **wew.java:79**: Related Emails "openHelpPage"
- **wdd.java:105**: SmartMail URI_INTENT action (primary finding)

---

## Testing Results — Content Providers

### Gmail Providers
| Provider | Authority | Exported | Result |
|----------|-----------|----------|--------|
| EmailProvider | com.google.android.gmail.provider | true (perm) | SecurityException (ACCESS_PROVIDER) |
| EmailProvider | com.google.android.gm.email.provider | true (perm) | SecurityException (ACCESS_PROVIDER) |
| AttachmentProvider | com.google.android.gmail.attachmentprovider | true (perm) | SecurityException (READ_ATTACHMENT) |
| MailProvider | gmail-ls | true (perm) | SecurityException (READ_GMAIL) |
| SapiUiProvider | com.google.android.gm.sapi | false | SecurityException (not exported) |
| FileProvider | com.google.android.gm.fileprovider | false | SecurityException (not exported) |
| ComposeImageFileProvider | com.google.android.gm.composeimagefileprovider | false | SecurityException (not exported) |
| GenerativeAiFileProvider | com.google.android.gm.generativeaiimagefileprovider | false | SecurityException (not exported) |
| MediaViewerFileProvider | com.google.android.libraries...fileprovider.com.google.android.gm | false | SecurityException (not exported) |
| ChimeFileProvider | com.google.android.gm.chime_sdk_file_provider | false | SecurityException (not exported) |

### Messages Providers
| Provider | Authority | Exported | Result |
|----------|-----------|----------|--------|
| BugleContentProvider | ...BugleContentProvider | true | "unimplemented" |
| MediaScratchFileProvider | ...MediaScratchFileProvider | true | Not found (Chimera) |
| AvatarContentProvider | ...AvatarContentProvider | true | UnsupportedOperationException |

### GMS Providers
| Provider | Authority | Exported | Result |
|----------|-----------|----------|--------|
| Phenotype | com.google.android.gms.phenotype | true | Empty results |
| SecurityProvider | com.google.android.gms.security.provider | true | Empty results |
| Chimera | com.google.android.gms.chimera | true | Empty results |
| Most others | Various | true | Not found (Chimera loading) |

---

## Testing Results — Activities & Deep Links

### Gmail
| Component | Result |
|-----------|--------|
| gmail://label/INBOX | Launched (opens inbox) |
| ConversationListActivityGmail + content:// | Launched |
| ComposeActivityGmailExternal (SEND) | Launched (compose screen) |
| SearchDeepLinkTrampolineActivity | Launched |
| TripsWebViewActivity | Blocked (not exported) |
| CseRedirectUriReceiverActivity | Not found (Chimera) |
| TrampolineActivityWear | Code-level caller check (Gmail-only) |
| TrampolineActivityMessageDeepLink | Account validation required |
| gmail-wear:// | Not found |

### FileProvider Path Traversal
All FileProviders are properly non-exported. Earlier false positives were due to providers not being registered (apps not running). When apps ARE running, SecurityException is properly thrown.

---

## Gmail JS Bridge Analysis

### "ads" Bridge (ConversationWebView)
- **Interface**: `zpm.java` → `triggerAction(String)` methods
- **Handler**: `zox.java` (AdViewController) → `m106890g()` (too complex for jadx)
- **Connected to**: `rdx.java:233` — `Intent.parseUri(str, 0)` on ad click
- **JS enabled**: Default OFF in ConversationWebView, ON in AdViewFragment
- **Exploitability**: Limited — requires injecting JS into ad content

### Other JS Bridges
- **"compose"**: `xef.java` — sanitizeHtml, escapePlainText (compose editor)
- **"UpsellInterface"**: `awsr.java` — purchase flow (finish, onStoragePurchaseComplete)
- **"notifyAddressChangedSuccess"**: ChangeAddressActivity (address update callback)

---

## Gmail SmartMail Action Type Enum (bezw.java)

| Ordinal | Name | Intent Parsing | Safety |
|---------|------|---------------|--------|
| 0 | GOTO | `Intent.parseUri(str, 1)` + BROWSABLE + null component | SAFE |
| 5 | CALL | `Intent(ACTION_DIAL)` | SAFE |
| 10 | NAVIGATE | `Intent(ACTION_VIEW, "google.navigation:...")` | SAFE |
| 12 | VIEW_MAP | `Intent(ACTION_VIEW, "geo:...")` | SAFE |
| **15** | **URI_INTENT** | **`Intent.parseUri(str, 0)`** | **UNSAFE** |
| 21 | VIEW_IN_TRIPS | `Intent` to TripsWebViewActivity | SAFE |

---

## Wallet & Messages FileProvider Configs (Notable)

### Wallet
```xml
<!-- wallet_file_provider_paths.xml - ENTIRE external storage -->
<external-path name="external" path="." />
```
Not exploitable — provider is not exported.

### Messages (GalleryCameraFileProvider)
```xml
<!-- media_paths.xml - ENTIRE external storage + files dir -->
<external-path name="content" path="." />
<files-path name="files_content" path="." />
```
Not exploitable — provider is not exported.

---

## Remaining Attack Surface (Not Yet Explored)

1. GMS 96 exported services without permission
2. Messages: LaunchConversationActivity SMS composition
3. Dialer, Contacts, Camera, Photos manifests
4. Google Search Assistant (370M, largest app)
5. SystemUI exported components
6. Gemini AI app (5.1M, small attack surface)
