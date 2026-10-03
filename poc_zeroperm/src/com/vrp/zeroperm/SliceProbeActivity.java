package com.vrp.zeroperm;

import android.app.Activity;
import android.app.slice.Slice;
import android.app.slice.SliceItem;
import android.app.slice.SliceManager;
import android.content.ContentResolver;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

import java.util.Collection;
import java.util.List;

public class SliceProbeActivity extends Activity {
    private static final String T = "SLICEPROBE";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== Slice & Content Probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid());

        probeWellbeingSlices();
        probeSettingsSlices();
        probeGmsSlices();
        probeUntestedGmsActivities();

        Log.w(T, "=== PROBE COMPLETE ===");
    }

    private void probeWellbeingSlices() {
        Log.w(T, "--- Wellbeing Slices ---");
        SliceManager sm = (SliceManager) getSystemService(SliceManager.class);

        String[] slicePaths = {
            "content://com.google.android.apps.wellbeing.slices/focus_mode",
            "content://com.google.android.apps.wellbeing.slices/screen_time",
            "content://com.google.android.apps.wellbeing.slices/bedtime",
            "content://com.google.android.apps.wellbeing.slices/app_timer",
            "content://com.google.android.apps.wellbeing.slices/wind_down",
            "content://com.google.android.apps.wellbeing.slices/screen_time_widget",
            "content://com.google.android.apps.wellbeing.slices/usage",
            "content://com.google.android.apps.wellbeing.slices/dashboard",
            "content://com.google.android.apps.wellbeing.slices/parental",
            "content://com.google.android.apps.wellbeing.slices/supervision",
        };

        for (String uri : slicePaths) {
            try {
                Slice slice = sm.bindSlice(Uri.parse(uri), java.util.Collections.emptySet());
                if (slice != null) {
                    Log.w(T, "[+] SLICE: " + uri);
                    dumpSlice(slice, "  ");
                } else {
                    Log.w(T, "[-] null slice: " + uri);
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] SECURITY: " + uri.substring(uri.lastIndexOf('/') + 1) + " — " + shortMsg(se));
            } catch (Exception e) {
                Log.w(T, "[-] " + uri.substring(uri.lastIndexOf('/') + 1) + ": " + e.getClass().getSimpleName());
            }
        }

        // Try bindSlice with intent
        try {
            Intent intent = new Intent("com.google.android.apps.wellbeing.action.HOME");
            intent.setPackage("com.google.android.apps.wellbeing");
            Slice slice = sm.bindSlice(intent, java.util.Collections.emptySet());
            if (slice != null) {
                Log.w(T, "[+] SLICE from intent");
                dumpSlice(slice, "  ");
            }
        } catch (Exception e) {
            Log.w(T, "[-] intent slice: " + e.getClass().getSimpleName());
        }
    }

    private void probeSettingsSlices() {
        Log.w(T, "--- Settings Slices ---");
        SliceManager sm = (SliceManager) getSystemService(SliceManager.class);

        String[] settingsSlices = {
            "content://android.settings.slices/action/wifi",
            "content://android.settings.slices/action/bluetooth",
            "content://android.settings.slices/action/airplane",
            "content://android.settings.slices/action/flashlight",
            "content://android.settings.slices/action/location",
            "content://android.settings.slices/action/nfc",
            "content://android.settings.slices/action/hotspot",
            "content://android.settings.slices/action/mobile_data",
        };

        for (String uri : settingsSlices) {
            try {
                Slice slice = sm.bindSlice(Uri.parse(uri), java.util.Collections.emptySet());
                if (slice != null) {
                    Log.w(T, "[+] SETTINGS SLICE: " + uri.substring(uri.lastIndexOf('/') + 1));
                    dumpSlice(slice, "  ");
                }
            } catch (SecurityException se) {
                Log.w(T, "[-] " + uri.substring(uri.lastIndexOf('/') + 1) + " SECURITY");
            } catch (Exception e) {
                Log.w(T, "[-] " + uri.substring(uri.lastIndexOf('/') + 1) + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void probeGmsSlices() {
        Log.w(T, "--- GMS Slices ---");
        SliceManager sm = (SliceManager) getSystemService(SliceManager.class);

        // Check if GMS has slice providers
        String[] gmsSlices = {
            "content://com.google.android.gms.nearby.discovery/scan",
            "content://com.google.android.gms.auth.api/status",
            "content://com.google.android.gms/settings",
        };

        for (String uri : gmsSlices) {
            try {
                Slice slice = sm.bindSlice(Uri.parse(uri), java.util.Collections.emptySet());
                if (slice != null) {
                    Log.w(T, "[+] GMS SLICE: " + uri);
                    dumpSlice(slice, "  ");
                }
            } catch (Exception e) {
                Log.w(T, "[-] " + uri.substring(uri.lastIndexOf('/') + 1) + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void probeUntestedGmsActivities() {
        Log.w(T, "--- Untested GMS Activities ---");

        // Test GMS PlacePicker — might return location
        Object[][] probes = {
            {400, "com.google.android.gms",
             "com.google.android.gms.location.places.internal.PlacePickerInternalActivity",
             "com.google.android.gms.location.places.ui.PICK_PLACE_INTERNAL"},
            {401, "com.google.android.gms",
             "com.google.android.gms.auth.api.signin.internal.SignInHubActivity",
             "com.google.android.gms.auth.GOOGLE_SIGN_IN"},
            {402, "com.google.android.gms",
             "com.google.android.gms.common.api.GoogleApiActivity",
             "com.google.android.gms.common.internal.RESOLVE_ACCOUNT"},
            {403, "com.google.android.gms",
             "com.google.android.gms.auth.api.credentials.ui.CredentialPickerActivity",
             "com.google.android.gms.auth.api.credentials.PICKER"},
            // Google Files — might expose file picker
            {404, "com.google.android.apps.nbu.files",
             "com.google.android.apps.nbu.files.picker.PickerActivity",
             "android.intent.action.GET_CONTENT"},
        };

        for (Object[] probe : probes) {
            int reqCode = (Integer) probe[0];
            String pkg = (String) probe[1];
            String cls = (String) probe[2];
            String action = (String) probe[3];

            try {
                Intent i = new Intent(action);
                i.setClassName(pkg, cls);
                i.addCategory("android.intent.category.DEFAULT");
                startActivityForResult(i, reqCode);
                Log.w(T, "[+] Launched: " + cls.substring(cls.lastIndexOf('.') + 1));
            } catch (SecurityException se) {
                Log.w(T, "[-] SECURITY: " + cls.substring(cls.lastIndexOf('.') + 1));
            } catch (Exception e) {
                Log.w(T, "[-] " + cls.substring(cls.lastIndexOf('.') + 1) + ": " + e.getClass().getSimpleName());
            }
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        Log.w(T, "[RESULT] req=" + req + " res=" + res);
        if (data != null) {
            Log.w(T, "[!!!] DATA from req=" + req);
            if (data.getData() != null) Log.w(T, "  URI: " + data.getData());
            if (data.getExtras() != null) {
                for (String key : data.getExtras().keySet()) {
                    Object val = data.getExtras().get(key);
                    String valStr = val != null ? val.toString() : "null";
                    Log.w(T, "  " + key + " = " + valStr.substring(0, Math.min(valStr.length(), 300)));
                }
            }
        }
    }

    private void dumpSlice(Slice slice, String prefix) {
        if (slice == null) return;
        List<SliceItem> items = slice.getItems();
        Log.w(T, prefix + "Slice URI=" + slice.getUri() + " items=" + items.size());
        for (SliceItem item : items) {
            String format = item.getFormat();
            Log.w(T, prefix + "  format=" + format);
            if ("text".equals(format)) {
                CharSequence text = item.getText();
                if (text != null) {
                    Log.w(T, prefix + "  [!!!] TEXT: " + text);
                }
            } else if ("int".equals(format)) {
                Log.w(T, prefix + "  INT: " + item.getInt());
            } else if ("slice".equals(format)) {
                dumpSlice(item.getSlice(), prefix + "    ");
            } else if ("action".equals(format)) {
                Log.w(T, prefix + "  ACTION: " + item.getAction());
                dumpSlice(item.getSlice(), prefix + "    ");
            } else if ("image".equals(format)) {
                Log.w(T, prefix + "  IMAGE present");
            } else if ("long".equals(format)) {
                Log.w(T, prefix + "  LONG: " + item.getLong());
            }
        }
    }

    private String shortMsg(Exception e) {
        String msg = e.getMessage();
        if (msg == null) return "";
        return msg.substring(0, Math.min(msg.length(), 120));
    }
}
