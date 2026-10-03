import android.os.IBinder;
import android.os.Parcel;
import android.net.Uri;
import java.lang.reflect.Method;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class ContentProviderScan {
    public static void main(String[] args) throws Exception {
        System.out.println("UID: " + android.os.Process.myUid());

        // Scan content providers via cmd content
        String[] uris = {
            // Wear OS specific
            "content://com.google.android.wearable.settings/settings",
            "content://com.google.android.wearable.settings",
            "content://com.google.android.apps.wearable.settings",
            "content://com.google.wear.services.provider",
            "content://com.google.wear.services",
            "content://com.google.android.clockwork.home",
            "content://com.google.android.clockwork.home.provider",
            // Health data
            "content://com.google.android.apps.fitness.api",
            "content://com.google.android.apps.fitness",
            "content://com.google.android.gms.fitness",
            "content://android.health.connect",
            // Wallet/payment
            "content://com.google.android.apps.walletnfcrel",
            "content://com.google.android.gms.tapandpay",
            // Settings/config
            "content://com.google.settings",
            "content://com.google.android.gsf.gservices",
            "content://com.google.android.gsf.gservices/prefix",
            // Standard providers that might leak on Wear
            "content://call_log/calls",
            "content://sms",
            "content://sms/inbox",
            "content://contacts/people",
            "content://com.android.contacts/contacts",
            "content://com.android.contacts/data",
            "content://user_dictionary/words",
            "content://telephony/carriers",
            "content://downloads/my_downloads",
            "content://media/external/file",
            // GMS internal
            "content://com.google.android.gms.phenotype",
            "content://com.google.android.gms.icing.provider",
            "content://com.google.android.gms.auth.accounts",
            "content://com.google.android.gms.people",
            "content://com.google.android.gms.common.config",
            // Notification
            "content://com.google.android.wearable.app.notification",
            // Watch face
            "content://com.google.android.wearable.app.watchface",
            // Companion
            "content://com.google.android.gms.wearable",
            // Pixel Watch specific
            "content://com.google.android.apps.pixelwatch.settings",
            "content://com.google.android.apps.diagnostics",
            // App data
            "content://com.google.android.gms.appusage",
            // Location
            "content://com.google.android.gms.location",
        };

        for (String uri : uris) {
            queryUri(uri);
        }

        // Also check for exported providers from all Google packages
        System.out.println("\n=== Scanning package providers ===");
        scanPackageProviders();
    }

    static void queryUri(String uri) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{
                "content", "query", "--uri", uri
            });
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            BufferedReader er = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            StringBuilder out = new StringBuilder();
            StringBuilder err = new StringBuilder();
            String line;
            int lineCount = 0;
            while ((line = br.readLine()) != null && lineCount < 5) {
                out.append(line).append("\n");
                lineCount++;
            }
            while ((line = er.readLine()) != null) {
                err.append(line).append("\n");
            }
            p.waitFor();

            String o = out.toString().trim();
            String e = err.toString().trim();

            if (!o.isEmpty() && !o.contains("No result found") && !o.contains("Unknown URI")) {
                System.out.println("\n[FOUND] " + uri);
                System.out.println("  " + o.replace("\n", "\n  "));
                if (lineCount >= 5) System.out.println("  ... (more rows)");
            } else if (!e.isEmpty() && e.contains("Permission") || (e.contains("security") || e.contains("SecurityException"))) {
                System.out.println("[PERM]  " + uri + ": " + e.substring(0, Math.min(e.length(), 100)));
            }
            // Skip unknown URIs and other errors silently
        } catch (Exception ex) {
            // skip
        }
    }

    static void scanPackageProviders() {
        try {
            // Get all Google package providers
            Process p = Runtime.getRuntime().exec(new String[]{
                "cmd", "package", "query-providers", "--auth", "com.google"
            });
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println("  " + line);
            }
        } catch (Exception e) {
            // Try alternative approach
            try {
                Process p = Runtime.getRuntime().exec(new String[]{
                    "dumpsys", "package", "providers"
                });
                BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                int count = 0;
                while ((line = br.readLine()) != null && count < 200) {
                    if (line.contains("google") || line.contains("wear") || line.contains("clockwork")) {
                        System.out.println("  " + line.trim());
                        count++;
                    }
                }
            } catch (Exception e2) {
                System.out.println("  Provider scan failed");
            }
        }
    }
}
