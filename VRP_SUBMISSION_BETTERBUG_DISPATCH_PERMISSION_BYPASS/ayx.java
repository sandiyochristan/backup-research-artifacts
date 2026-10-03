package defpackage;

import android.content.Context;
import android.content.Intent;
import android.text.TextUtils;
import java.nio.ByteBuffer;
import java.util.Collection;

/* compiled from: PG */
/* loaded from: classes.dex */
public final class ayx {
    public static /* synthetic */ String a(int i) {
        return i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? "null" : "MEMORY_CACHE" : "RESOURCE_DISK_CACHE" : "DATA_DISK_CACHE" : "REMOTE" : "LOCAL";
    }

    public static final int b(int i, ByteBuffer byteBuffer) {
        if (u(i, 4, byteBuffer)) {
            return byteBuffer.getInt(i);
        }
        return -1;
    }

    public static final short c(int i, ByteBuffer byteBuffer) {
        if (u(i, 2, byteBuffer)) {
            return byteBuffer.getShort(i);
        }
        return (short) -1;
    }

    public static Intent d() {
        return new Intent().setClassName("com.google.android.apps.betterbug", "com.google.android.apps.betterbug.filebug.BugIntentDialogActivity");
    }

    public static Intent e(cen cenVar) {
        return d().putExtra("KEY_SAVED_USER_INPUT", cenVar.bW());
    }

    public static Intent f() {
        Intent intentD = d();
        intentD.putExtra("EXTRA_FOR_DEEPLINK_INTERMEDIATE_SCREEN", true);
        return intentD;
    }

    public static Intent g() {
        Intent intentF = f();
        intentF.putExtra("EXTRA_FOR_DEEPLINK_INTERMEDIATE_SCREEN_WITH_COMPANION_APP_CROSS_DEVICE_BUG_REPORTS", true);
        return intentF;
    }

    public static String h(Intent intent) {
        return intent.getStringExtra("EXTRA_EXCLUDING_USER_INPUT_ID");
    }

    public static boolean i(Intent intent) {
        return intent.getBooleanExtra("EXTRA_FOR_DEEPLINK_INTERMEDIATE_SCREEN", false);
    }

    public static boolean j(Intent intent) {
        return i(intent) && intent.getBooleanExtra("EXTRA_FOR_DEEPLINK_INTERMEDIATE_SCREEN_WITH_COMPANION_APP_CROSS_DEVICE_BUG_REPORTS", false);
    }

    public static boolean k(Intent intent) {
        return intent.getBooleanExtra("EXTRA_FROM_REUSE_BUGREPORT_ATTACHMENT", false);
    }

    public static boolean l(Intent intent) {
        return intent.getBooleanExtra("EXTRA_FROM_REUSE_LOCAL_STORAGE_FILE", false);
    }

    public static /* synthetic */ cen m(byte[] bArr) {
        if (bArr == null) {
            return null;
        }
        try {
            hzv hzvVarV = hzv.v(cen.b, bArr, 0, bArr.length, hzj.a);
            hzv.J(hzvVarV);
            return (cen) hzvVarV;
        } catch (iag e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static void n(boolean z) {
        o(z, "");
    }

    public static void o(boolean z, String str) {
        if (!z) {
            throw new IllegalArgumentException(str);
        }
    }

    public static void p(String str) {
        if (TextUtils.isEmpty(str)) {
            throw new IllegalArgumentException("Must not be null or empty");
        }
    }

    public static void q(Collection collection) {
        if (collection.isEmpty()) {
            throw new IllegalArgumentException("Must not be empty.");
        }
    }

    public static void r(Object obj) {
        a.z(obj, "Argument must not be null");
    }

    public static cpj t(Context context) {
        cwx cwxVar = new cwx(context);
        jus.l();
        return new cpj(cwxVar);
    }

    private static final boolean u(int i, int i2, ByteBuffer byteBuffer) {
        return byteBuffer.remaining() - i >= i2;
    }
}
