package com.google.android.apps.betterbug.dispatch;

import android.content.Intent;
import android.os.Bundle;
import defpackage.ayx;
import defpackage.bpt;
import defpackage.bpy;
import defpackage.btf;
import defpackage.bwz;
import defpackage.bxa;
import defpackage.cfz;
import defpackage.cix;
import defpackage.ckf;
import defpackage.gdz;
import defpackage.geb;
import defpackage.wr;

/* compiled from: PG */
/* loaded from: classes.dex */
public class DispatchActivity extends bpt {
    private static final geb J = geb.k("com/google/android/apps/betterbug/dispatch/DispatchActivity");

    @Override // defpackage.bpt
    public final int A() {
        return 4;
    }

    @Override // defpackage.bpt
    protected final void C(bpy bpyVar) {
        bpyVar.getClass();
        btf btfVar = new btf(bpyVar, 10);
        btf btfVar2 = new btf(bpyVar, 11);
        this.x = btfVar;
        this.y = btfVar2;
        cfz cfzVarX = bpyVar.X();
        cfzVarX.getClass();
        this.z = cfzVarX;
        this.A = bpyVar.a();
        this.B = bpyVar.e();
        this.C = new ckf();
        this.I = bpyVar.Q();
        this.D = bpyVar.g();
        this.E = bpyVar.n();
        this.F = bpyVar.Z();
        this.G = bpyVar.E();
        this.H = bpyVar.p();
    }

    @Override // defpackage.bpt, defpackage.at, defpackage.mt, defpackage.ce, android.app.Activity
    protected final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        geb gebVar = J;
        ((gdz) ((gdz) gebVar.d()).i("com/google/android/apps/betterbug/dispatch/DispatchActivity", "onCreate", 27, "DispatchActivity.java")).q("creating DispatchActivity");
        ((gdz) ((gdz) gebVar.d()).i("com/google/android/apps/betterbug/dispatch/DispatchActivity", "startBugIntentDialogActivity", 32, "DispatchActivity.java")).q("Dispatching incoming intent");
        Intent intent = getIntent();
        geb gebVar2 = cix.a;
        ((gdz) ((gdz) gebVar2.d()).i("com/google/android/apps/betterbug/util/IntentUtil", "dumpIntentDetails", 103, "IntentUtil.java")).C("intent has data: %s, has clip data: %s", intent.getData(), intent.getClipData());
        Bundle extras = intent.getExtras();
        if (extras != null) {
            for (String str : extras.keySet()) {
                ((gdz) ((gdz) gebVar2.d()).i("com/google/android/apps/betterbug/util/IntentUtil", "dumpIntentDetails", 109, "IntentUtil.java")).C("key: %s, value: %s", str, extras.getString(str));
            }
        }
        Bundle extras2 = getIntent().getExtras();
        Intent intentD = extras2 == null ? ayx.d() : ayx.d().putExtras(extras2);
        if (wr.W(this)) {
            bwz bwzVar = bxa.a;
        }
        intentD.setAction(getIntent().getAction());
        startActivity(intentD);
        finish();
    }

    @Override // defpackage.cu, defpackage.at, android.app.Activity
    protected final void onDestroy() {
        ((gdz) ((gdz) J.d()).i("com/google/android/apps/betterbug/dispatch/DispatchActivity", "onDestroy", 61, "DispatchActivity.java")).q("DispatchActivity destroyed, uri permission might be lost");
        super.onDestroy();
    }

    @Override // defpackage.bpt
    public final int p() {
        return -1;
    }
}
