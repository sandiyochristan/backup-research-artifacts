package com.android.systemui.settings.brightness;

import android.R;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.MotionEvent;
import androidx.activity.ComponentActivity;
import com.android.internal.logging.MetricsLogger;
import com.android.systemui.brightness.ui.viewmodel.BrightnessSliderViewModel;
import com.android.systemui.broadcast.BroadcastSender;
import com.android.systemui.statusbar.policy.AccessibilityManagerWrapper;
import com.android.systemui.util.concurrency.DelayableExecutor;
import com.android.systemui.util.concurrency.ExecutorImpl;
import com.android.systemui.volume.dialog.domain.interactor.ExpandedAudioTileDetailsFeatureInteractor;
import dagger.Lazy;
import java.lang.invoke.VarHandle;

/* compiled from: go/retraceme 62c875cb2fdb9334e959738c0d57cd7e9de8676167876f38ef886b13c386d351 */
/* loaded from: classes.dex */
public class BrightnessDialog extends ComponentActivity {
    static final int DIALOG_TIMEOUT_MILLIS = 3000;
    public final AccessibilityManagerWrapper mAccessibilityMgr;
    public ExecutorImpl.ExecutionToken mCancelTimeoutRunnable;
    public final DelayableExecutor mMainExecutor;

    public BrightnessDialog(DelayableExecutor delayableExecutor, AccessibilityManagerWrapper accessibilityManagerWrapper, Lazy lazy, BrightnessSliderViewModel.Factory factory, BroadcastSender broadcastSender, ExpandedAudioTileDetailsFeatureInteractor expandedAudioTileDetailsFeatureInteractor) {
        this.mMainExecutor = delayableExecutor;
        this.mAccessibilityMgr = accessibilityManagerWrapper;
        expandedAudioTileDetailsFeatureInteractor.getClass();
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity, android.view.Window.Callback
    public final boolean dispatchKeyEvent(KeyEvent keyEvent) {
        if (getIntent().getBooleanExtra("android.intent.extra.FROM_BRIGHTNESS_KEY", false) && (keyEvent.getKeyCode() == 21 || keyEvent.getKeyCode() == 22)) {
            int action = keyEvent.getAction();
            boolean z = action == 0;
            boolean z2 = action == 1;
            if (z) {
                ExecutorImpl.ExecutionToken executionToken = this.mCancelTimeoutRunnable;
                if (executionToken != null) {
                    executionToken.run();
                    this.mCancelTimeoutRunnable = null;
                }
            } else if (z2) {
                scheduleTimeout$1();
            }
        }
        return super.dispatchKeyEvent(keyEvent);
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public final boolean dispatchTouchEvent(MotionEvent motionEvent) {
        if (getIntent().getBooleanExtra("android.intent.extra.FROM_BRIGHTNESS_KEY", false)) {
            int actionMasked = motionEvent.getActionMasked();
            boolean z = actionMasked == 0;
            boolean z2 = actionMasked == 1 || actionMasked == 3;
            if (z) {
                ExecutorImpl.ExecutionToken executionToken = this.mCancelTimeoutRunnable;
                if (executionToken != null) {
                    executionToken.run();
                    this.mCancelTimeoutRunnable = null;
                }
            } else if (z2) {
                scheduleTimeout$1();
            }
        }
        return super.dispatchTouchEvent(motionEvent);
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public final void onCreate(Bundle bundle) {
        throw new IllegalStateException("Legacy code path not supported when com.android.systemui.shared.brightness_system_ui_dialog is enabled.");
    }

    @Override // android.app.Activity, android.view.KeyEvent.Callback
    public final boolean onKeyDown(int i, KeyEvent keyEvent) {
        if (i == 25 || i == 24 || i == 164) {
            ExecutorImpl.ExecutionToken executionToken = this.mCancelTimeoutRunnable;
            if (executionToken != null) {
                executionToken.run();
                this.mCancelTimeoutRunnable = null;
            }
            finish();
        }
        return super.onKeyDown(i, keyEvent);
    }

    @Override // android.app.Activity
    public final void onPause() {
        super.onPause();
        overridePendingTransition(R.anim.fade_in, R.anim.fade_out);
    }

    @Override // android.app.Activity
    public final void onResume() {
        super.onResume();
        if (getIntent().getBooleanExtra("android.intent.extra.FROM_BRIGHTNESS_KEY", false)) {
            scheduleTimeout$1();
        }
    }

    @Override // android.app.Activity
    public final void onStart() {
        super.onStart();
    }

    @Override // android.app.Activity
    public final void onStop() {
        super.onStop();
        MetricsLogger.hidden(this, 220);
    }

    public final void scheduleTimeout$1() {
        ExecutorImpl.ExecutionToken executionToken = this.mCancelTimeoutRunnable;
        if (executionToken != null) {
            executionToken.run();
            this.mCancelTimeoutRunnable = null;
        }
        int recommendedTimeoutMillis = this.mAccessibilityMgr.mAccessibilityManager.getRecommendedTimeoutMillis(DIALOG_TIMEOUT_MILLIS, 4);
        BrightnessDialog$$ExternalSyntheticLambda0 brightnessDialog$$ExternalSyntheticLambda0 = new BrightnessDialog$$ExternalSyntheticLambda0();
        brightnessDialog$$ExternalSyntheticLambda0.f$0 = this;
        VarHandle.storeStoreFence();
        this.mCancelTimeoutRunnable = this.mMainExecutor.executeDelayed(brightnessDialog$$ExternalSyntheticLambda0, recommendedTimeoutMillis);
    }
}
