package com.android.federatedcompute.services;

import android.content.ComponentName;
import android.content.Context;
import android.federatedcompute.aidl.IFederatedComputeCallback;
import android.federatedcompute.aidl.IFederatedComputeService;
import android.federatedcompute.aidl.IIsFeatureEnabledCallback;
import android.federatedcompute.common.TrainingOptions;
import android.os.Binder;
import android.os.RemoteException;
import android.os.SystemClock;
import com.android.federatedcompute.internal.util.LogUtil;
import com.android.federatedcompute.services.common.FeatureStatusManager;
import com.android.federatedcompute.services.common.FederatedComputeExecutors;
import com.android.federatedcompute.services.common.FlagsFactory;
import com.android.federatedcompute.services.scheduling.FederatedComputeJobManager;
import com.android.federatedcompute.services.statsd.ApiCallStats;
import com.android.federatedcompute.services.statsd.FederatedComputeStatsdLogger;
import com.android.odp.module.common.Clock;
import com.android.odp.module.common.MonotonicClock;
import java.util.Objects;

/* loaded from: classes.dex */
class FederatedComputeManagingServiceDelegate extends IFederatedComputeService.Stub {
    private final Clock mClock;
    private final Context mContext;
    private final FederatedComputeStatsdLogger mFcStatsdLogger;
    private final Injector mInjector;

    class Injector {
        Injector() {
        }

        FederatedComputeJobManager getJobManager(Context context) {
            return FederatedComputeJobManager.getInstance(context);
        }
    }

    FederatedComputeManagingServiceDelegate(Context context, FederatedComputeStatsdLogger federatedComputeStatsdLogger) {
        this(context, new Injector(), federatedComputeStatsdLogger, MonotonicClock.getInstance());
    }

    FederatedComputeManagingServiceDelegate(Context context, Injector injector, FederatedComputeStatsdLogger federatedComputeStatsdLogger, Clock clock) {
        Objects.requireNonNull(context);
        this.mContext = context;
        Objects.requireNonNull(injector);
        this.mInjector = injector;
        this.mClock = clock;
        this.mFcStatsdLogger = federatedComputeStatsdLogger;
    }

    public void schedule(final String str, final TrainingOptions trainingOptions, final IFederatedComputeCallback iFederatedComputeCallback) {
        String packageName;
        try {
            Objects.requireNonNull(str);
            Objects.requireNonNull(iFederatedComputeCallback);
            if (trainingOptions.getOwnerComponentName() == null) {
                packageName = "";
            } else {
                packageName = trainingOptions.getOwnerComponentName().getPackageName();
            }
            final String str2 = packageName;
            if (isKillSwitchEnabled(str2, 1, iFederatedComputeCallback, this.mFcStatsdLogger)) {
                return;
            }
            final long jElapsedRealtime = this.mClock.elapsedRealtime();
            final FederatedComputeJobManager jobManager = this.mInjector.getJobManager(this.mContext);
            FederatedComputeExecutors.getBackgroundExecutor().execute(new Runnable() { // from class: com.android.federatedcompute.services.FederatedComputeManagingServiceDelegate$$ExternalSyntheticLambda1
                @Override // java.lang.Runnable
                public final void run() throws Throwable {
                    this.f$0.lambda$schedule$0(jobManager, str, trainingOptions, iFederatedComputeCallback, jElapsedRealtime, str2);
                }
            });
        } catch (IllegalArgumentException | NullPointerException e) {
            LogUtil.e("FcpServiceDelegate", e, "Got exception for schedule()");
            throw e;
        } catch (Exception e2) {
            LogUtil.e("FcpServiceDelegate", e2, "Got exception for schedule()");
            sendResult(iFederatedComputeCallback, 1);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$schedule$0(FederatedComputeJobManager federatedComputeJobManager, String str, TrainingOptions trainingOptions, IFederatedComputeCallback iFederatedComputeCallback, long j, String str2) throws Throwable {
        long j2;
        String str3;
        Throwable th;
        int i;
        try {
            int iOnTrainerStartCalled = federatedComputeJobManager.onTrainerStartCalled(str, trainingOptions);
            sendResult(iFederatedComputeCallback, iOnTrainerStartCalled);
            logServiceLatency(j, 1, iOnTrainerStartCalled, str2, this.mFcStatsdLogger, this.mClock);
        } catch (Exception e) {
            j2 = j;
            str3 = str2;
            i = 1;
            try {
                LogUtil.e("FcpServiceDelegate", e, "Got exception for schedule()");
                sendResult(iFederatedComputeCallback, 1);
                logServiceLatency(j2, 1, 1, str3, this.mFcStatsdLogger, this.mClock);
            } catch (Throwable th2) {
                th = th2;
                sendResult(iFederatedComputeCallback, i);
                logServiceLatency(j2, 1, i, str3, this.mFcStatsdLogger, this.mClock);
                throw th;
            }
        } catch (Throwable th3) {
            j2 = j;
            str3 = str2;
            th = th3;
            i = 0;
            sendResult(iFederatedComputeCallback, i);
            logServiceLatency(j2, 1, i, str3, this.mFcStatsdLogger, this.mClock);
            throw th;
        }
    }

    public void cancel(final ComponentName componentName, final String str, IFederatedComputeCallback iFederatedComputeCallback) {
        final IFederatedComputeCallback iFederatedComputeCallback2;
        try {
            try {
                Objects.requireNonNull(componentName);
                Objects.requireNonNull(iFederatedComputeCallback);
                Objects.requireNonNull(str);
                if (isKillSwitchEnabled(componentName.getPackageName(), 2, iFederatedComputeCallback, this.mFcStatsdLogger)) {
                    return;
                }
                final long jElapsedRealtime = this.mClock.elapsedRealtime();
                final FederatedComputeJobManager jobManager = this.mInjector.getJobManager(this.mContext);
                iFederatedComputeCallback2 = iFederatedComputeCallback;
                try {
                    FederatedComputeExecutors.getBackgroundExecutor().execute(new Runnable() { // from class: com.android.federatedcompute.services.FederatedComputeManagingServiceDelegate$$ExternalSyntheticLambda0
                        @Override // java.lang.Runnable
                        public final void run() throws Throwable {
                            this.f$0.lambda$cancel$0(jobManager, componentName, str, iFederatedComputeCallback2, jElapsedRealtime);
                        }
                    });
                } catch (Exception e) {
                    e = e;
                    LogUtil.e("FcpServiceDelegate", e, "Got exception for cancel()");
                    sendResult(iFederatedComputeCallback2, 1);
                }
            } catch (Exception e2) {
                e = e2;
                iFederatedComputeCallback2 = iFederatedComputeCallback;
            }
        } catch (IllegalArgumentException | NullPointerException e3) {
            LogUtil.e("FcpServiceDelegate", e3, "Got exception for cancel()");
            throw e3;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$cancel$0(FederatedComputeJobManager federatedComputeJobManager, ComponentName componentName, String str, IFederatedComputeCallback iFederatedComputeCallback, long j) throws Throwable {
        long j2;
        Throwable th;
        int i;
        try {
            int iOnTrainerStopCalled = federatedComputeJobManager.onTrainerStopCalled(componentName, str);
            sendResult(iFederatedComputeCallback, iOnTrainerStopCalled);
            logServiceLatency(j, 2, iOnTrainerStopCalled, componentName.getPackageName(), this.mFcStatsdLogger, this.mClock);
        } catch (Exception e) {
            j2 = j;
            i = 1;
            try {
                LogUtil.e("FcpServiceDelegate", e, "Got exception when calling cancel for population: %s, owner: %s", new Object[]{str, componentName.flattenToString()});
                sendResult(iFederatedComputeCallback, 1);
                logServiceLatency(j2, 2, 1, componentName.getPackageName(), this.mFcStatsdLogger, this.mClock);
            } catch (Throwable th2) {
                th = th2;
                sendResult(iFederatedComputeCallback, i);
                logServiceLatency(j2, 2, i, componentName.getPackageName(), this.mFcStatsdLogger, this.mClock);
                throw th;
            }
        } catch (Throwable th3) {
            j2 = j;
            th = th3;
            i = 0;
            sendResult(iFederatedComputeCallback, i);
            logServiceLatency(j2, 2, i, componentName.getPackageName(), this.mFcStatsdLogger, this.mClock);
            throw th;
        }
    }

    private static void logServiceLatency(long j, int i, int i2, String str, FederatedComputeStatsdLogger federatedComputeStatsdLogger, Clock clock) {
        federatedComputeStatsdLogger.logApiCallStats(new ApiCallStats.Builder().setApiName(i).setLatencyMillis((int) (clock.elapsedRealtime() - j)).setResponseCode(i2).setSdkPackageName(str).build());
    }

    private static boolean isKillSwitchEnabled(String str, int i, IFederatedComputeCallback iFederatedComputeCallback, FederatedComputeStatsdLogger federatedComputeStatsdLogger) {
        boolean z;
        long jClearCallingIdentity = Binder.clearCallingIdentity();
        if (FlagsFactory.getFlags().getGlobalKillSwitch()) {
            federatedComputeStatsdLogger.logApiCallStats(new ApiCallStats.Builder().setApiName(i).setResponseCode(3).setSdkPackageName(str).build());
            sendResult(iFederatedComputeCallback, 3);
            z = true;
        } else {
            z = false;
        }
        Binder.restoreCallingIdentity(jClearCallingIdentity);
        return z;
    }

    public void isFeatureEnabled(String str, IIsFeatureEnabledCallback iIsFeatureEnabledCallback) {
        if (!FlagsFactory.getFlags().isFeatureEnabledApiEnabled()) {
            throw new IllegalStateException("isFeatureEnabled flag is not enabled.");
        }
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        FeatureStatusManager.getFeatureStatusAndSendResult(str, jElapsedRealtime, iIsFeatureEnabledCallback);
        this.mFcStatsdLogger.logApiCallStats(new ApiCallStats.Builder().setApiName(24).setLatencyMillis((int) (this.mClock.elapsedRealtime() - jElapsedRealtime)).setResponseCode(0).setSdkPackageName("").build());
    }

    private static void sendResult(IFederatedComputeCallback iFederatedComputeCallback, int i) {
        try {
            if (i == 0) {
                iFederatedComputeCallback.onSuccess();
            } else {
                iFederatedComputeCallback.onFailure(i);
            }
        } catch (RemoteException e) {
            LogUtil.e("FcpServiceDelegate", e, "Callback error");
        }
    }
}
