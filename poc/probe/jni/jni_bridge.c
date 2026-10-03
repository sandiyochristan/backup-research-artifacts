#include <jni.h>
#include <android/log.h>
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "VRPNATIVE", __VA_ARGS__)

extern int bff_open(const char *dev);
extern int bff_run(int seed, int iters);

JNIEXPORT jint JNICALL
Java_com_vrp_probe_BinderFz_nOpen(JNIEnv *env, jclass c, jstring dev) {
    const char *d = (*env)->GetStringUTFChars(env, dev, 0);
    int r = bff_open(d);
    (*env)->ReleaseStringUTFChars(env, dev, d);
    LOGE("bff_open(%s) = %d", d, r);
    return r;
}

JNIEXPORT jint JNICALL
Java_com_vrp_probe_BinderFz_nRun(JNIEnv *env, jclass c, jint seed, jint iters) {
    int r = bff_run(seed, iters);
    LOGE("bff_run(seed=%d, iters=%d) = %d", seed, iters, r);
    return r;
}

extern int bff_ioctlnum(void);
extern int bff_clean(void);
JNIEXPORT jint JNICALL
Java_com_vrp_probe_BinderFz_nIoctlnum(JNIEnv *env, jclass c) {
    int v = bff_ioctlnum();
    LOGE("BINDER_WRITE_READ ioctlnum = 0x%08x (%d)", (unsigned)v, v);
    return v;
}

JNIEXPORT jint JNICALL
Java_com_vrp_probe_BinderFz_nClean(JNIEnv *env, jclass c) {
    int v = bff_clean();
    LOGE("bff_clean() = %d", v);
    return v;
}
