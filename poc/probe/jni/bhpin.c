/*
 * bhpin.c — characterisation harness for the libbarhopper OOB read (crash at +0x161ac).
 *
 * Sweeps declared geometry against a fixed small allocation to isolate the root cause:
 *   - is it declared width x height that overruns the real buffer?
 *   - is it the stride field?
 * The faulting instruction is a byte load at libbarhopper+0x161ac inside the scan loop.
 */
#define _GNU_SOURCE 1
#include <jni.h>
#include <dlfcn.h>
#include <android/log.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <setjmp.h>

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,"BHPIN",__VA_ARGS__)
typedef jobject (*fn4)(JNIEnv*,jclass,jint,jint,jint,jbyteArray,jobject);
typedef jobject (*fn3)(JNIEnv*,jclass,jint,jint,jbyteArray,jobject);

static int getenv_fuzz_fill(void){ return 0; }
static void *g_lib; static fn4 g_r4; static fn3 g_r3; static jobject g_a;
static sigjmp_buf g_jb; static volatile int g_armed;

static void h(int s,siginfo_t*si,void*u){ if(g_armed){g_armed=0;siglongjmp(g_jb,1);} _exit(97); }

/* one call, returns 1 if it crashed */
static int one(JNIEnv *env, jclass cls, jobject opts, int dw,int dh,int stride,int w,int h){
    size_t n=(size_t)w*(size_t)h; if(n==0)n=1;
    jbyteArray a=(*env)->NewByteArray(env,(jsize)n);
    jbyte *e=(*env)->GetByteArrayElements(env,a,0);
    if (getenv_fuzz_fill()) { /* random */ long st=1; for(size_t k=0;k<n;k++){ st=st*6364136223846793005ULL+1442695040888963407ULL; e[k]=(jbyte)(st>>33);} }
    else memset(e,0x41,n);
    (*env)->ReleaseByteArrayElements(env,a,e,0);
    g_armed=1;
    if(sigsetjmp(g_jb,1)==0){
        jobject r = g_r4 ? g_r4(env,cls,dw,dh,stride,a,opts) : g_r3(env,cls,dw,dh,a,opts);
        if((*env)->ExceptionCheck(env))(*env)->ExceptionClear(env);
        (void)r;
        g_armed=0;
        (*env)->DeleteLocalRef(env,a);
        return 0;
    }
    (*env)->DeleteLocalRef(env,a);
    return 1;
}

JNIEXPORT jint JNICALL
Java_com_vrp_probe_BarhopperFuzz_nPin(JNIEnv *env,jclass cls,jstring so,jobject opts){
    struct sigaction sa; memset(&sa,0,sizeof sa);
    sa.sa_sigaction=h; sa.sa_flags=SA_SIGINFO;
    sigaction(SIGSEGV,&sa,NULL); sigaction(SIGBUS,&sa,NULL);
    const char*p=(*env)->GetStringUTFChars(env,so,0);
    g_lib=dlopen(p,RTLD_NOW); if(!g_lib){LOGE("dlopen %s",dlerror());return -1;}
    g_r3=(fn3)dlsym(g_lib,"Java_com_google_android_libraries_barhopper_Barhopper_recognizeNative");
    g_r4=(fn4)dlsym(g_lib,"Java_com_google_android_libraries_barhopper_Barhopper_recognizeStridedNative");

    struct { const char*name; int dw,dh,stride,w,h; } T[] = {
        {"ORIGINAL crash params, fill=0x41", 15,3753,4014, 15,199},
        {"ORIGINAL params, stride=15",       15,3753,15,   15,199},
        {"ORIGINAL params, stride=4014 dh=199",15,199,4014, 15,199},
    };
    for (unsigned i=0;i<sizeof T/sizeof T[0];i++){
        int c = one(env,cls,opts,T[i].dw,T[i].dh,T[i].stride,T[i].w,T[i].h);
        LOGE("%-34s dw=%-7d dh=%-7d stride=%-6d buf=%dx%d  => %s",
             T[i].name,T[i].dw,T[i].dh,T[i].stride,T[i].w,T[i].h, c?"CRASH":"ok");
    }
    (*env)->ReleaseStringUTFChars(env,so,p);
    return 0;
}
