/*
 * j2k.c — direct fuzzing of Google's JPEG2000 decoder used by Google Pay.
 *
 *   Java_com_google_android_gms_pay_jpeg2k_Jpeg2kConverter_decodeJpeg2k(byte[], boolean) -> Bitmap
 *
 * Called directly (dlsym) instead of through JNI method binding, because GMS's classloader
 * namespace cannot see a library we preload — this reaches the exact same native function.
 * The library IS live in production: GMS logs "convertRawJpeg2kToBitmap loading jpeg2k_converter
 * library" and loads the same "jpeg2k_converter" name that ships in the APK.
 *
 * Inputs are seeded with a real JP2 signature so the parser is driven deep, then mutated.
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

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,"J2K",__VA_ARGS__)

typedef jobject (*fn_j2k)(JNIEnv*,jclass,jbyteArray,jboolean);
static void *g_base;
static volatile sig_atomic_t g_in;
static uint32_t g_len;
static void handler(int s,siginfo_t *si,void *uc){
    ucontext_t *c=(ucontext_t*)uc;
    unsigned long pc=(unsigned long)c->uc_mcontext.pc;
    char b[288];
    snprintf(b,sizeof b,"J2K CRASH sig=%d addr=%p pc=%#lx off_in_lib=%#lx in_call=%d len=%u\n",
             s,si->si_addr,pc,g_base?(pc-(unsigned long)g_base):0,(int)g_in,g_len);
    __android_log_write(ANDROID_LOG_FATAL,"J2K",b);
    signal(s,SIG_DFL); raise(s);
}
static void arm(void){struct sigaction sa;memset(&sa,0,sizeof sa);
    sa.sa_sigaction=handler;sa.sa_flags=SA_SIGINFO;
    sigaction(SIGSEGV,&sa,NULL);sigaction(SIGBUS,&sa,NULL);sigaction(SIGABRT,&sa,NULL);
    sigaction(SIGILL,&sa,NULL);sigaction(SIGFPE,&sa,NULL);}

static uint64_t st;
static uint32_t xr(void){uint64_t x=st;x^=x<<13;x^=x>>7;x^=x<<17;st=x;return (uint32_t)(x>>32);}

JNIEXPORT jint JNICALL
Java_com_vrp_probe_Jpeg2kFuzz_nNative(JNIEnv *env,jclass cls,jstring so,jint iters,jint seed){
    arm();
    const char *p=(*env)->GetStringUTFChars(env,so,0);
    void *h=dlopen(p,RTLD_NOW);
    if(!h){LOGE("dlopen FAIL %s",dlerror());return -1;}
    Dl_info di; g_base=0;
    { void*s=dlsym(h,"Java_com_google_android_gms_pay_jpeg2k_Jpeg2kConverter_decodeJpeg2k");
      if(s&&dladdr(s,&di)) g_base=di.dli_fbase; }
    fn_j2k dec=(fn_j2k)dlsym(h,"Java_com_google_android_gms_pay_jpeg2k_Jpeg2kConverter_decodeJpeg2k");
    if(!dec){LOGE("no decodeJpeg2k");return -2;}
    LOGE("[+] jpeg2k base=%p decode=%p",g_base,(void*)dec);

    st = seed?(uint64_t)seed:7;
    int ok=0;
    for(int i=0;i<iters;i++){
        int len=1+(xr()%65536);
        jbyteArray a=(*env)->NewByteArray(env,(jsize)len);
        if(!a)continue;
        jbyte*e=(*env)->GetByteArrayElements(env,a,0);
        if(e){
            /* real JP2 signature box: 00 00 00 0C 6A 50 20 20 0D 0A 87 0A */
            static const unsigned char magic[12]={0,0,0,0x0C,0x6A,0x50,0x20,0x20,0x0D,0x0A,0x87,0x0A};
            for(int k=0;k<len;k++) e[k]=0;
            for(int k=0;k<12&&k<len;k++) e[k]=(jbyte)magic[k];
            int mode=xr()%4;
            if(mode==0){ for(int k=12;k<len;k++) e[k]=(jbyte)xr(); }
            else if(mode==1){ for(int k=12;k<len;k++) e[k]=(jbyte)(k&0xFF); }
            else if(mode==2){ for(int k=12;k<len;k++) e[k]=(jbyte)0xFF; }
            (*env)->ReleaseByteArrayElements(env,a,e,0);
        }
        g_len=(uint32_t)len;
        g_in=1;
        jobject r=dec(env,cls,a,(jboolean)((xr()&1)==0));
        g_in=0;
        if((*env)->ExceptionCheck(env))(*env)->ExceptionClear(env);
        if(r){ ok++; }
        (*env)->DeleteLocalRef(env,a);
        if((ok&0x3F)==0) LOGE("[.] i=%d ok=%d len=%u",i,ok,g_len);
    }
    LOGE("[+] DONE iters=%d decoded=%d",iters,ok);
    (*env)->ReleaseStringUTFChars(env,so,p);
    return ok;
}
