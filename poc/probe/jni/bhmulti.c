/*
 * bhmulti.c — multi-entry fuzzing of Google's libbarhopper.
 *
 * Targets all exported parsers, not just the strided one:
 *   parseRawValue(String, int)                 <- pure string parser, classic overflow class
 *   recognizeNative(int,int,byte[],opts)       <- array path
 *   recognizeStridedNative(int,int,int,byte[],opts) <- confirmed OOB at +0x161ac (stride)
 *   recognizeBufferNative(int,int,ByteBuffer,opts)  <- ByteBuffer path (JNI GetDirectBuffer)
 *
 * Each case is run under a SIGSEGV/SIGBUS/SIGABRT handler that records the faulting PC so we can
 * prove where in the Google library the fault occurred (offset = pc - lib base).
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

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,"BHMULTI",__VA_ARGS__)

typedef jobject (*fn3)(JNIEnv*,jclass,jint,jint,jbyteArray,jobject);
typedef jobject (*fn4)(JNIEnv*,jclass,jint,jint,jint,jbyteArray,jobject);
typedef jobject (*fnbuf)(JNIEnv*,jclass,jint,jint,jobject,jobject);
typedef jobject (*fnstr)(JNIEnv*,jclass,jstring,jint);

static void *g_base; static int g_mode; static char g_desc[256];
static uint64_t st;
static uint32_t xr(void){uint64_t x=st;x^=x<<13;x^=x>>7;x^=x<<17;st=x;return (uint32_t)(x>>32);}

static void handler(int sig,siginfo_t *si,void *uc){
    ucontext_t *c=(ucontext_t*)uc;
    unsigned long pc=(unsigned long)c->uc_mcontext.pc;
    unsigned long off = (g_base)?(pc-(unsigned long)g_base):0;
    char b[384];
    snprintf(b,sizeof b,"BHMULTI CRASH sig=%d addr=%p pc=%#lx off_in_lib=%#lx mode=%d %s\n",
             sig,si->si_addr,pc,off,g_mode,g_desc);
    __android_log_write(ANDROID_LOG_FATAL,"BHMULTI",b);
    signal(sig,SIG_DFL); raise(sig);
}
static void arm(void){struct sigaction sa;memset(&sa,0,sizeof(sa));
    sa.sa_sigaction=handler;sa.sa_flags=SA_SIGINFO;
    sigaction(SIGSEGV,&sa,NULL);sigaction(SIGBUS,&sa,NULL);sigaction(SIGABRT,&sa,NULL);
    sigaction(SIGILL,&sa,NULL);sigaction(SIGFPE,&sa,NULL);}

JNIEXPORT jint JNICALL
Java_com_vrp_probe_BarhopperFuzz_nMulti(JNIEnv *env,jclass cls,jstring so,jobject opts,
                                      jint iters,jint seed){
    arm();
    const char *p=(*env)->GetStringUTFChars(env,so,0);
    void *L=dlopen(p,RTLD_NOW);
    if(!L){LOGE("dlopen %s",dlerror());return -1;}
    Dl_info di; g_base=0;
    { void*sym=dlsym(L,"Java_com_google_android_libraries_barhopper_Barhopper_parseRawValue");
      if(sym && dladdr(sym,&di)) g_base=di.dli_fbase; }
    fn3    rArr =(fn3)dlsym(L,"Java_com_google_android_libraries_barhopper_Barhopper_recognizeNative");
    fn4    rStr =(fn4)dlsym(L,"Java_com_google_android_libraries_barhopper_Barhopper_recognizeStridedNative");
    fnbuf  rBuf =(fnbuf)dlsym(L,"Java_com_google_android_libraries_barhopper_Barhopper_recognizeBufferNative");
    fnstr  rRaw =(fnstr)dlsym(L,"Java_com_google_android_libraries_barhopper_Barhopper_parseRawValue");
    LOGE("[+] base=%p sym=%p arr=%p strided=%p buf=%p raw=%p",g_base,
         dlsym(L,"Java_com_google_android_libraries_barhopper_Barhopper_parseRawValue"),
         (void*)rArr,(void*)rStr,(void*)rBuf,(void*)rRaw);

    st = seed?(uint64_t)seed:1;
    int made=0;
    for(int i=0;i<iters;i++){
        int which = rRaw ? (xr()%4) : (xr()%3);
        if(which==3 && rRaw){
            /* parseRawValue: fuzz the string + int */
            g_mode=3;
            int len=(int)(xr()%4096);
            char *buf=(char*)malloc(len+1);
            for(int k=0;k<len;k++){
                int r=xr()%10;
                buf[k]= (r<5)?(char)(0x20+(xr()%95))      /* printable */
                       :(r<8)?(char)(0x00+(xr()%32))      /* control */
                       :(char)(xr());                     /* arbitrary */
            }
            buf[len]=0;
            jstring s=(*env)->NewStringUTF(env,buf);
            snprintf(g_desc,sizeof g_desc,"parseRawValue len=%d int=%u",len,(unsigned)xr());
            jobject r=rRaw(env,cls,s,(jint)xr());
            if((*env)->ExceptionCheck(env))(*env)->ExceptionClear(env);
            (void)r; free(buf);
            if(s)(*env)->DeleteLocalRef(env,s);
        } else {
            int w=1+(xr()%2048), h=1+(xr()%2048);
            int dw=(xr()%3==0)?w:(1+(int)(xr()%4096));
            int dh=(xr()%3==0)?h:(1+(int)(xr()%4096));
            int stride=(xr()%2)?w:(1+(int)(xr()%8192));
            size_t n=(size_t)w*(size_t)h; if(!n||n>(2u<<20))n=65536;
            if(which==0 && rArr){
                g_mode=0; snprintf(g_desc,sizeof g_desc,"recognizeNative dw=%d dh=%d buf=%dx%d",dw,dh,w,h);
                jbyteArray a=(*env)->NewByteArray(env,(jsize)n);
                jbyte*e=(*env)->GetByteArrayElements(env,a,0);
                if(e){int f=xr()%4; for(size_t k=0;k<n;k++) e[k]= (f==0)?(jbyte)xr():(f==1)?0:(f==2)?(jbyte)0xFF:(k%251==0?(jbyte)xr():(jbyte)0x80);
                       (*env)->ReleaseByteArrayElements(env,a,e,0);}
                jobject r=rArr(env,cls,dw,dh,a,opts);
                if((*env)->ExceptionCheck(env))(*env)->ExceptionClear(env);
                (void)r; (*env)->DeleteLocalRef(env,a);
            } else if(which==1 && rStr){
                g_mode=1; snprintf(g_desc,sizeof g_desc,"recognizeStridedNative dw=%d dh=%d stride=%d buf=%dx%d",dw,dh,stride,w,h);
                jbyteArray a=(*env)->NewByteArray(env,(jsize)n);
                jbyte*e=(*env)->GetByteArrayElements(env,a,0);
                if(e){int f=xr()%4; for(size_t k=0;k<n;k++) e[k]= (f==0)?(jbyte)xr():(f==1)?0:(f==2)?(jbyte)0xFF:(k%251==0?(jbyte)xr():(jbyte)0x80);
                       (*env)->ReleaseByteArrayElements(env,a,e,0);}
                jobject r=rStr(env,cls,dw,dh,stride,a,opts);
                if((*env)->ExceptionCheck(env))(*env)->ExceptionClear(env);
                (void)r; (*env)->DeleteLocalRef(env,a);
            } else if(which==2 && rBuf){
                g_mode=2; snprintf(g_desc,sizeof g_desc,"recognizeBufferNative dw=%d dh=%d buf=%dx%d",dw,dh,w,h);
                jbyteArray a=(*env)->NewByteArray(env,(jsize)n);
                jbyte*e=(*env)->GetByteArrayElements(env,a,0);
                if(e){int f=xr()%4; for(size_t k=0;k<n;k++) e[k]=(f==0)?(jbyte)xr():(f==1)?0:(f==2)?(jbyte)0xFF:(k%251==0?(jbyte)xr():(jbyte)0x80);
                       (*env)->ReleaseByteArrayElements(env,a,e,0);}
                jobject r=rBuf(env,cls,dw,dh,a,opts);   /* ByteBuffer sig shares slot */
                if((*env)->ExceptionCheck(env))(*env)->ExceptionClear(env);
                (void)r; (*env)->DeleteLocalRef(env,a);
            }
        }
        made++;
        if((made&0xFF)==0) LOGE("[.] i=%d mode=%d %s",i,g_mode,g_desc);
    }
    LOGE("[+] DONE iters=%d",made);
    (*env)->ReleaseStringUTFChars(env,so,p);
    return made;
}
