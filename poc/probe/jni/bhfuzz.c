/*
 * bhfuzz.c — direct native fuzzing of Google's libbarhopper barcode/QR decoder (in GMS).
 *
 * Reachability: libbarhopper is the decoder behind AGSA/Lens, Wallet, Photos and Keep barcode
 * scanning. On this build GMS's Barhopper class cannot load it (APK ships a differently-named
 * file), so we load the blob in our own namespace and drive its exported entry points.
 *
 * Signatures recovered from the GMS dex (Barhopper.smali):
 *   recognizeNative       (int,int,byte[],RecognitionOptions)             -> Barcode[]
 *   recognizeStridedNative(int,int,int,byte[],RecognitionOptions)       -> Barcode[]
 *
 * Hostile axis: declared width/height/stride vs the true allocation, plus hostile pixel bytes.
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

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,"BHFUZZ",__VA_ARGS__)

typedef jobject (*fn3)(JNIEnv*,jclass,jint,jint,jbyteArray,jobject);
typedef jobject (*fn4)(JNIEnv*,jclass,jint,jint,jint,jbyteArray,jobject);

static uint64_t st;
static uint32_t xr(void){uint64_t x=st;x^=x<<13;x^=x>>7;x^=x<<17;st=x;return (uint32_t)(x>>32);}
static volatile sig_atomic_t g_in;
static volatile unsigned g_w,g_h,g_stride,g_dw,g_dh;
static void handler(int sig,siginfo_t *si,void*uc){
    ucontext_t *c=(ucontext_t*)uc;
    unsigned long pc=(unsigned long)c->uc_mcontext.pc;
    unsigned long sp=(unsigned long)c->uc_mcontext.sp;
    char b[320];
    snprintf(b,sizeof(b),"BHFUZZ CRASH sig=%d addr=%p pc=%#lx sp=%#lx in_call=%d dw=%u dh=%u alloc=%ux%u stride=%u\n",
             sig,si->si_addr,pc,sp,(int)g_in,g_dw,g_dh,g_w,g_h,g_stride);
    __android_log_write(ANDROID_LOG_FATAL,"BHFUZZ",b);
    /* default action -> real tombstone with the crashing module in the backtrace */
    signal(sig,SIG_DFL); raise(sig);
}
static void arm(void){struct sigaction sa;memset(&sa,0,sizeof(sa));
    sa.sa_sigaction=handler;sa.sa_flags=SA_SIGINFO;
    sigaction(SIGSEGV,&sa,NULL);sigaction(SIGBUS,&sa,NULL);sigaction(SIGABRT,&sa,NULL);
    sigaction(SIGILL,&sa,NULL);sigaction(SIGFPE,&sa,NULL);}

JNIEXPORT jint JNICALL
Java_com_vrp_probe_BarhopperFuzz_nNative(JNIEnv *env,jclass cls,jstring soPath,
                                       jint iters,jint seed,jobject g_opts) {
    arm();
    if(!g_opts){LOGE("no RecognitionOptions");return -3;}
    const char *p=(*env)->GetStringUTFChars(env,soPath,0);
    void *h=dlopen(p,RTLD_NOW);
    if(!h){LOGE("dlopen FAIL path=%s err=%s",p,dlerror());return -1;}
    fn3  rec =(fn3)dlsym(h,"Java_com_google_android_libraries_barhopper_Barhopper_recognizeNative");
    fn4  recs=(fn4)dlsym(h,"Java_com_google_android_libraries_barhopper_Barhopper_recognizeStridedNative");
    if(!rec&&!recs){LOGE("no sym");return -2;}
    LOGE("[+] loaded rec=%p recs=%p opts=%p",(void*)rec,(void*)recs,g_opts);
    { Dl_info di; void *base=0;
      if (dladdr((void*)rec,&di) && di.dli_fbase) { base=di.dli_fbase;
        FILE*f=fopen("/proc/self/maps","r"); char line[512];
        if(f){ while(fgets(line,sizeof line,f)){
            unsigned long a,b; char perms[8]; char path[256]={0};
            if(sscanf(line,"%lx-%lx %7s %*x %*s %*u %255s",&a,&b,perms,path)>=3){
              if((void*)a==(void*)base){ LOGE("[+] BARHOP_BASE=%p SIZE=%#lx",base,(unsigned long)(b-a)); break; }
            }
          } fclose(f);} } }

    st = seed?(uint64_t)seed:0xC0FFEEULL;
    int made=0;
    for(int i=0;i<iters;i++){
        int mode=xr()%3;
        g_w=1+(xr()%2048); g_h=1+(xr()%2048);
        g_dw=(mode==0)?g_w:(1+(xr()%4096));
        g_dh=(mode==1)?g_h:(1+(xr()%4096));
        g_stride=(xr()%2)?g_w:(1+(xr()%4096));
        size_t n=(size_t)g_w*(size_t)g_h;
        if(n==0||n>(2u<<20))n=65536;
        jbyteArray arr=(*env)->NewByteArray(env,(jsize)n);
        if(!arr)continue;
        jbyte*el=(*env)->GetByteArrayElements(env,arr,0);
        if(el){int f=xr()%4;
            for(size_t k=0;k<n;k++){
                switch(f){case 0:el[k]=(jbyte)xr();break;case 1:el[k]=0;break;
                          case 2:el[k]=(jbyte)0xFF;break;
                          default:el[k]=(k%251==0)?(jbyte)xr():(jbyte)0x80;}
            }
            (*env)->ReleaseByteArrayElements(env,arr,el,0);}
        made++;
        g_in=1; jobject r=NULL;
        if(recs) r=recs(env,cls,g_dw,g_dh,(jint)g_stride,arr,g_opts);
        else     r=rec (env,cls,g_dw,g_dh,arr,g_opts);
        g_in=0;
        if((*env)->ExceptionCheck(env))(*env)->ExceptionClear(env);
        (void)r;
        (*env)->DeleteLocalRef(env,arr);
        if((made&0x3F)==0)LOGE("[.] i=%d made=%d dw=%u dh=%u alloc=%ux%u stride=%u",
                                i,made,g_dw,g_dh,g_w,g_h,g_stride);
    }
    LOGE("[+] DONE iters=%d arrays=%d",iters,made);
    (*env)->ReleaseStringUTFChars(env,soPath,p);
    return made;
}
