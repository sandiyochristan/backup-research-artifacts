/*
 * Fuzz Google's libbarhopper (barcode/QR scanner) native code under AddressSanitizer.
 *
 * Reachability: libbarhopper_qr_only_jni.so ships in com.google.android.gms and is invoked
 * from AGSA/Lens, Wallet, Photos and Keep when an app supplies an image (ACTION_SEND) or the
 * camera scans a frame. A memory-safety bug here is reachable by any app with an image.
 *
 * We dlopen() the real Google .so and drive its JNI entry points with fuzzed buffers.
 * ASAN gives an exact report (OOB read/write, UAF, overflow) inside Google's code.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

typedef void* (*fn_recognizeNative)(void*, void*, void*, int, int, int, int, int, int);
typedef void* (*fn_parseRaw)(void*, void*);

static uint64_t st;
static uint32_t xr(void){uint64_t x=st;x^=x<<13;x^=x>>7;x^=x<<17;st=x;return (uint32_t)(x>>32);}

int main(int argc, char **argv) {
    const char *path = argv[1];
    int iters = (argc > 2) ? atoi(argv[2]) : 200000;
    uint64_t seed = (argc > 3) ? strtoull(argv[3],0,10) : 0x1234567;
    st = seed ? seed : 0x1234567;

    void *h = dlopen(path, RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 2; }

    fn_recognizeNative rec = (fn_recognizeNative)dlsym(h, "Java_com_google_android_libraries_barhopper_Barhopper_recognizeNative");
    if (!rec) { fprintf(stderr, "no recognizeNative: %s\n", dlerror()); return 3; }
    fprintf(stderr, "[+] loaded, recognizeNative=%p\n", (void*)rec);

    /* onewayBuffer: byte[] laid out as a luminance/grayscale image the scanner will
       transform. We fuzz width/height/stride vs the actual allocation -> classic OOB. */
    for (int i = 0; i < iters; i++) {
        int w = 1 + (xr() % 2048);
        int h = 1 + (xr() % 2048);
        int cw = 1 + (xr() % 8);       /* color width multiplier 1..4 */
        int ch = 1 + (xr() % 8);
        int stride = (int)(xr() % 4096);
        size_t alloc = (size_t)stride * (size_t)h + 4096;
        if (alloc > (8u<<20)) alloc = 8u<<20;
        unsigned char *buf = (unsigned char*)malloc(alloc);
        if (!buf) break;
        /* fill: mostly noise, sometimes sparse/extreme patterns */
        int mode = xr() % 4;
        for (size_t k = 0; k < alloc; k++) {
            switch (mode) {
                case 0: buf[k] = (unsigned char)xr(); break;
                case 1: buf[k] = 0x00; break;                 /* sparse */
                case 2: buf[k] = 0xFF; break;                 /* saturated */
                default: buf[k] = (k % 251 == 0) ? (unsigned char)xr() : 0x80; break;
            }
        }
        void *out = rec(NULL, buf, NULL, w, h, cw, ch, stride, 0);
        (void)out;
        free(buf);
        if ((i & 0x3FFF) == 0) fprintf(stderr, "[.] %d iters (w=%d h=%d stride=%d mode=%d)\n", i, w, h, stride, mode);
    }
    fprintf(stderr, "[+] done %d iters, no crash\n", iters);
    return 0;
}
