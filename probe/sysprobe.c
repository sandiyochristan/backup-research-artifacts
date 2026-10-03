#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>
#include <linux/userfaultfd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/prctl.h>
static long sc(long n,...){va_list a;va_start(a,n);long r=syscall(n,a);va_end(a);return r;}
int main(){
  printf("uid=%d\n",getuid());
  long fd=sc(__NR_io_uring_setup,8,NULL);
  printf("io_uring_setup(8) = %ld  errno=%s\n",fd,fd<0?strerror(errno):"-");
  int ufd=syscall(__NR_userfaultfd,O_CLOEXEC|O_NONBLOCK);
  printf("userfaultfd = %d errno=%s\n",ufd,ufd<0?strerror(errno):"-");
  int bpfd=sc(__NR_bpf,5 /*BPF_PROG_LOAD*/,NULL,0);
  printf("bpf(PROG_LOAD) = %d errno=%s\n",bpfd,bpfd<0?strerror(errno):"-");
  void*m=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  printf("mmap=%p\n",m);
  int cfd=open("/proc/self/maps",O_RDONLY); printf("open /proc/self/maps=%d errno=%s\n",cfd,cfd<0?strerror(errno):"-");
  printf("kptr_restrict=%s\n",getenv("X")?"":"n/a");
  return 0;
}
