/* Android binder UAPI matching kernel 6.1 (include/uapi/linux/android/binder.h) */
#ifndef _UAPI_LINUX_BINDER_H
#define _UAPI_LINUX_BINDER_H
#include <linux/types.h>
#include <linux/ioctl.h>

#define BINDER_VERSION _IOWR('b', 9, struct binder_version)
#define BINDER_GET_VERSION _IOWR('b', 10, __s32)
#define BINDER_WORK_RETURN_ERROR _IOW('b', 1, __s32)
#define BINDER_THREAD_EXIT _IOW('b', 2, __s32)
#define BINDER_THREAD_READY _IOW('b', 3, __s32)
#define BINDER_WRITE_READ _IOWR('b', 4, struct binder_write_read)
#define BINDER_SET_CONTEXT_MGR _IOW('b', 7, __s32)
#define BINDER_SET_MAX_THREADS _IOW('b', 5, __u32)
#define BINDER_SET_WORK_AREA _IOW('b', 10, __ptr_t)
#define BINDER_SET_TARGET_HARDENED _IOW('b', 25, __s32)

struct binder_type { char name[16]; };
struct binder_version { __s32 protocol_version; };

struct binder_write_read {
  __u32 write_size;
  __u32 write_consumed;
  __u64 write_buffer;
  __u32 read_size;
  __u32 read_consumed;
  __u64 read_buffer;
};

struct binder_object_header {
  __u8 type;
  __u8 flags;
  __u16 old_type;
  __u32 pid;
};

enum {
  BINDER_TYPE_BINDER = 1,
  BINDER_TYPE_WEAK_BINDER = 2,
  BINDER_TYPE_HANDLE = 3,
  BINDER_TYPE_WEAK_HANDLE = 4,
  BINDER_TYPE_FD = 5,
  BINDER_TYPE_FDEX = 6,
  BINDER_TYPE_PTR = 7,
  BINDER_TYPE_BUNDLE = 8,
  BINDER_TYPE_ALIAS = 9,
  BINDER_TYPE_BUFFER = 13,
  BINDER_TYPE_STRING_UTF8 = 16,
  BINDER_TYPE_STRING_UTF16 = 17,
};

/* Exact 6.1 layout: hdr + {binder_type,flags,desc...} union + next + padding */
struct binder_object {
  struct binder_object_header hdr;
  union {
    struct { __u32 binder_type; __u32 flags; __u32 weak_ref; __u32 strong_ref; };
    struct { __u32 pad[2]; struct binder_buffer_desc *desc; };
  };
  struct binder_object *next;
  __u32 padding[4];
};
struct binder_buffer_desc {
  __u32 size; __u32 num_elements; __u32 parent_offset; __u32 parent_index;
};

struct binder_transaction_header {
  __u32 size;
  __u32 ptr;
  __u32 flags;
};

#define TF_ACCEPT_FDS 0x20
#define TF_REJECT_FDS 0x10
#define TF_ONE_WAY 0x08
#define TF_2X2_EVENTS 0x02
#define TF_UPDATE_TXN 0x40
#define TF_HAS_BOOKEEPER 0x00000010
#endif
