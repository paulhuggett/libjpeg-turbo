#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

enum {
  sys_exit = 93,
  sys_read = 63,
  sys_write = 64,
  sys_close = 57,
  sys_lseek = 62,
  sys_openat = 56,
  sys_getmainvars = 2011,
};

enum { channel_stdin = 0, channel_stdout = 1, channel_stderr = 2 };

extern volatile uint64_t tohost;
volatile uint64_t tohost;
extern volatile uint64_t fromhost;
volatile uint64_t fromhost;

__attribute__((noinline)) static uint64_t syscall(uint64_t n, uint64_t a0,
                                                  uint64_t a1, uint64_t a2,
                                                  uint64_t a3, uint64_t a4,
                                                  uint64_t a5, uint64_t a6) {
  uint64_t const th = tohost;
  if (th) {
    __builtin_trap();
  }

  static volatile uint64_t htif_mem[8];
  htif_mem[0] = n;
  htif_mem[1] = a0;
  htif_mem[2] = a1;
  htif_mem[3] = a2;
  htif_mem[4] = a3;
  htif_mem[5] = a4;
  htif_mem[6] = a5;
  htif_mem[7] = a6;
  tohost = (uint64_t)htif_mem;

  for (;;) {
    uint64_t const fh = fromhost;
    if (fh) {
      fromhost = 0;
      break;
    }
  }
  return htif_mem[0];
}



// A small buffer for stdout. Flushed when full or '\n' is written to the device.
static char buffer[256];
static size_t pos = 0;

static int stdout_flush(FILE *) {
  if (pos > 0) {
    syscall(sys_write, channel_stdout, (uintptr_t)buffer, pos, 0, 0, 0, 0);
    pos = 0;
  }
  return 0;
}

static int stdout_writec(char c, FILE *file) {
  buffer[pos++] = c;
  if (pos >= sizeof(buffer) / sizeof(buffer[0]) || c == '\n') {
    stdout_flush(file);
  }
  return c;
}

static void stdout_write_str(char const * str) {
  for (; *str != '\0'; ++str) {
    stdout_writec(*str, nullptr);
  }
}


// A callback for picolibc stdio providing unbuffered output for stderr.
static int stderr_writec(char c, FILE *) {
  syscall(sys_write, channel_stderr, (uintptr_t)&c, 1, 0, 0, 0, 0);
  return c;
}

// putc, get, flush for stdin, stdout, and stderr.
#define FDEV_SETUP_WRITE __SWR
static FILE __stdio = FDEV_SETUP_STREAM(stdout_writec, nullptr, stdout_flush, FDEV_SETUP_WRITE);
FILE *const stdout = &__stdio;
__strong_reference(stdout, stdin);

static FILE __stdio_stderr = FDEV_SETUP_STREAM(stderr_writec, nullptr, nullptr, FDEV_SETUP_WRITE);
FILE *const stderr = &__stdio_stderr;

[[noreturn]] void _exit(int const status) {
  syscall(sys_exit, (uint64_t)status, 0, 0, 0, 0, 0, 0);
  for (;;) {
  }
  __builtin_unreachable();
}


// Convert number to hex string
static void uint_to_hex(uint32_t val, char *buf) {
  static char const hex[] = "0123456789abcdef";
  buf[0] = '0';
  buf[1] = 'x';
  for (int i = 7; i >= 0; i--) {
    buf[2 + (7 - i)] = hex[(val >> (i * 4)) & 0xF];
  }
  buf[10] = '\0';
}
void writemsg(char const * msg, uint32_t val) {
  char hbuf[11];
  uint_to_hex(val, hbuf);
  
  stdout_write_str(msg);
  stdout_write_str(hbuf);
  stdout_writec('\n', nullptr);
}

int sys_semihost_get_cmdline(char *buf, size_t size) {
  uint64_t args[64];
  uint64_t res = syscall(sys_getmainvars, (uintptr_t)args, sizeof(args), 0, 0, 0, 0, 0);
  if (res != 0) {
    //  panic("args must not exceed %d bytes", (int)sizeof(arg_buf));
    return -1;
  }

  char *orig_buf = buf;
  uint64_t argc = args[0];
  for (unsigned ctr = 0; ctr < argc; ++ctr) {
    if (ctr > 0) {
      *(buf++) = ' ';
      --size;
    }

    char const *argv = (char const *)args[ctr + 1];
    size_t len = strlen(argv);
    if (len >= size) {
      return -1;
    }
    memcpy(buf, argv, len);
    buf += len;
    size -= len;
    if (size == 0) {
      return -1;
    }
  }
  *buf = '\0';
  return 0; // success
}



typedef struct file {
  int kfd; // file descriptor on the host side of the HTIF
  unsigned refcnt;
} file_t;

#define MAX_FDS 128
static file_t* fds[MAX_FDS];
#define MAX_FILES 128
file_t files[MAX_FILES] = {[0 ... MAX_FILES-1] = {-1,0}};

static void file_incref(file_t * const f) {
  ++f->refcnt;
  //kassert(prev > 0);
}

static void file_decref(file_t* f) {
  if (f->refcnt-- == 2) {
    int kfd = f->kfd;
    //mb();
    f->refcnt = 0;
    syscall(sys_close, kfd, 0, 0, 0, 0, 0, 0);
  }
}

static file_t* file_get_free() {
  for (file_t* f = files; f < files + MAX_FILES; f++) {
    if (f->refcnt == 0) {
      f->refcnt = 2;
      return f;
    }
  }
  return nullptr;
}

// Given a file_t, returns a new file descriptor.
int file_dup(file_t* f) {
  for (int i = 3; i < MAX_FDS; i++) {
    if (fds[i] == nullptr) {
      fds[i] = f;
      file_incref(f);
      return i;
    }
  }
  return -1;
}
static file_t* file_get(int fd) {
  if (fd < 0 || fd >= MAX_FDS) {
    return nullptr;
  }
  file_t * const f = fds[fd];
  if (f->refcnt == 0) {
    writemsg("file_get refcnt=0, fd=", fd);
    return nullptr;
  }
  ++f->refcnt;
  return f;
}


#undef AT_FDCWD
#define AT_FDCWD -100

static int at_kfd(int dirfd) {
  if (dirfd == AT_FDCWD) {
    return AT_FDCWD;
  }
  file_t* const dir = file_get(dirfd);
  if (dir == nullptr) {
    return -1;
  }
  int kfd = dir->kfd;
  file_decref(dir);
  return kfd;
}



#define IS_ERR_VALUE(x) ((unsigned long)(x) >= (unsigned long)-4096)
#define ERR_PTR(x) ((void*)(long)(x))
#define PTR_ERR(x) ((long)(x))



file_t* file_openat(int dirfd, char const * fn, int flags, int mode) {
  file_t * const f = file_get_free();
  if (f == nullptr) {
    stdout_write_str("get_free returned nullptr\n");
    return ERR_PTR(-ENOMEM);
  }

  size_t fn_size = strlen(fn) + 1;
  long ret = syscall(sys_openat, dirfd, (uint64_t)(uintptr_t)fn, fn_size, flags, mode, 0, 0);
  if (ret >= 0) {
    f->kfd = ret;
    return f;
  }
  return ERR_PTR(ret);
}

int open(char const* name, int flags, ...) {
  int kfd = at_kfd(AT_FDCWD);
  if (kfd == -1) {
    return -EBADF;
  }

  int mode = 0;
  if (flags & O_CREAT) {
    va_list args;
    va_start(args, flags);
    mode = va_arg(args, int);
    va_end(args);
  }

  file_t* file = file_openat(kfd, name, flags, mode);
  if (IS_ERR_VALUE(file)) {
    return PTR_ERR(file);
  }

  int fd = file_dup(file);
  file_decref(file); // counteract file_dup's file_incref
  if (fd < 0) {
    return -ENOMEM;
  }
  return fd;
}

ssize_t read(int fd, void*buf, size_t nbyte){
  file_t * const f = file_get(fd);
  if (f == nullptr) {
    return -1;
  }

  int res = syscall(sys_read, f->kfd, (uint64_t)(uintptr_t)buf, nbyte, 0, 0, 0, 0);
  if (res < 0) {
    errno = res;
    res = -1;
  }
  return res;
}
ssize_t write(int fd, void const*buf, size_t nbyte) {
  file_t * const f = file_get(fd);
  if (f == nullptr) {
    return -1;
  }
  return syscall(sys_write, f->kfd, (uint64_t)(uintptr_t)buf, nbyte, 0, 0, 0, 0);
}

off_t lseek(int fd, off_t offset, int whence) {
  file_t * const f = file_get(fd);
  if (f == nullptr) {
    return -1;
  }
  int res = syscall(sys_lseek, f->kfd, offset, whence, 0, 0, 0, 0);
  if (res < 0) {
    errno = res;
    res = -1;
  }
  return res;
}

int close(int fd) {
  file_t * const f = file_get(fd);
  if (f == nullptr) {
    return -1;
  }
  return syscall(sys_close, f->kfd, 0, 0, 0, 0, 0, 0);
}

// Read the RISC-V time CSR (cycle counter)
static inline uint64_t read_time(void) {
  // For RV32, need to read timeh and time with proper synchronization
  uint32_t hi = 0;
  uint32_t lo = 0;
  uint32_t tmp = 0;
  do {
    __asm__ volatile("rdtimeh %0" : "=r"(hi));
    __asm__ volatile("rdtime %0" : "=r"(lo));
    __asm__ volatile("rdtimeh %0" : "=r"(tmp));
  } while (hi != tmp);
  return ((uint64_t)hi << 32) | lo;
}

static uint64_t sys_semihost_elapsed(void) {
  return read_time();
}
static uintptr_t sys_semihost_tickfreq() {
  return 10000000ULL;
}
uintptr_t sys_semihost_time(void) {
  return 0;
}

int gettimeofday(struct timeval *restrict tv, void *restrict tz) {
  uint64_t ticks;
  static uint64_t start_elapsed;
  static uint64_t start_ticks;
  static uintptr_t tick_freq;
  static _Bool been_here = false;
  
  (void) tz;
  uint64_t const elapsed = read_time();
  if (!been_here) {
    start_elapsed = elapsed;
    tick_freq = sys_semihost_tickfreq();
    start_ticks = 0;//(uint64_t) sys_semihost_time() * tick_freq;
    been_here = 1;
  }
  
  ticks = start_ticks + (elapsed - start_elapsed);
  
  tv->tv_sec = (time_t) (ticks / tick_freq);
  tv->tv_usec = (suseconds_t) ((ticks % tick_freq) * 1000000 / tick_freq);
  return 0;
}
