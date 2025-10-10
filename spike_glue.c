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
  //  sys_gettimeofday = 169,
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




#if 0
#include <stdint.h>

// RISC-V CSR definitions
#define CSR_MSTATUS  0x300
#define CSR_MEPC     0x341
#define CSR_MCAUSE   0x342
#define CSR_MTVAL    0x343

// Exception causes
#define CAUSE_LOAD_ACCESS_FAULT  5

// CSR read/write macros
#define read_csr(reg) ({ \
    unsigned long __tmp; \
    asm volatile ("csrr %0, " #reg : "=r"(__tmp)); \
    __tmp; })

#define write_csr(reg, val) ({ \
    asm volatile ("csrw " #reg ", %0" :: "r"(val)); })

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

static size_t writestr(char const *c, FILE *file) {
  (void)file;
  size_t len = strlen(c);
  syscall(sys_write, stdout_channel, (uintptr_t)c, (uintptr_t)len, 0, 0, 0, 0);
  return len;
}

static void writestr_hex(char const *msg, uint32_t val) {
  char hex_buf[11];
  writestr(msg, stderr);
  uint_to_hex(val, hex_buf);
  writestr(hex_buf, stderr);
  writec('\n', stderr);
}

// Trap handler function
void handle_load_access_fault(void) {
  uint32_t mepc = read_csr(mepc);
  uint32_t mtval = read_csr(mtval);

  writestr("\n*** LOAD ACCESS FAULT ***\n", stderr);
  writestr_hex("Faulting address: ", mtval);
  writestr_hex("Faulting PC: ", mepc);
  writestr("Program terminated.\n", stderr);
  
  // Exit with error code 1
  _exit(1);
}

// Main trap vector
void trap_handler(void) {
  uint32_t mcause = read_csr(mcause);
  uint32_t cause_code = mcause & 0x7FFFFFFF;
  
  if (cause_code == CAUSE_LOAD_ACCESS_FAULT) {
    handle_load_access_fault();
  } else {
    // Handle other exceptions
    writestr("\n*** UNHANDLED EXCEPTION ***\n", stderr);
    writestr_hex("mcause: ", mcause);
    _exit(1);
  }
}

// Trap vector entry point (must be aligned to 4 bytes)
__attribute__((naked, aligned(4)))
void trap_entry() {
    asm volatile (
        // Save context (RV32 uses sw/lw and 128 byte frame)
        "addi sp, sp, -128\n"
        "sw x1,  0(sp)\n"
        "sw x2,  4(sp)\n"
        "sw x3,  8(sp)\n"
        "sw x4,  12(sp)\n"
        "sw x5,  16(sp)\n"
        "sw x6,  20(sp)\n"
        "sw x7,  24(sp)\n"
        "sw x8,  28(sp)\n"
        "sw x9,  32(sp)\n"
        "sw x10, 36(sp)\n"
        "sw x11, 40(sp)\n"
        "sw x12, 44(sp)\n"
        "sw x13, 48(sp)\n"
        "sw x14, 52(sp)\n"
        "sw x15, 56(sp)\n"
        "sw x16, 60(sp)\n"
        "sw x17, 64(sp)\n"
        "sw x18, 68(sp)\n"
        "sw x19, 72(sp)\n"
        "sw x20, 76(sp)\n"
        "sw x21, 80(sp)\n"
        "sw x22, 84(sp)\n"
        "sw x23, 88(sp)\n"
        "sw x24, 92(sp)\n"
        "sw x25, 96(sp)\n"
        "sw x26, 100(sp)\n"
        "sw x27, 104(sp)\n"
        "sw x28, 108(sp)\n"
        "sw x29, 112(sp)\n"
        "sw x30, 116(sp)\n"
        "sw x31, 120(sp)\n"
        
        // Call C handler
        "call trap_handler\n"
        
        // Restore context
        "lw x1,  0(sp)\n"
        "lw x2,  4(sp)\n"
        "lw x3,  8(sp)\n"
        "lw x4,  12(sp)\n"
        "lw x5,  16(sp)\n"
        "lw x6,  20(sp)\n"
        "lw x7,  24(sp)\n"
        "lw x8,  28(sp)\n"
        "lw x9,  32(sp)\n"
        "lw x10, 36(sp)\n"
        "lw x11, 40(sp)\n"
        "lw x12, 44(sp)\n"
        "lw x13, 48(sp)\n"
        "lw x14, 52(sp)\n"
        "lw x15, 56(sp)\n"
        "lw x16, 60(sp)\n"
        "lw x17, 64(sp)\n"
        "lw x18, 68(sp)\n"
        "lw x19, 72(sp)\n"
        "lw x20, 76(sp)\n"
        "lw x21, 80(sp)\n"
        "lw x22, 84(sp)\n"
        "lw x23, 88(sp)\n"
        "lw x24, 92(sp)\n"
        "lw x25, 96(sp)\n"
        "lw x26, 100(sp)\n"
        "lw x27, 104(sp)\n"
        "lw x28, 108(sp)\n"
        "lw x29, 112(sp)\n"
        "lw x30, 116(sp)\n"
        "lw x31, 120(sp)\n"
        "addi sp, sp, 128\n"
        
        // Return from trap
        "mret\n"
    );
}

// Initialize trap vector
void init_trap_handler() {
  // Set mtvec to trap_entry (direct mode)
  uint32_t mtvec_val = (uint32_t)(uintptr_t)trap_entry;
  write_csr(mtvec, mtvec_val);
}

#endif































#if 0
int gettimeofday(long* loc)
{
  //syscall(sys_gettimeofday, 0, 0, 0, 0, 0, 0, 0);
  *loc = 0;
  return 0;
}
#endif


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

#if 0
int file_dup3(file_t* f, int newfd) {
  if (newfd < 0 || newfd >= MAX_FDS) {
    return -1;
  }
  if (atomic_cas(&fds[newfd], 0, f) == 0) {
    file_incref(f);
    return newfd;
  }
  return -1;
}
void file_init() {
  // create stdin, stdout, stderr and FDs 0-2
  for (int i = 0; i < 3; i++) {
    file_t* f = file_get_free();
    f->kfd = i;
    file_dup(f);
  }
}
#endif



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
  return 0;//sys_semihost(SYS_TIME, 0);
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





#if 0
// Time structure definitions
struct timeval {
    int64_t tv_sec;   // seconds
    int64_t tv_usec;  // microseconds
};

struct timezone {
    int tz_minuteswest; // minutes west of Greenwich
    int tz_dsttime;     // type of DST correction
};


// RISC-V timebase frequency (typically 10 MHz, adjust for your platform)
#ifndef TIMEBASE_FREQ
#define TIMEBASE_FREQ 10000000ULL
#endif

// Epoch offset (set when system initializes)
static int64_t epoch_offset_sec = 0;


// Set the epoch offset (call this during system initialization)
void set_epoch_offset(int64_t seconds_since_epoch) {
    epoch_offset_sec = seconds_since_epoch;
}

// RISC-V implementation of gettimeofday
int gettimeofday(struct timeval *restrict tv, struct timezone *restrict tz) {
  stdout_writestr("gettimeofday\n");
    if (tv == nullptr) {
        return -1; // EFAULT equivalent
    }

    // Read the time counter
    uint64_t ticks = read_time();
    
    // Convert ticks to seconds and microseconds
    uint64_t total_usec = (ticks * 1000000ULL) / TIMEBASE_FREQ;
    
    tv->tv_sec = epoch_offset_sec + (int64_t)(total_usec / 1000000ULL);
    tv->tv_usec = (int64_t)(total_usec % 1000000ULL);
    
    // Handle timezone if requested (typically deprecated and unused)
    if (tz != nullptr) {
        tz->tz_minuteswest = 0;
        tz->tz_dsttime = 0;
    }
    
    return 0;
}
#endif
