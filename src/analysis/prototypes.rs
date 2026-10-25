//! The prototypes of common library and runtime functions, for calls into
//! code the binary only imports: the type of each parameter and of the
//! result. A variadic function that takes a format string names it, and its
//! conversions count the arguments that follow.
//!
//! macOS declarations and record layouts come from the generated SDK library.
//! Other targets and unsupported declarations use the tables below.
//!
//! The declarations are written as C declares them, apart from three
//! simplifications: a pointer to a function is written `void (*)(...)` and
//! taken for a pointer to code, an array parameter is written as the pointer
//! it decays to, and a typedef is used only where its width and sign agree
//! between Linux on x86-64 and `AArch64` and macOS on arm64.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::ir::{CType, Stmt};
use crate::loader::{Image, NameSource};

mod generated;
pub(crate) use generated::{apply_records, is_library_record};

/// What a function takes and returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prototype {
    /// The parameters before any variadic ones, in order.
    pub params: Vec<CType>,
    pub ret: CType,
    pub variadic: bool,
    /// The position among the integer arguments of the format string whose
    /// conversions count the variadic arguments.
    pub format: Option<usize>,
    /// Its format string's conversions read input, through pointers.
    pub scans: bool,
}

impl Prototype {
    /// How many integer and pointer arguments it takes before any variadic
    /// ones.
    #[must_use]
    pub fn fixed(&self) -> usize {
        self.params.iter().filter(|ty| !ty.is_sse_float()).count()
    }

    /// How many floating-point arguments it takes.
    #[must_use]
    pub fn floats(&self) -> usize {
        self.params.iter().filter(|ty| ty.is_sse_float()).count()
    }

    /// The types of the integer and pointer arguments, in the order the
    /// argument registers take them.
    pub fn integer_params(&self) -> impl Iterator<Item = &CType> {
        self.params.iter().filter(|ty| !ty.is_sse_float())
    }

    /// The integer arguments it takes as pointers, one bit for each.
    #[must_use]
    pub fn pointers(&self) -> u32 {
        self.integer_params()
            .enumerate()
            .take(32)
            .filter(|(_, ty)| ty.is_pointer())
            .fold(0, |bits, (position, _)| bits | 1 << position)
    }

    /// It returns a 32-bit integer, which leaves the upper half of the
    /// return register unspecified.
    #[must_use]
    pub fn narrow_return(&self) -> bool {
        self.ret.integer().is_some_and(|(bits, _)| bits == 32)
    }
}

/// The C library and POSIX, and the entry points of the C++ runtime.
const LIBRARY: &[&str] = &[
    // Process start and exit.
    "void abort(void)",
    "void exit(int)",
    "void _exit(int)",
    "void _Exit(int)",
    "void quick_exit(int)",
    "int atexit(void (*)(void))",
    "int __cxa_atexit(void (*)(void *), void *, void *)",
    "void __cxa_finalize(void *)",
    "int __libc_start_main(int (*)(int, char **, char **), int, char **, void (*)(void), void (*)(void), void (*)(void), void *)",
    "void __stack_chk_fail(void)",
    "void __assert_fail(const char *, const char *, unsigned int, const char *)",
    "void __assert_rtn(const char *, const char *, int, const char *)",
    "void *__tls_get_addr(void *)",
    // The C++ runtime.
    "void *_Znwm(size_t)",
    "void *_Znam(size_t)",
    "void *_ZnwmRKSt9nothrow_t(size_t, const void *)",
    "void *_ZnamRKSt9nothrow_t(size_t, const void *)",
    "void *_ZnwmSt11align_val_t(size_t, size_t)",
    "void *_ZnamSt11align_val_t(size_t, size_t)",
    "void _ZdlPv(void *)",
    "void _ZdaPv(void *)",
    "void _ZdlPvm(void *, size_t)",
    "void _ZdaPvm(void *, size_t)",
    "void _ZdlPvSt11align_val_t(void *, size_t)",
    "void _ZdaPvSt11align_val_t(void *, size_t)",
    "void _ZdlPvmSt11align_val_t(void *, size_t, size_t)",
    "void _ZdaPvmSt11align_val_t(void *, size_t, size_t)",
    "void _ZSt9terminatev(void)",
    "void *__cxa_allocate_exception(size_t)",
    "void __cxa_free_exception(void *)",
    "void __cxa_throw(void *, void *, void (*)(void *))",
    "void __cxa_rethrow(void)",
    "void *__cxa_begin_catch(void *)",
    "void __cxa_end_catch(void)",
    "int __cxa_guard_acquire(int64_t *)",
    "void __cxa_guard_release(int64_t *)",
    "void __cxa_guard_abort(int64_t *)",
    "void __cxa_pure_virtual(void)",
    "void _Unwind_Resume(void *)",
    // stdlib.h
    "void *malloc(size_t)",
    "void *calloc(size_t, size_t)",
    "void *realloc(void *, size_t)",
    "void *reallocarray(void *, size_t, size_t)",
    "void free(void *)",
    "void *aligned_alloc(size_t, size_t)",
    "int posix_memalign(void **, size_t, size_t)",
    "long strtol(const char *, char **, int)",
    "unsigned long strtoul(const char *, char **, int)",
    "long long strtoll(const char *, char **, int)",
    "unsigned long long strtoull(const char *, char **, int)",
    "long __isoc23_strtol(const char *, char **, int)",
    "unsigned long __isoc23_strtoul(const char *, char **, int)",
    "long long __isoc23_strtoll(const char *, char **, int)",
    "unsigned long long __isoc23_strtoull(const char *, char **, int)",
    "double strtod(const char *, char **)",
    "float strtof(const char *, char **)",
    "int atoi(const char *)",
    "long atol(const char *)",
    "long long atoll(const char *)",
    "double atof(const char *)",
    "char *getenv(const char *)",
    "char *secure_getenv(const char *)",
    "int setenv(const char *, const char *, int)",
    "int unsetenv(const char *)",
    "int putenv(char *)",
    "int system(const char *)",
    "void qsort(void *, size_t, size_t, int (*)(const void *, const void *))",
    "void *bsearch(const void *, const void *, size_t, size_t, int (*)(const void *, const void *))",
    "int abs(int)",
    "long labs(long)",
    "long long llabs(long long)",
    "int rand(void)",
    "void srand(unsigned int)",
    "int rand_r(unsigned int *)",
    "long random(void)",
    "void srandom(unsigned int)",
    "uint32_t arc4random(void)",
    "void arc4random_buf(void *, size_t)",
    "uint32_t arc4random_uniform(uint32_t)",
    "char *realpath(const char *, char *)",
    "int mkstemp(char *)",
    "char *mkdtemp(char *)",
    // string.h and strings.h
    "void *memcpy(void *, const void *, size_t)",
    "void *memmove(void *, const void *, size_t)",
    "void *mempcpy(void *, const void *, size_t)",
    "void *memccpy(void *, const void *, int, size_t)",
    "void *memset(void *, int, size_t)",
    "void memset_pattern4(void *, const void *, size_t)",
    "void memset_pattern8(void *, const void *, size_t)",
    "void memset_pattern16(void *, const void *, size_t)",
    "int memcmp(const void *, const void *, size_t)",
    "void *memchr(const void *, int, size_t)",
    "void *memrchr(const void *, int, size_t)",
    "void *memmem(const void *, size_t, const void *, size_t)",
    "void bzero(void *, size_t)",
    "void explicit_bzero(void *, size_t)",
    "int bcmp(const void *, const void *, size_t)",
    "void *__memcpy_chk(void *, const void *, size_t, size_t)",
    "void *__memmove_chk(void *, const void *, size_t, size_t)",
    "void *__memset_chk(void *, int, size_t, size_t)",
    "char *__strcpy_chk(char *, const char *, size_t)",
    "char *__stpcpy_chk(char *, const char *, size_t)",
    "char *__strcat_chk(char *, const char *, size_t)",
    "char *__strncpy_chk(char *, const char *, size_t, size_t)",
    "char *__strncat_chk(char *, const char *, size_t, size_t)",
    "size_t strlen(const char *)",
    "size_t strnlen(const char *, size_t)",
    "int strcmp(const char *, const char *)",
    "int strncmp(const char *, const char *, size_t)",
    "int strcoll(const char *, const char *)",
    "int strcasecmp(const char *, const char *)",
    "int strncasecmp(const char *, const char *, size_t)",
    "char *strcpy(char *, const char *)",
    "char *strncpy(char *, const char *, size_t)",
    "char *stpcpy(char *, const char *)",
    "char *stpncpy(char *, const char *, size_t)",
    "char *strcat(char *, const char *)",
    "char *strncat(char *, const char *, size_t)",
    "size_t strlcpy(char *, const char *, size_t)",
    "size_t strlcat(char *, const char *, size_t)",
    "char *strchr(const char *, int)",
    "char *strrchr(const char *, int)",
    "char *strchrnul(const char *, int)",
    "char *strstr(const char *, const char *)",
    "char *strcasestr(const char *, const char *)",
    "char *strpbrk(const char *, const char *)",
    "size_t strspn(const char *, const char *)",
    "size_t strcspn(const char *, const char *)",
    "char *strtok(char *, const char *)",
    "char *strtok_r(char *, const char *, char **)",
    "char *strsep(char **, const char *)",
    "char *strdup(const char *)",
    "char *strndup(const char *, size_t)",
    "size_t strxfrm(char *, const char *, size_t)",
    "char *strerror(int)",
    "char *strsignal(int)",
    "char *basename(char *)",
    "char *dirname(char *)",
    "int fnmatch(const char *, const char *, int)",
    // ctype.h, and the tables glibc's macros read.
    "int isalnum(int)",
    "int isalpha(int)",
    "int isascii(int)",
    "int isblank(int)",
    "int iscntrl(int)",
    "int isdigit(int)",
    "int isgraph(int)",
    "int islower(int)",
    "int isprint(int)",
    "int ispunct(int)",
    "int isspace(int)",
    "int isupper(int)",
    "int isxdigit(int)",
    "int tolower(int)",
    "int toupper(int)",
    "const unsigned short **__ctype_b_loc(void)",
    "const int32_t **__ctype_tolower_loc(void)",
    "const int32_t **__ctype_toupper_loc(void)",
    // errno, as glibc, macOS and bionic reach it.
    "int *__errno_location(void)",
    "int *__error(void)",
    "int *__errno(void)",
    "int *__h_errno_location(void)",
    // stdio.h
    "FILE *fopen(const char *, const char *)",
    "FILE *fopen64(const char *, const char *)",
    "FILE *fdopen(int, const char *)",
    "FILE *freopen(const char *, const char *, FILE *)",
    "FILE *fmemopen(void *, size_t, const char *)",
    "FILE *tmpfile(void)",
    "FILE *popen(const char *, const char *)",
    "int pclose(FILE *)",
    "int fclose(FILE *)",
    "int fflush(FILE *)",
    "size_t fread(void *, size_t, size_t, FILE *)",
    "size_t fwrite(const void *, size_t, size_t, FILE *)",
    "int fseek(FILE *, long, int)",
    "int fseeko(FILE *, off_t, int)",
    "long ftell(FILE *)",
    "off_t ftello(FILE *)",
    "void rewind(FILE *)",
    "int feof(FILE *)",
    "int ferror(FILE *)",
    "void clearerr(FILE *)",
    "int fileno(FILE *)",
    "int fgetc(FILE *)",
    "int getc(FILE *)",
    "int getchar(void)",
    "int ungetc(int, FILE *)",
    "char *fgets(char *, int, FILE *)",
    "char *__fgets_chk(char *, size_t, int, FILE *)",
    "int fputc(int, FILE *)",
    "int putc(int, FILE *)",
    "int putchar(int)",
    "int fputs(const char *, FILE *)",
    "int puts(const char *)",
    "ssize_t getline(char **, size_t *, FILE *)",
    "ssize_t getdelim(char **, size_t *, int, FILE *)",
    "void setbuf(FILE *, char *)",
    "int setvbuf(FILE *, char *, int, size_t)",
    "void perror(const char *)",
    "int remove(const char *)",
    "int rename(const char *, const char *)",
    "int printf(const char *format, ...)",
    "int fprintf(FILE *, const char *format, ...)",
    "int dprintf(int, const char *format, ...)",
    "int sprintf(char *, const char *format, ...)",
    "int snprintf(char *, size_t, const char *format, ...)",
    "int asprintf(char **, const char *format, ...)",
    "int scanf(const char *format, ...)",
    "int fscanf(FILE *, const char *format, ...)",
    "int sscanf(const char *, const char *format, ...)",
    "int __isoc99_scanf(const char *format, ...)",
    "int __isoc99_fscanf(FILE *, const char *format, ...)",
    "int __isoc99_sscanf(const char *, const char *format, ...)",
    "int __isoc23_scanf(const char *format, ...)",
    "int __isoc23_fscanf(FILE *, const char *format, ...)",
    "int __isoc23_sscanf(const char *, const char *format, ...)",
    "int __printf_chk(int, const char *format, ...)",
    "int __fprintf_chk(FILE *, int, const char *format, ...)",
    "int __dprintf_chk(int, int, const char *format, ...)",
    "int __sprintf_chk(char *, int, size_t, const char *format, ...)",
    "int __snprintf_chk(char *, size_t, int, size_t, const char *format, ...)",
    "int __asprintf_chk(char **, int, const char *format, ...)",
    "void syslog(int, const char *format, ...)",
    "void err(int, const char *format, ...)",
    "void errx(int, const char *format, ...)",
    "void warn(const char *format, ...)",
    "void warnx(const char *format, ...)",
    "void error(int, int, const char *format, ...)",
    // fcntl.h, unistd.h, sys/wait.h, signal.h
    "int open(const char *, int, ...)",
    "int open64(const char *, int, ...)",
    "int openat(int, const char *, int, ...)",
    "int creat(const char *, mode_t)",
    "int fcntl(int, int, ...)",
    "int ioctl(int, unsigned long, ...)",
    "ssize_t read(int, void *, size_t)",
    "ssize_t __read_chk(int, void *, size_t, size_t)",
    "ssize_t write(int, const void *, size_t)",
    "ssize_t pread(int, void *, size_t, off_t)",
    "ssize_t pwrite(int, const void *, size_t, off_t)",
    "ssize_t readv(int, const struct iovec *, int)",
    "ssize_t writev(int, const struct iovec *, int)",
    "int close(int)",
    "off_t lseek(int, off_t, int)",
    "int pipe(int *)",
    "int pipe2(int *, int)",
    "int dup(int)",
    "int dup2(int, int)",
    "int dup3(int, int, int)",
    "int fsync(int)",
    "int ftruncate(int, off_t)",
    "int truncate(const char *, off_t)",
    "pid_t fork(void)",
    "pid_t vfork(void)",
    "pid_t getpid(void)",
    "pid_t getppid(void)",
    "pid_t gettid(void)",
    "pid_t setsid(void)",
    "uid_t getuid(void)",
    "uid_t geteuid(void)",
    "gid_t getgid(void)",
    "gid_t getegid(void)",
    "int setuid(uid_t)",
    "int setgid(gid_t)",
    "int execv(const char *, char **)",
    "int execvp(const char *, char **)",
    "int execve(const char *, char **, char **)",
    "int execl(const char *, const char *, ...)",
    "int execlp(const char *, const char *, ...)",
    "pid_t wait(int *)",
    "pid_t waitpid(pid_t, int *, int)",
    "unsigned int sleep(unsigned int)",
    "int usleep(useconds_t)",
    "unsigned int alarm(unsigned int)",
    "int pause(void)",
    "int access(const char *, int)",
    "int unlink(const char *)",
    "int rmdir(const char *)",
    "int chdir(const char *)",
    "int fchdir(int)",
    "char *getcwd(char *, size_t)",
    "int chown(const char *, uid_t, gid_t)",
    "int link(const char *, const char *)",
    "int symlink(const char *, const char *)",
    "ssize_t readlink(const char *, char *, size_t)",
    "int isatty(int)",
    "char *ttyname(int)",
    "long sysconf(int)",
    "int getpagesize(void)",
    "int gethostname(char *, size_t)",
    "int getopt(int, char **, const char *)",
    "void *sbrk(intptr_t)",
    "ssize_t getrandom(void *, size_t, unsigned int)",
    "int getentropy(void *, size_t)",
    "int kill(pid_t, int)",
    "int raise(int)",
    "void *signal(int, void (*)(int))",
    "int sigaction(int, const struct sigaction *, struct sigaction *)",
    "int sigemptyset(sigset_t *)",
    "int sigfillset(sigset_t *)",
    "int sigaddset(sigset_t *, int)",
    "int sigdelset(sigset_t *, int)",
    "int sigismember(const sigset_t *, int)",
    "int sigprocmask(int, const sigset_t *, sigset_t *)",
    "int getrlimit(int, struct rlimit *)",
    "int setrlimit(int, const struct rlimit *)",
    "int tcgetattr(int, struct termios *)",
    "int tcsetattr(int, int, const struct termios *)",
    // sys/stat.h, dirent.h
    "int stat(const char *, struct stat *)",
    "int fstat(int, struct stat *)",
    "int lstat(const char *, struct stat *)",
    "int fstatat(int, const char *, struct stat *, int)",
    "int __xstat(int, const char *, struct stat *)",
    "int __fxstat(int, int, struct stat *)",
    "int __lxstat(int, const char *, struct stat *)",
    "int mkdir(const char *, mode_t)",
    "int chmod(const char *, mode_t)",
    "int fchmod(int, mode_t)",
    "mode_t umask(mode_t)",
    "DIR *opendir(const char *)",
    "DIR *fdopendir(int)",
    "struct dirent *readdir(DIR *)",
    "int closedir(DIR *)",
    "void rewinddir(DIR *)",
    "int dirfd(DIR *)",
    // sys/mman.h
    "void *mmap(void *, size_t, int, int, int, off_t)",
    "void *mmap64(void *, size_t, int, int, int, off_t)",
    "int munmap(void *, size_t)",
    "int mprotect(void *, size_t, int)",
    "int madvise(void *, size_t, int)",
    "int msync(void *, size_t, int)",
    "int mlock(const void *, size_t)",
    "int munlock(const void *, size_t)",
    "int shm_open(const char *, int, mode_t)",
    "int shm_unlink(const char *)",
    // pthread.h, sched.h
    "int pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *)",
    "int pthread_join(pthread_t, void **)",
    "int pthread_detach(pthread_t)",
    "pthread_t pthread_self(void)",
    "int pthread_equal(pthread_t, pthread_t)",
    "void pthread_exit(void *)",
    "int pthread_cancel(pthread_t)",
    "int pthread_kill(pthread_t, int)",
    "int pthread_sigmask(int, const sigset_t *, sigset_t *)",
    "int pthread_once(pthread_once_t *, void (*)(void))",
    "int pthread_key_create(pthread_key_t *, void (*)(void *))",
    "int pthread_attr_init(pthread_attr_t *)",
    "int pthread_attr_destroy(pthread_attr_t *)",
    "int pthread_attr_setstacksize(pthread_attr_t *, size_t)",
    "int pthread_attr_setdetachstate(pthread_attr_t *, int)",
    "int pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *)",
    "int pthread_mutex_destroy(pthread_mutex_t *)",
    "int pthread_mutex_lock(pthread_mutex_t *)",
    "int pthread_mutex_trylock(pthread_mutex_t *)",
    "int pthread_mutex_unlock(pthread_mutex_t *)",
    "int pthread_mutexattr_init(pthread_mutexattr_t *)",
    "int pthread_mutexattr_destroy(pthread_mutexattr_t *)",
    "int pthread_mutexattr_settype(pthread_mutexattr_t *, int)",
    "int pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *)",
    "int pthread_cond_destroy(pthread_cond_t *)",
    "int pthread_cond_wait(pthread_cond_t *, pthread_mutex_t *)",
    "int pthread_cond_timedwait(pthread_cond_t *, pthread_mutex_t *, const struct timespec *)",
    "int pthread_cond_signal(pthread_cond_t *)",
    "int pthread_cond_broadcast(pthread_cond_t *)",
    "int pthread_rwlock_init(pthread_rwlock_t *, const pthread_rwlockattr_t *)",
    "int pthread_rwlock_destroy(pthread_rwlock_t *)",
    "int pthread_rwlock_rdlock(pthread_rwlock_t *)",
    "int pthread_rwlock_wrlock(pthread_rwlock_t *)",
    "int pthread_rwlock_unlock(pthread_rwlock_t *)",
    "int sched_yield(void)",
    // time.h, sys/time.h
    "time_t time(time_t *)",
    "clock_t clock(void)",
    "int clock_gettime(clockid_t, struct timespec *)",
    "int clock_getres(clockid_t, struct timespec *)",
    "int clock_nanosleep(clockid_t, int, const struct timespec *, struct timespec *)",
    "int nanosleep(const struct timespec *, struct timespec *)",
    "int gettimeofday(struct timeval *, void *)",
    "struct tm *localtime(const time_t *)",
    "struct tm *gmtime(const time_t *)",
    "struct tm *localtime_r(const time_t *, struct tm *)",
    "struct tm *gmtime_r(const time_t *, struct tm *)",
    "time_t mktime(struct tm *)",
    "size_t strftime(char *, size_t, const char *, const struct tm *)",
    "char *ctime(const time_t *)",
    "char *asctime(const struct tm *)",
    "double difftime(time_t, time_t)",
    // math.h
    "double sqrt(double)",
    "double cbrt(double)",
    "double fabs(double)",
    "double floor(double)",
    "double ceil(double)",
    "double round(double)",
    "double trunc(double)",
    "double rint(double)",
    "double nearbyint(double)",
    "double exp(double)",
    "double exp2(double)",
    "double expm1(double)",
    "double log(double)",
    "double log2(double)",
    "double log10(double)",
    "double log1p(double)",
    "double sin(double)",
    "double cos(double)",
    "double tan(double)",
    "double asin(double)",
    "double acos(double)",
    "double atan(double)",
    "double sinh(double)",
    "double cosh(double)",
    "double tanh(double)",
    "double atan2(double, double)",
    "double pow(double, double)",
    "double fmod(double, double)",
    "double hypot(double, double)",
    "double fmin(double, double)",
    "double fmax(double, double)",
    "double copysign(double, double)",
    "double ldexp(double, int)",
    "double frexp(double, int *)",
    "double modf(double, double *)",
    "long lround(double)",
    "long lrint(double)",
    "long long llround(double)",
    "float sqrtf(float)",
    "float cbrtf(float)",
    "float fabsf(float)",
    "float floorf(float)",
    "float ceilf(float)",
    "float roundf(float)",
    "float truncf(float)",
    "float expf(float)",
    "float exp2f(float)",
    "float logf(float)",
    "float log2f(float)",
    "float log10f(float)",
    "float sinf(float)",
    "float cosf(float)",
    "float tanf(float)",
    "float atanf(float)",
    "float tanhf(float)",
    "float atan2f(float, float)",
    "float powf(float, float)",
    "float fmodf(float, float)",
    "float hypotf(float, float)",
    "float fminf(float, float)",
    "float fmaxf(float, float)",
    "float ldexpf(float, int)",
    "long lroundf(float)",
    // sys/socket.h, netdb.h, arpa/inet.h, poll.h, sys/select.h, sys/epoll.h
    "int socket(int, int, int)",
    "int socketpair(int, int, int, int *)",
    "int bind(int, const struct sockaddr *, socklen_t)",
    "int connect(int, const struct sockaddr *, socklen_t)",
    "int listen(int, int)",
    "int accept(int, struct sockaddr *, socklen_t *)",
    "int accept4(int, struct sockaddr *, socklen_t *, int)",
    "ssize_t send(int, const void *, size_t, int)",
    "ssize_t recv(int, void *, size_t, int)",
    "ssize_t sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t)",
    "ssize_t recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *)",
    "ssize_t sendmsg(int, const struct msghdr *, int)",
    "ssize_t recvmsg(int, struct msghdr *, int)",
    "int setsockopt(int, int, int, const void *, socklen_t)",
    "int getsockopt(int, int, int, void *, socklen_t *)",
    "int getsockname(int, struct sockaddr *, socklen_t *)",
    "int getpeername(int, struct sockaddr *, socklen_t *)",
    "int shutdown(int, int)",
    "int getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **)",
    "void freeaddrinfo(struct addrinfo *)",
    "const char *gai_strerror(int)",
    "struct hostent *gethostbyname(const char *)",
    "uint32_t htonl(uint32_t)",
    "uint32_t ntohl(uint32_t)",
    "uint16_t htons(uint16_t)",
    "uint16_t ntohs(uint16_t)",
    "in_addr_t inet_addr(const char *)",
    "int inet_pton(int, const char *, void *)",
    "const char *inet_ntop(int, const void *, char *, socklen_t)",
    "int poll(struct pollfd *, nfds_t, int)",
    "int select(int, fd_set *, fd_set *, fd_set *, struct timeval *)",
    "int epoll_create1(int)",
    "int epoll_ctl(int, int, int, struct epoll_event *)",
    "int epoll_wait(int, struct epoll_event *, int, int)",
    // dlfcn.h, locale.h
    "void *dlopen(const char *, int)",
    "void *dlsym(void *, const char *)",
    "int dlclose(void *)",
    "char *dlerror(void)",
    "char *setlocale(int, const char *)",
];

/// The C++ runtime's entry points as demangled, by their mangled names.
const DEMANGLED: &[(&str, &str)] = &[
    ("operator new(unsigned long)", "_Znwm"),
    ("operator new[](unsigned long)", "_Znam"),
    (
        "operator new(unsigned long, std::nothrow_t const&)",
        "_ZnwmRKSt9nothrow_t",
    ),
    (
        "operator new[](unsigned long, std::nothrow_t const&)",
        "_ZnamRKSt9nothrow_t",
    ),
    (
        "operator new(unsigned long, std::align_val_t)",
        "_ZnwmSt11align_val_t",
    ),
    (
        "operator new[](unsigned long, std::align_val_t)",
        "_ZnamSt11align_val_t",
    ),
    ("operator delete(void*)", "_ZdlPv"),
    ("operator delete[](void*)", "_ZdaPv"),
    ("operator delete(void*, unsigned long)", "_ZdlPvm"),
    ("operator delete[](void*, unsigned long)", "_ZdaPvm"),
    (
        "operator delete(void*, std::align_val_t)",
        "_ZdlPvSt11align_val_t",
    ),
    (
        "operator delete[](void*, std::align_val_t)",
        "_ZdaPvSt11align_val_t",
    ),
    (
        "operator delete(void*, unsigned long, std::align_val_t)",
        "_ZdlPvmSt11align_val_t",
    ),
    (
        "operator delete[](void*, unsigned long, std::align_val_t)",
        "_ZdaPvmSt11align_val_t",
    ),
    ("std::terminate()", "_ZSt9terminatev"),
];

/// Functions of the Go and Rust runtimes whose arguments have stayed the
/// same across releases, as their arguments arrive in the registers of the
/// language's own convention. A Go `int` and `uintptr` are 64 bits.
const RUNTIME: &[&str] = &[
    "void runtime.memmove(void *, const void *, uintptr_t)",
    "void runtime.memclrNoHeapPointers(void *, uintptr_t)",
    "_Bool runtime.memequal(const void *, const void *, uintptr_t)",
    "uintptr_t runtime.memhash(const void *, uintptr_t, uintptr_t)",
    "void *runtime.mallocgc(uintptr_t, void *, _Bool)",
    "void *runtime.newobject(void *)",
    "void *runtime.makeslice(void *, int64_t, int64_t)",
    "void runtime.typedmemmove(void *, void *, const void *)",
    "void runtime.throw(const uint8_t *, int64_t)",
    "void runtime.printstring(const uint8_t *, int64_t)",
    "void runtime.printint(int64_t)",
    "int64_t runtime.nanotime1(void)",
    "void runtime.usleep(uint32_t)",
    "void runtime.exit(int32_t)",
    "uint8_t *__rust_alloc(size_t, size_t)",
    "uint8_t *__rust_alloc_zeroed(size_t, size_t)",
    "void __rust_dealloc(uint8_t *, size_t, size_t)",
    "uint8_t *__rust_realloc(uint8_t *, size_t, size_t, size_t)",
    "uint8_t *__rdl_alloc(size_t, size_t)",
    "uint8_t *__rdl_alloc_zeroed(size_t, size_t)",
    "void __rdl_dealloc(uint8_t *, size_t, size_t)",
    "uint8_t *__rdl_realloc(uint8_t *, size_t, size_t, size_t)",
    "void core::panicking::panic(const uint8_t *, size_t, const void *)",
    "void core::panicking::panic_fmt(const void *, const void *)",
    "void core::panicking::panic_bounds_check(size_t, size_t, const void *)",
];

/// Members of the structures whose layout is the same on every platform
/// the prototypes are written for: name, then each member's offset and
/// name.
const LAYOUTS: &[(&str, &[(i64, &str)])] = &[
    ("timespec", &[(0, "tv_sec"), (8, "tv_nsec")]),
    ("timeval", &[(0, "tv_sec"), (8, "tv_usec")]),
    ("iovec", &[(0, "iov_base"), (8, "iov_len")]),
    ("pollfd", &[(0, "fd"), (4, "events"), (6, "revents")]),
    ("rlimit", &[(0, "rlim_cur"), (8, "rlim_max")]),
    (
        "tm",
        &[
            (0, "tm_sec"),
            (4, "tm_min"),
            (8, "tm_hour"),
            (12, "tm_mday"),
            (16, "tm_mon"),
            (20, "tm_year"),
            (24, "tm_wday"),
            (28, "tm_yday"),
            (32, "tm_isdst"),
            (40, "tm_gmtoff"),
            (48, "tm_zone"),
        ],
    ),
];

type Table = HashMap<&'static str, Prototype>;

fn table(declarations: &'static [&'static str]) -> Table {
    declarations
        .iter()
        .map(|declaration| parse(declaration))
        .collect()
}

fn library() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(|| table(LIBRARY))
}

fn runtime_table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(|| table(RUNTIME))
}

/// A declaration from the tables as its name and prototype.
fn parse(declaration: &'static str) -> (&'static str, Prototype) {
    let open = declaration.find('(').expect("a parameter list");
    let (head, rest) = declaration.split_at(open);
    let list = rest[1..]
        .strip_suffix(')')
        .expect("a closed parameter list");
    let at = head.rfind([' ', '*']).map_or(0, |at| at + 1);
    let (ret, name) = head.split_at(at);
    let mut params = Vec::new();
    let mut variadic = false;
    let mut format = None;
    let mut depth = 0;
    let mut start = 0;
    let mut pieces = Vec::new();
    for (at, c) in list.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                pieces.push(&list[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    pieces.push(&list[start..]);
    for piece in pieces.iter().map(|piece| piece.trim()) {
        match piece {
            "void" | "" => {}
            "..." => variadic = true,
            _ => {
                let ty = match piece.strip_suffix("format") {
                    Some(ty) => {
                        format = Some(
                            params
                                .iter()
                                .filter(|ty: &&CType| !ty.is_sse_float())
                                .count(),
                        );
                        ty
                    }
                    None => piece,
                };
                params.push(parse_type(ty));
            }
        }
    }
    (
        name,
        Prototype {
            params,
            ret: parse_type(ret),
            variadic,
            format,
            scans: name.contains("scanf"),
        },
    )
}

/// `const char *` as the pointer to `const char` it is.
fn parse_type(text: &str) -> CType {
    let text = text.trim();
    // A pointer to a function points at code.
    if text.contains("(*") {
        return CType::pointer_to(CType::Void);
    }
    match text.strip_suffix('*') {
        Some(target) => CType::pointer_to(parse_type(target)),
        None if text == "void" => CType::Void,
        None => CType::Named(text.to_owned()),
    }
}

/// The name a library function goes by without the decorations its
/// symbol carries: `@plt` or a version, and Mach-O's `$` variants.
fn undecorated(name: &str, macho: bool) -> &str {
    let name = name.split('@').next().unwrap_or(name);
    if !macho {
        return name;
    }
    name.split('$').next().unwrap_or(name)
}

/// The prototype a library function's name gives, whatever symbol
/// decorations it carries.
#[must_use]
pub fn of(name: &str, macho: bool) -> Option<&'static Prototype> {
    let name = undecorated(name, macho);
    let c_name = if macho {
        name.strip_prefix('_').unwrap_or(name)
    } else {
        name
    };
    for candidate in [c_name, name] {
        let candidate = DEMANGLED
            .iter()
            .find(|(demangled, _)| *demangled == candidate)
            .map_or(candidate, |(_, mangled)| mangled);
        if macho && let Some(prototype) = generated::of(candidate) {
            return Some(prototype);
        }
        if let Some(prototype) = library().get(candidate) {
            return Some(prototype);
        }
    }
    None
}

/// The prototype of a function of the Go or Rust runtime, by its name.
#[must_use]
pub fn runtime(name: &str) -> Option<&'static Prototype> {
    let name = name.strip_prefix("__rustc::").unwrap_or(name);
    runtime_table().get(name)
}

/// The prototype of the function a call reaches: an import, through its
/// linkage stub or its slot, or a runtime function the binary defines.
pub fn called(image: &Image, stmt: &Stmt) -> Option<&'static Prototype> {
    let macho = image.format == crate::loader::Format::MachO;
    let Stmt::Call {
        target, through, ..
    } = stmt
    else {
        return None;
    };
    if let Some(through) = through {
        return crate::lift::import_name(image, through).and_then(|name| of(name, macho));
    }
    let Some(target) = target else {
        return None;
    };
    let Some(function) = image.functions.get(target) else {
        return None;
    };
    let Some(name) = function.name.as_deref() else {
        return None;
    };
    if function.sources.contains(&NameSource::Plt) {
        of(name, macho)
    } else {
        runtime(name)
    }
}

pub(crate) fn scalar_call_output<'a>(
    stmt: &'a Stmt,
    ret: &CType,
) -> Option<&'a crate::ir::CallOutput> {
    if ret.is_sse_float() {
        let Stmt::Call { convention, .. } = stmt else {
            return None;
        };
        let register = match convention {
            crate::ir::Convention::SysV | crate::ir::Convention::Win64 => crate::arch::x86::XMM0,
            crate::ir::Convention::Aapcs64 => crate::arch::aarch64::V0,
            _ => return None,
        };
        stmt.call_outputs()
            .iter()
            .find(|output| output.register == register)
    } else if ret.integer().is_some() || ret.is_pointer() {
        stmt.primary_call_output()
    } else {
        None
    }
}

/// The members of a structure whose layout is known, by offset.
#[must_use]
pub fn layout(structure: &str) -> Option<&'static [(i64, &'static str)]> {
    LAYOUTS
        .iter()
        .find(|(name, _)| *name == structure)
        .map(|(_, members)| *members)
}

/// The type that says more of a value two uses give a type: a pointer to
/// something rather than to nothing in particular; otherwise the first.
#[must_use]
pub fn preferred(first: CType, second: &CType) -> CType {
    if void_pointer(&first) && second.is_pointer() {
        second.clone()
    } else {
        first
    }
}

/// `void *` or `const void *`, which say only that a value is a pointer.
#[must_use]
pub fn void_pointer(ty: &CType) -> bool {
    match ty {
        CType::Pointer(target) => match target.as_ref() {
            CType::Void => true,
            CType::Named(name) => name == "const void",
            _ => false,
        },
        _ => false,
    }
}

/// The types of the integer and pointer arguments a format string's
/// conversions take, in order, with each `*` width or precision an `int`;
/// `%%` takes none, and a floating-point value goes in a vector register
/// rather than an argument register. The conversions of a function that
/// `scans` its input take pointers to what they read.
#[must_use]
pub fn conversion_types(format: &str, scans: bool) -> Vec<CType> {
    let named = |name: &str| CType::Named(name.to_owned());
    let mut types = Vec::new();
    let mut chars = format.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            continue;
        }
        if chars.peek() == Some(&'%') {
            chars.next();
            continue;
        }
        // Flags, width, precision and length, up to the conversion letter.
        let mut length = String::new();
        // In input, `*` reads a value and stores it nowhere.
        let mut suppressed = false;
        while let Some(&next) = chars.peek() {
            chars.next();
            if next == '*' {
                if scans {
                    suppressed = true;
                } else {
                    types.push(named("int"));
                }
            } else if matches!(next, 'h' | 'l' | 'q' | 'j' | 'z' | 't' | 'L') {
                length.push(next);
            } else if next.is_ascii_alphabetic() || next == '[' {
                let integer = |signed: bool| {
                    let base = match length.as_str() {
                        "l" | "j" | "t" => "long",
                        "ll" | "q" => "long long",
                        "z" if signed => "ssize_t",
                        "z" => "size_t",
                        "h" if scans => "short",
                        "hh" if scans => "char",
                        _ => "int",
                    };
                    match (signed, base) {
                        (false, "ssize_t" | "size_t") => named("size_t"),
                        (false, base) => named(&format!("unsigned {base}")),
                        (true, base) => named(base),
                    }
                };
                let ty = match next {
                    _ if suppressed => {
                        if next == '[' {
                            for c in chars.by_ref().skip(1) {
                                if c == ']' {
                                    break;
                                }
                            }
                        }
                        break;
                    }
                    'd' | 'i' => integer(true),
                    'u' | 'x' | 'X' | 'o' => integer(false),
                    'c' if !scans => named("int"),
                    // glibc's `%m` prints the error `errno` holds.
                    'm' => break,
                    'c' | 's' | '[' if scans => {
                        // A scanned set runs to its closing bracket.
                        if next == '[' {
                            if chars.peek() == Some(&']') {
                                chars.next();
                            }
                            for c in chars.by_ref() {
                                if c == ']' {
                                    break;
                                }
                            }
                        }
                        types.push(CType::pointer_to(named("char")));
                        break;
                    }
                    's' => CType::pointer_to(named("const char")),
                    'p' => CType::pointer_to(CType::Void),
                    'n' => CType::pointer_to(named("int")),
                    'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A' if scans => {
                        let float = match length.as_str() {
                            "l" => "double",
                            "L" => "long double",
                            _ => "float",
                        };
                        types.push(CType::pointer_to(named(float)));
                        break;
                    }
                    'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A' => break,
                    // Some other letter: an argument of no type known.
                    _ => CType::U64,
                };
                types.push(if scans { CType::pointer_to(ty) } else { ty });
                break;
            }
        }
    }
    types
}

#[cfg(test)]
mod tests {
    use super::{LIBRARY, RUNTIME, conversion_types, layout, of, parse, runtime};
    use crate::ir::CType;

    #[test]
    fn library_names_give_their_arity() {
        assert_eq!(of("fputs", false).map(|p| p.fixed()), Some(2));
        assert_eq!(of("memcpy@GLIBC_2.14", false).map(|p| p.fixed()), Some(3));
        assert_eq!(of("_strlen", true).map(|p| p.fixed()), Some(1));
        for name in ["memcpy", "_memcpy", "memset", "_memset"] {
            assert_eq!(of(name, true).map(|p| p.fixed()), Some(3));
        }
        for name in ["__memcpy_chk", "___memcpy_chk"] {
            assert_eq!(of(name, true).map(|p| p.fixed()), Some(4));
        }
        for name in ["_Unwind_Resume", "__Unwind_Resume"] {
            assert_eq!(of(name, true).map(|p| p.fixed()), Some(1));
        }
        let printf = of("__printf_chk", false).expect("known");
        assert_eq!((printf.fixed(), printf.format), (2, Some(1)));
        let open = of("open", false).expect("known");
        assert_eq!((open.fixed(), open.variadic, open.format), (2, true, None));
    }

    #[test]
    fn declarations_give_the_types_of_parameters_and_results() {
        let strlen = of("strlen", false).expect("known");
        assert_eq!(strlen.ret, CType::Named("size_t".to_owned()));
        assert_eq!(
            strlen.params,
            [CType::pointer_to(CType::Named("const char".to_owned()))]
        );
        assert_eq!(strlen.params[0].to_string(), "const char *");
        let qsort = of("qsort", false).expect("known");
        assert_eq!(qsort.params.len(), 4);
        assert_eq!(qsort.params[3], CType::pointer_to(CType::Void));
        assert_eq!(qsort.ret, CType::Void);
        assert_eq!(qsort.pointers(), 0b1001);
        let strtol = of("strtol", false).expect("known");
        assert_eq!(strtol.params[1].to_string(), "char **");
        assert!(of("strcmp", false).expect("known").narrow_return());
        assert!(!of("strlen", false).expect("known").narrow_return());
    }

    #[test]
    fn float_arguments_are_counted_apart() {
        let ldexp = of("ldexp", false).expect("known");
        assert_eq!((ldexp.fixed(), ldexp.floats()), (1, 1));
        let pow = of("_pow", true).expect("known");
        assert_eq!((pow.fixed(), pow.floats()), (0, 2));
    }

    #[test]
    fn decorated_and_demangled_names_find_their_prototypes() {
        assert_eq!(of("_stat$INODE64", true), of("stat", false));
        assert_eq!(of("operator new(unsigned long)", false), of("_Znwm", false));
        assert_eq!(runtime("__rustc::__rust_alloc").map(|p| p.fixed()), Some(2));
        assert_eq!(runtime("runtime.memmove").map(|p| p.fixed()), Some(3));
        assert!(runtime("strlen").is_none());
    }

    #[test]
    fn every_declaration_parses_into_a_type_the_analysis_knows() {
        for declaration in LIBRARY.iter().chain(RUNTIME) {
            let (name, prototype) = parse(declaration);
            assert!(!name.is_empty(), "{declaration}");
            for ty in prototype.params.iter().chain([&prototype.ret]) {
                // Every scalar has a known width; anything else is a pointer
                // or a float.
                assert!(
                    matches!(ty, CType::Void | CType::Pointer(_))
                        || ty.is_sse_float()
                        || ty.integer().is_some(),
                    "{declaration}: {ty}"
                );
            }
        }
    }

    #[test]
    fn known_layouts_name_their_members() {
        assert_eq!(
            layout("timespec").map(|members| members[1].1),
            Some("tv_nsec")
        );
        assert!(layout("stat").is_none());
    }

    #[test]
    fn conversions_count_the_variadic_arguments() {
        let count = |format: &str| conversion_types(format, false).len();
        assert_eq!(count("missing key %d among %d"), 2);
        assert_eq!(count("  %s=%d\n"), 2);
        assert_eq!(count("100%% %*.*ld"), 3);
        assert_eq!(count("no conversions"), 0);
        assert_eq!(count("%d %.2f"), 1);
    }

    #[test]
    fn conversions_give_the_types_of_the_variadic_arguments() {
        let types = |format: &str, scans: bool| -> Vec<String> {
            conversion_types(format, scans)
                .iter()
                .map(ToString::to_string)
                .collect()
        };
        assert_eq!(
            types("%s=%lu (%zu) %p %x", false),
            [
                "const char *",
                "unsigned long",
                "size_t",
                "void *",
                "unsigned int"
            ]
        );
        assert_eq!(
            types("%*d %lld %c", false),
            ["int", "int", "long long", "int"]
        );
        assert_eq!(
            types("%d %15s %lf %[^,] %hhu", true),
            ["int *", "char *", "double *", "char *", "unsigned char *"]
        );
        assert_eq!(
            types("%d %15s %*d %lf %[^,] %*[]x] %hhu", true),
            ["int *", "char *", "double *", "char *", "unsigned char *"]
        );
    }
}
