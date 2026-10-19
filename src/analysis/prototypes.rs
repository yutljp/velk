//! How many arguments common library functions take, for calls into code
//! the binary only imports. A variadic function names the argument holding
//! its format string, whose conversions count the arguments that follow.

/// The arguments a function takes before any variadic ones, and the
/// position of its format string when it is variadic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prototype {
    pub fixed: usize,
    pub format: Option<usize>,
}

const FIXED: &[(&str, usize)] = &[
    ("abort", 0),
    ("exit", 1),
    ("_exit", 1),
    ("_Exit", 1),
    ("atexit", 1),
    ("__cxa_atexit", 3),
    ("__cxa_finalize", 1),
    ("__libc_start_main", 7),
    ("__stack_chk_fail", 0),
    ("__assert_fail", 4),
    ("_Unwind_Resume", 1),
    ("__cxa_throw", 3),
    ("__cxa_allocate_exception", 1),
    ("__cxa_begin_catch", 1),
    ("__cxa_end_catch", 0),
    ("malloc", 1),
    ("calloc", 2),
    ("realloc", 2),
    ("free", 1),
    ("aligned_alloc", 2),
    ("posix_memalign", 3),
    ("memcpy", 3),
    ("memmove", 3),
    ("memset", 3),
    ("memcmp", 3),
    ("memchr", 3),
    ("__memcpy_chk", 4),
    ("__memmove_chk", 4),
    ("__memset_chk", 4),
    ("strlen", 1),
    ("strnlen", 2),
    ("strcmp", 2),
    ("strncmp", 3),
    ("strcasecmp", 2),
    ("strcpy", 2),
    ("strncpy", 3),
    ("stpcpy", 2),
    ("strcat", 2),
    ("strncat", 3),
    ("strchr", 2),
    ("strrchr", 2),
    ("strstr", 2),
    ("strdup", 1),
    ("strndup", 2),
    ("strtol", 3),
    ("strtoul", 3),
    ("strtoll", 3),
    ("strtoull", 3),
    ("strtod", 2),
    ("atoi", 1),
    ("atol", 1),
    ("getenv", 1),
    ("setenv", 3),
    ("puts", 1),
    ("putchar", 1),
    ("fputs", 2),
    ("fputc", 2),
    ("putc", 2),
    ("fgets", 3),
    ("fgetc", 1),
    ("getc", 1),
    ("getchar", 0),
    ("fopen", 2),
    ("fdopen", 2),
    ("fclose", 1),
    ("fflush", 1),
    ("fread", 4),
    ("fwrite", 4),
    ("fseek", 3),
    ("ftell", 1),
    ("fileno", 1),
    ("perror", 1),
    ("strerror", 1),
    ("__errno_location", 0),
    ("read", 3),
    ("write", 3),
    ("close", 1),
    ("lseek", 3),
    ("pipe", 1),
    ("dup", 1),
    ("dup2", 2),
    ("fork", 0),
    ("getpid", 0),
    ("kill", 2),
    ("signal", 2),
    ("sigaction", 3),
    ("mmap", 6),
    ("munmap", 2),
    ("mprotect", 3),
    ("qsort", 4),
    ("bsearch", 5),
    ("time", 1),
    ("clock_gettime", 2),
    ("gettimeofday", 2),
    ("sleep", 1),
    ("usleep", 1),
    ("rand", 0),
    ("srand", 1),
    ("isatty", 1),
    ("setlocale", 2),
    ("pthread_create", 4),
    ("pthread_join", 2),
    ("pthread_mutex_lock", 1),
    ("pthread_mutex_unlock", 1),
    ("pthread_mutex_init", 2),
    ("pthread_self", 0),
    ("dlopen", 2),
    ("dlsym", 2),
    ("dlclose", 1),
];

const VARIADIC: &[(&str, usize, usize)] = &[
    // (name, arguments before the variadic ones, position of the format)
    ("printf", 1, 0),
    ("fprintf", 2, 1),
    ("dprintf", 2, 1),
    ("sprintf", 2, 1),
    ("snprintf", 3, 2),
    ("scanf", 1, 0),
    ("fscanf", 2, 1),
    ("sscanf", 2, 1),
    ("__printf_chk", 2, 1),
    ("__fprintf_chk", 3, 2),
    ("__sprintf_chk", 4, 3),
    ("__snprintf_chk", 5, 4),
    ("__dprintf_chk", 3, 2),
    ("syslog", 2, 1),
    ("err", 2, 1),
    ("errx", 2, 1),
    ("warn", 1, 0),
    ("warnx", 1, 0),
    ("open", 2, usize::MAX),
    ("ioctl", 2, usize::MAX),
    ("fcntl", 2, usize::MAX),
];

/// The prototype a library function's name gives, whatever symbol
/// decorations it carries (`@plt`, a version, Mach-O's leading underscore).
pub fn of(name: &str, macho: bool) -> Option<Prototype> {
    let name = name.split('@').next().unwrap_or(name);
    let name = match name.strip_prefix('_') {
        Some(rest) if macho => rest,
        _ => name,
    };
    if let Some((_, fixed)) = FIXED.iter().find(|(known, _)| *known == name) {
        return Some(Prototype {
            fixed: *fixed,
            format: None,
        });
    }
    VARIADIC
        .iter()
        .find(|(known, ..)| *known == name)
        .map(|(_, fixed, format)| Prototype {
            fixed: *fixed,
            // A variadic function with no format string passes no more that
            // a decompiler can count.
            format: (*format != usize::MAX).then_some(*format),
        })
}

/// How many integer arguments a format string's conversions take, with each
/// `*` width or precision one more; `%%` takes none, and a floating-point
/// conversion takes a vector register rather than an argument register.
pub fn format_arguments(format: &str) -> usize {
    let mut count = 0;
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
        while let Some(&next) = chars.peek() {
            if next == '*' {
                count += 1;
                chars.next();
            } else if next.is_ascii_alphabetic()
                && !matches!(next, 'h' | 'l' | 'q' | 'j' | 'z' | 't' | 'L')
            {
                chars.next();
                if !matches!(next, 'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A') {
                    count += 1;
                }
                break;
            } else {
                chars.next();
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::{format_arguments, of};

    #[test]
    fn library_names_give_their_arity() {
        assert_eq!(of("fputs", false).map(|p| p.fixed), Some(2));
        assert_eq!(of("memcpy@GLIBC_2.14", false).map(|p| p.fixed), Some(3));
        assert_eq!(of("_strlen", true).map(|p| p.fixed), Some(1));
        let printf = of("__printf_chk", false).expect("known");
        assert_eq!((printf.fixed, printf.format), (2, Some(1)));
    }

    #[test]
    fn conversions_count_the_variadic_arguments() {
        assert_eq!(format_arguments("missing key %d among %d"), 2);
        assert_eq!(format_arguments("  %s=%d\n"), 2);
        assert_eq!(format_arguments("100%% %*.*ld"), 3);
        assert_eq!(format_arguments("no conversions"), 0);
        assert_eq!(format_arguments("%d %.2f"), 1);
    }
}
