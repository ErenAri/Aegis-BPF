/*
 * glibc_compat.c — Weak-symbol shims for glibc 2.38+ functions.
 *
 * When building on Ubuntu 24.04 (glibc 2.38) with -static-libstdc++
 * -static-libgcc, the static archives reference symbols that don't
 * exist on older glibcs:
 *
 *   __isoc23_strtoul  (GLIBC_2.38)  — C23 strtol family
 *   arc4random        (GLIBC_2.36)  — random number generator
 *   _dl_find_object   (GLIBC_2.35)  — fast exception unwinding
 *
 * These weak stubs satisfy the linker.  At runtime on a newer glibc
 * the real symbols override them; on older glibc the stubs provide
 * compatible fallback behavior.
 *
 * This file MUST be compiled with the glibc_compat.h force-include
 * (PORTABLE_GLIBC=ON) so that strtoul/strtoull are NOT redirected
 * to their __isoc23_* variants.
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef __linux__
#include <sys/random.h>  /* getrandom() — available since glibc 2.25 */
#endif

/* ---- __isoc23_strtoul / strtoull ---------------------------------------- */
/* The C23 versions add 0b/0B binary-literal support.  libstdc++'s
   debug.o and eh_alloc.o call these for env-var parsing where binary
   literals are irrelevant, so forwarding to the C11 versions is safe. */

__attribute__((weak))
unsigned long
__isoc23_strtoul(const char *nptr, char **endptr, int base)
{
    return strtoul(nptr, endptr, base);
}

__attribute__((weak))
unsigned long long
__isoc23_strtoull(const char *nptr, char **endptr, int base)
{
    return strtoull(nptr, endptr, base);
}

__attribute__((weak))
long
__isoc23_strtol(const char *nptr, char **endptr, int base)
{
    return strtol(nptr, endptr, base);
}

__attribute__((weak))
int
__isoc23_sscanf(const char *str, const char *fmt, ...)
{
    /* Forward via vsscanf.  We need the va_list variant. */
    int ret;
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    ret = vsscanf(str, fmt, ap);
    __builtin_va_end(ap);
    return ret;
}

/* ---- arc4random --------------------------------------------------------- */
/* libstdc++'s random_device uses arc4random (glibc 2.36+).
   Fall back to getrandom() which is available since glibc 2.25. */

__attribute__((weak))
uint32_t
arc4random(void)
{
    uint32_t val;
#ifdef __linux__
    /* GRND_NONBLOCK is not set — block until entropy is available. */
    if (getrandom(&val, sizeof(val), 0) == (ssize_t)sizeof(val))
        return val;
#endif
    /* Last resort (should never happen on a running Linux system). */
    return (uint32_t)random();
}

/* ---- _dl_find_object ---------------------------------------------------- */
/* Used by libgcc_s/libgcc_eh for fast exception-frame lookup (glibc 2.35+).
   Returning -1 tells the unwinder to fall back to dl_iterate_phdr,
   which is slower but always available. */

struct dl_find_object;  /* opaque — we never fill it in */

__attribute__((weak))
int
_dl_find_object(void *address, struct dl_find_object *result)
{
    (void)address;
    (void)result;
    return -1;  /* "not found" → unwinder uses fallback path */
}
