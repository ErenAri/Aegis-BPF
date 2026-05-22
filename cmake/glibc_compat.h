/*
 * glibc_compat.h — Suppress glibc 2.38+ C23 symbol redirections.
 *
 * On glibc 2.38+, _GNU_SOURCE (always defined by GCC/Clang for C++)
 * enables _ISOC2X_SOURCE → __GLIBC_USE_ISOC2X=1 → strtol/sscanf/etc.
 * get redirected to __isoc23_strtol/__isoc23_sscanf via __REDIRECT.
 * These symbols don't exist on older glibc (Debian 12 = 2.36,
 * Rocky 9 = 2.34), making the binary uninstallable there.
 *
 * Including <features.h> first (with its include guard) then
 * overriding the macros prevents the redirections in <stdlib.h>,
 * <stdio.h>, and <wchar.h> while keeping all other _GNU_SOURCE
 * extensions intact.
 *
 * Force-included via -include cmake/glibc_compat.h when
 * PORTABLE_GLIBC is ON.
 */
#include <features.h>
#undef __GLIBC_USE_ISOC2X
#define __GLIBC_USE_ISOC2X 0
#undef __GLIBC_USE_C2X_STRTOL
#define __GLIBC_USE_C2X_STRTOL 0
