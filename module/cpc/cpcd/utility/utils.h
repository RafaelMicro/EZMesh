

#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <string.h>

#define SIZEOF_MEMBER(T, m) (sizeof(((T *)0)->m))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define PAD_TO_8_BYTES(x) (x + 8 - (x % 8))

static inline void *calloc_port(size_t size)
{
    return calloc(1, size);
}

int recursive_mkdir(const char *dir, size_t len, const mode_t mode);

#endif
