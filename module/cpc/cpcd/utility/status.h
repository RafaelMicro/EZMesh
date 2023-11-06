#ifndef STATUS_H
#define STATUS_H

#include <stdint.h>

typedef enum
{
    STATUS_OK = 0,
    STATUS_FAIL,
    STATUS_IN_PROGRESS = 5,
    STATUS_ABORT,
    STATUS_TIMEOUT,
    STATUS_WOULD_BLOCK = 9,
}E_STATUS;

typedef uint32_t status_t;

#endif /* STATUS_H */
