#ifndef HAL_MEMORY_H
#define HAL_MEMORY_H

#define _GNU_SOURCE

#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#define HAL_MEM_ALLOC(size) hal_mem_alloc(__FILE__, __LINE__, (size_t)(size), false)

#define HAL_MEM_FREE(ptr) hal_mem_free(__FILE__, __LINE__, (uint8_t **)(ptr), false)

#define HAL_MEM_ALLOC_TRACE(size) hal_mem_alloc(__FILE__, __LINE__, (size_t)(size), true)

#define HAL_MEM_FREE_TRACE(ptr) hal_mem_free(__FILE__, __LINE__, (uint8_t **)(ptr), true)

void hal_mem_free(const char *file, int line, uint8_t **ptr, bool trace);

uint8_t *hal_mem_alloc(const char *file, int line, size_t size, bool trace);

void hal_mem_print();

void hal_mem_table_clean();

#endif
