#define _GNU_SOURCE

#include "hal_memory.h"
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "utility/log.h"

typedef struct hal_memory hal_memory_t;
struct hal_memory
{
  uint8_t type;
  uint8_t* file;
  uint32_t line;
  uintptr_t ptr;
  size_t len;
  hal_memory_t* next;
};

typedef uint8_t hal_memory_status_t;
enum hal_memory_status_t
{
  HAL_MEM_TYPE_CALLOC,
  HAL_MEM_TYPE_FREE,
  HAL_MEM_TYPE_MALLOC,
  HAL_MEM_TYPE_REALLOC,
};

hal_memory_t* mem_table = NULL;

static uint8_t* hal_mem_safe_alloc(const char *file, int line, size_t size){
  uint8_t *ptr = calloc(1, size);
  if (ptr == NULL) {
    log_error("[HAL] Failed to allocate memory at %s:%d", file, line);
    signal_crash();
  }
  return ptr;
}

static hal_memory_t* hal_mem_create_debug_record(const char *file, int line, hal_memory_status_t type, uint8_t *ptr, size_t size){
  hal_memory_t* record = (hal_memory_t*)hal_mem_safe_alloc(file, line, sizeof(hal_memory_t));
  record->file = hal_mem_safe_alloc(file, line, strlen(file)+1);
  memccpy(record->file, file, (int)(strlen(file)+1), (size_t)(strlen(file)+1));
  record->type = type;
  record->line = (uint32_t)line;
  record->ptr = (uintptr_t)ptr;
  record->len = size;
  record->next = NULL;
  return record;
}

static void hal_mem_store_table(const char *file, int line, hal_memory_status_t type, uint8_t *ptr, size_t size){
  hal_memory_t* new_record = hal_mem_create_debug_record(file, line, type, ptr, size);
  if (mem_table == NULL) mem_table = new_record; 
  else {
    hal_memory_t* curr_mem_table = mem_table;
    while (curr_mem_table->next != NULL) curr_mem_table = curr_mem_table->next;
    curr_mem_table->next = new_record;
  }
}

void hal_mem_table_clean()
{
  if(mem_table == NULL) return;
  log_debug("[HAL] Clean debug memory table");  
  hal_memory_t* curr_mem_table = mem_table;
  while (curr_mem_table != NULL) {
    hal_memory_t* tmp_mem_table = curr_mem_table;
    curr_mem_table = curr_mem_table->next;
    free(tmp_mem_table->file);
    free(tmp_mem_table);
  }
  mem_table = NULL;
}

void hal_mem_print()
{
  if(mem_table == NULL) return;
  log_debug("[HAL] Memory table:");
  hal_memory_t* tmp_mem_table = mem_table;
  while (tmp_mem_table != NULL) {
    log_debug("[HAL] type: %d, ptr: %p, len: %d, file: %s , line: %d", 
      tmp_mem_table->type, tmp_mem_table->ptr, tmp_mem_table->len, 
      tmp_mem_table->file, tmp_mem_table->line);
    tmp_mem_table = tmp_mem_table->next;
  }
}

void hal_mem_free(const char *file, int line, uint8_t **ptr, bool trace)
{
  if(*ptr==NULL) {
    log_warn("[HAL] Attempt to free NULL pointer at %s:%d", file, line);
    return;
  }
  // log_debug("Freeing memory at %p", *ptr);
  if(trace) hal_mem_store_table(file, line, HAL_MEM_TYPE_FREE, (uint8_t *)*ptr, 0);
  free(*ptr);
  *ptr = NULL;
}

uint8_t *hal_mem_alloc(const char *file, int line, size_t size, bool trace)
{
  uint8_t *ptr = hal_mem_safe_alloc(file, line, size);
  if(trace) hal_mem_store_table(file, line, HAL_MEM_TYPE_CALLOC, (uint8_t *)ptr, size);
  // log_debug("Allocated memory at %p, size: 0x%x, %s:%d", ptr, size, file, line);
  return ptr;
}
