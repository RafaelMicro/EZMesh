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
  uint8_t* ptr;
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


void hal_mem_table_clean()
{
  hal_memory_t* tmp_mem_table = mem_table;
  while (tmp_mem_table != NULL)
  {
    hal_memory_t* next = tmp_mem_table->next;
    free(tmp_mem_table->file);
    free(tmp_mem_table);
    tmp_mem_table = next;
  }
}
static void hal_mem_store_table(const char *file, int line, hal_memory_status_t type, uint8_t *ptr, size_t size){
  if(mem_table==NULL) {
    mem_table = malloc(sizeof(hal_memory_t));
    if(mem_table == NULL) {
      log_error("Failed to allocate memory mem_table");
      signal_crash();
    }
    mem_table->file = malloc(strlen(file)+1);
    if(mem_table->file == NULL) {
      log_error("Failed to allocate memory file or line");
      signal_crash();
    }
    memccpy(mem_table->file, file, (int)(strlen(file)+1), (size_t)(strlen(file)+1));
    mem_table->type = type;
    mem_table->line = (uint32_t)line;
    mem_table->ptr = ptr;
    mem_table->len = size;
    mem_table->next = NULL;
  } else {
    hal_memory_t* tmp_mem_table = mem_table;
    while (tmp_mem_table->next != NULL) tmp_mem_table = tmp_mem_table->next;

    hal_memory_t* mem_record = malloc(sizeof(hal_memory_t));
    if(mem_record == NULL) {
      log_error("Failed to allocate memory mem_record");
      signal_crash();
    }
    mem_record->file = malloc(strlen(file)+1);
    if(mem_record->file == NULL) {
      log_error("Failed to allocate memory file or line");
      signal_crash();
    }

    mem_record->type = type;
    memccpy(mem_record->file, file, (int)(strlen(file)+1), (size_t)(strlen(file)+1));
    mem_record->line= (uint32_t)line;
    mem_record->ptr = ptr;
    mem_record->len = size;
    mem_record->next = NULL;
    tmp_mem_table->next = mem_record;
  }
}

void hal_mem_print()
{
  hal_memory_t* tmp_mem_table = mem_table;
  if(tmp_mem_table!=NULL) {
    log_warn("Memory table:");
    while (tmp_mem_table != NULL)
    {
      log_debug("type: %d, ptr: %p, len: %d, file: %s , line: %d", 
        tmp_mem_table->type, tmp_mem_table->ptr, tmp_mem_table->len, 
        tmp_mem_table->file, tmp_mem_table->line);
      tmp_mem_table = tmp_mem_table->next;
    }
  }
}

void hal_mem_free(const char *file, int line, uint8_t **ptr, bool trace)
{
  if(*ptr==NULL) return;
  // log_debug("Freeing memory at %p", *ptr);
  if(trace) hal_mem_store_table(file, line, HAL_MEM_TYPE_FREE, (uint8_t *)ptr, 0);
  free(*ptr);
  *ptr = NULL;
}

uint8_t *hal_mem_alloc(const char *file, int line, size_t size, bool trace)
{
  uint8_t *ptr = calloc(1, size);
  if (ptr == NULL) {
    log_error("Failed to allocate memory at %s:%d", file, line);
    signal_crash();
  }
  if(trace) hal_mem_store_table(file, line, HAL_MEM_TYPE_CALLOC, (uint8_t *)ptr, size);
  // log_debug("Allocated memory at %p, size: 0x%x, %s:%d", ptr, size, file, line);
  return ptr;
}
