
#ifndef LOG_H
#define LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>


typedef struct {
  va_list ap;
  const char *fmt;
  const char *file;
  struct tm *time;
  void *udata;
  int line;
  int level;
} log_Event;

typedef void (*log_LogFn)(log_Event *ev);
typedef void (*log_LockFn)(bool lock, void *udata);

enum { LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_FATAL, LOG_CRASH };
enum { LOG_MODE_SYS, LOG_MODE_DEV };

#define log_trace(...) log_log(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define log_debug(...) log_log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define log_info(...)  log_log(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define log_warn(...)  log_log(LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define log_error(...) log_log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define log_fatal(...) log_log(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)
#define log_crash(...) log_log(LOG_CRASH, __FILE__, __LINE__, __VA_ARGS__)

#define log_trace_hexdump(...) log_dump(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define log_debug_hexdump(...) log_dump(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define log_info_hexdump(...)  log_dump(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define log_warn_hexdump(...)  log_dump(LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define log_error_hexdump(...) log_dump(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define log_fatal_hexdump(...) log_dump(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)
#define log_crash_hexdump(...) log_dump(LOG_CRASH, __FILE__, __LINE__, __VA_ARGS__)

__attribute__((noreturn)) void signal_crash(void);

#define CHECK_WARN(cond)  {if (cond) { log_warn("Warn... ");}}
#define CHECK_ERROR(cond) {if (cond) { log_error("Error: Crash!!!"); signal_crash();}}
#define CHECK_FATAL(cond) {if (cond) { log_fatal("Error: Fatal!!!"); signal_crash();}}
#define FATAL(...) do{ log_log(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__); signal_crash(); }while(0)

const char *log_level_string(int level);
void log_set_lock(log_LockFn fn, void *udata);
void log_set_info(int mode, int level);
void log_log(int level, const char *file, int line, const char *fmt, ...);
void log_dump(int level, const char *file, int line, const char *tag, const void *data, const size_t len);

#ifdef __cplusplus
}
#endif

#endif