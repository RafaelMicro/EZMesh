
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include "log.h"
#include <time.h>
#include <sys/time.h>


#define MAX_CALLBACKS 32

typedef struct {
  log_LogFn fn;
  void *udata;
  int level;
} Callback;

static struct {
  void *udata;
  log_LockFn lock;
  int level;
  int mode;
  bool quiet;
  Callback callbacks[MAX_CALLBACKS];
} L;

static const char *level_strings[] = {"TRACE", "DEBUG", "INFO",
                                      "WARN",  "ERROR", "FATAL", "CRASH"};

static const char *level_colors[] = {"\x1b[94m", "\x1b[36m", "\x1b[32m",
                                     "\x1b[33m", "\x1b[31m", "\x1b[35m", "\x1b[35m"};

static void stdout_callback(log_Event *ev, ...) {
  char buf[16], Tbuf[40];
  buf[strftime(buf, sizeof(buf), "%H:%M:%S", ev->time)] = '\0';
  Tbuf[snprintf(Tbuf, sizeof(Tbuf), "%s.%03ld", buf, ev->tv.tv_usec / 1000)] = '\0';
  if (L.mode == LOG_MODE_SYS) fprintf(ev->udata, "%s %s%-5s\x1b[0m ", Tbuf, level_colors[ev->level], level_strings[ev->level]);
  else fprintf(ev->udata, "%s %s%-5s\x1b[0m \x1b[90m%s:%d:\x1b[0m ", Tbuf, level_colors[ev->level], level_strings[ev->level], ev->file, ev->line);

  vfprintf(ev->udata, ev->fmt, ev->ap);
  fprintf(ev->udata, "\n");
  fflush(ev->udata);
}

static void sysout_callback(log_Event *ev, ...) {
  char buf[16], Tbuf[40];
  char syslog_buffer[512]={0};
  int idx=0;
  buf[strftime(buf, sizeof(buf), "%H:%M:%S", ev->time)] = '\0';
  Tbuf[snprintf(Tbuf, sizeof(Tbuf), "%s.%03ld", buf, ev->tv.tv_usec / 1000)] = '\0';
  if (L.mode == LOG_MODE_SYS) {
    idx += snprintf(syslog_buffer, sizeof(syslog_buffer), "%s", Tbuf);
    idx += snprintf(syslog_buffer+(long unsigned int)idx, sizeof(syslog_buffer)-(long unsigned int)idx, " %s%-5s\x1b[0m ", level_colors[ev->level], level_strings[ev->level]);
  }
  else {
    idx += snprintf(syslog_buffer, sizeof(syslog_buffer), "%s", Tbuf);
    idx += snprintf(syslog_buffer+(long unsigned int)idx, sizeof(syslog_buffer)-(long unsigned int)idx, "%s %s%-5s\x1b[0m \x1b[90m%s:%d:\x1b[0m ", Tbuf, level_colors[ev->level], level_strings[ev->level], ev->file, ev->line);
  }
  idx += vsnprintf(syslog_buffer+(long unsigned int)idx, sizeof(syslog_buffer)-(long unsigned int)idx, ev->fmt, ev->ap);
  syslog(LOG_INFO | LOG_NDELAY, "%s", syslog_buffer);
}

static void stdout_callback_hex(log_Event *ev, const char *tag, uint8_t *data, const size_t len) {
  char buf[16], Tbuf[40];
  buf[strftime(buf, sizeof(buf), "%H:%M:%S", ev->time)] = '\0';
  Tbuf[snprintf(Tbuf, sizeof(Tbuf), "%s.%03ld", buf, ev->tv.tv_usec / 1000)] = '\0';
  if (L.mode == LOG_MODE_SYS) fprintf(ev->udata, "%s %s%-5s\x1b[0m ", Tbuf, level_colors[ev->level], level_strings[ev->level]);
  else fprintf(ev->udata, "%s %s%-5s\x1b[0m \x1b[90m%s:%d:\x1b[0m ", Tbuf, level_colors[ev->level], level_strings[ev->level], ev->file, ev->line);
  fprintf(ev->udata, "%s ", tag);
  for (size_t i = 0; i < len; ++i) fprintf(ev->udata, "%02X ", data[i]);
  fprintf(ev->udata, "\n");
  fflush(ev->udata);
}

static void sysout_callback_hex(log_Event *ev, const char *tag, uint8_t *data, const size_t len) {
  char buf[16], Tbuf[40], data_buffer[512]={0};
  int idx=0;
  buf[strftime(buf, sizeof(buf), "%H:%M:%S", ev->time)] = '\0';
  Tbuf[snprintf(Tbuf, sizeof(Tbuf), "%s.%03ld", buf, ev->tv.tv_usec / 1000)] = '\0';
  if (L.mode == LOG_MODE_SYS)  {
    idx += snprintf(data_buffer, sizeof(data_buffer), "%s", Tbuf);
    idx += snprintf(data_buffer+(long unsigned int)idx, sizeof(data_buffer)-(long unsigned int)idx, " %s%-5s\x1b[0m ", level_colors[ev->level], level_strings[ev->level]);
  }
  else {
    idx += snprintf(data_buffer, sizeof(data_buffer), "%s", Tbuf);
    idx += snprintf(data_buffer+(long unsigned int)idx, sizeof(data_buffer)-(long unsigned int)idx, "%s %s%-5s\x1b[0m \x1b[90m%s:%d:\x1b[0m ", Tbuf, level_colors[ev->level], level_strings[ev->level], ev->file, ev->line);
  }
  idx += snprintf(data_buffer+(long unsigned int)idx, sizeof(data_buffer)-(long unsigned int)idx, "%s ", tag);
  for (size_t i = 0; i < len; ++i) idx += snprintf(data_buffer+(long unsigned int)idx, sizeof(data_buffer)-(long unsigned int)idx, "%02X ", data[i]);
  syslog(LOG_INFO | LOG_NDELAY, "%s", data_buffer);
}

static void lock(void) { if (L.lock) L.lock(true, L.udata); }

static void unlock(void) { if (L.lock) L.lock(false, L.udata); }

void log_set_info(int mode, int level) {
  if (mode == 2) L.quiet = true;
  L.mode = mode;
  L.level = level;
}

static void init_event(log_Event *ev, void *udata) {
  // openlog("EZmeshD", LOG_CONS | LOG_PID | LOG_NDELAY, 0);
  if (!ev->time) {
    time_t t = time(NULL);
    ev->time = localtime(&t);
    gettimeofday(&ev->tv, NULL);
  }
  ev->udata = udata;
}

void log_dump(int level, const char *file, int line, const char *tag, const void *data, const size_t len) {
  log_Event ev = {
    .file = file,
    .line = line,
    .level = level,
  };

  lock();
  if (!L.quiet && level >= L.level) {
    init_event(&ev, stderr);
    sysout_callback_hex(&ev, tag, (uint8_t *)data, len);
    stdout_callback_hex(&ev, tag, (uint8_t *)data, len);
  }
  unlock();
  if (level == U_LOG_CRASH) { signal_crash(); }
}

void log_log(int level, const char *file, int line, const char *fmt, ...) {
  log_Event ev = {
    .fmt = fmt,
    .file = file,
    .line = line,
    .level = level,
  };

  lock();
  if (!L.quiet && level >= L.level) {
    init_event(&ev, stderr);
    va_start(ev.ap, fmt);
    stdout_callback(&ev);
    va_end(ev.ap);
    va_start(ev.ap, fmt);
    sysout_callback(&ev);
    va_end(ev.ap);
  }

  for (int i = 0; i < MAX_CALLBACKS && L.callbacks[i].fn; i++) {
    Callback *cb = &L.callbacks[i];
    if (level >= cb->level) {
      init_event(&ev, cb->udata);
      va_start(ev.ap, fmt);
      cb->fn(&ev);
      va_end(ev.ap);
      va_start(ev.ap, fmt);
      sysout_callback(&ev);
      va_end(ev.ap);
    }
  }
  unlock();
  if (level == U_LOG_CRASH) { signal_crash(); }
}

