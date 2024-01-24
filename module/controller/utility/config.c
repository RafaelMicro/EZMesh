
/* inih -- simple .INI file parser
SPDX-License-Identifier: BSD-3-Clause
Copyright (C) 2009-2020, Ben Hoyt
inih is released under the New BSD license (see LICENSE.txt). Go to the project
home page for more info: https://github.com/benhoyt/inih
*/
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include "config.h"
#include "log.h"

#define MAX_SECTION 50
#define MAX_NAME 50

sys_config config;

/* Used by ini_parse_string() to keep track of string parsing state. */
typedef struct {
  const char *ptr;
  size_t num_left;
} ini_parse_string_ctx;

/* Strip whitespace chars off end of given string, in place. Return s. */
static char *rstrip(char *s) {
  char *p = s + strlen(s);
  while (p > s && isspace((unsigned char)(*--p)))
    *p = '\0';
  return s;
}

/* Return pointer to first non-whitespace char in given string. */
static char *lskip(const char *s) {
  while (*s && isspace((unsigned char)(*s)))
    s++;
  return (char *)s;
}

/* Return pointer to first char (of chars) or inline comment in given string,
   or pointer to NUL at end of string if neither found. Inline comment must
   be prefixed by a whitespace character to register as a comment. */
static char *find_chars_or_comment(const char *s, const char *chars) {
#if INI_ALLOW_INLINE_COMMENTS
  int was_space = 0;
  while (*s && (!chars || !strchr(chars, *s)) &&
         !(was_space && strchr(INI_INLINE_COMMENT_PREFIXES, *s))) {
    was_space = isspace((unsigned char)(*s));
    s++;
  }
#else
  while (*s && (!chars || !strchr(chars, *s))) {
    s++;
  }
#endif
  return (char *)s;
}

/* Similar to strncpy, but ensures dest (size bytes) is
   NUL-terminated, and doesn't pad with NULs. */
static char *strncpy0(char *dest, const char *src, size_t size) {
  /* Could use strncpy internally, but it causes gcc warnings (see issue #91) */
  size_t i;
  for (i = 0; i < size - 1 && src[i]; i++)
    dest[i] = src[i];
  dest[i] = '\0';
  return dest;
}

/* See documentation in header file. */
static int ini_parse_stream(ini_reader reader, void *stream, ini_handler handler,
                     void *user) {
  /* Uses a fair bit of stack (use heap instead if you need to) */
  char line[INI_MAX_LINE];
  size_t max_line = INI_MAX_LINE;

  char section[MAX_SECTION] = "";
  char prev_name[MAX_NAME] = "";

  char *start;
  char *end;
  char *name;
  char *value;
  int lineno = 0;
  int error = 0;

#if INI_HANDLER_LINENO
#define HANDLER(u, s, n, v) handler(u, s, n, v, lineno)
#else
#define HANDLER(u, s, n, v) handler(u, s, n, v)
#endif

  /* Scan through stream line by line */
  while (reader(line, (int)max_line, stream) != NULL) {
    lineno++;

    start = line;
#if INI_ALLOW_BOM
    if (lineno == 1 && (unsigned char)start[0] == 0xEF &&
        (unsigned char)start[1] == 0xBB && (unsigned char)start[2] == 0xBF) {
      start += 3;
    }
#endif
    start = lskip(rstrip(start));

    if (strchr(INI_START_COMMENT_PREFIXES, *start)) {
      /* Start-of-line comment */
    }
#if INI_ALLOW_MULTILINE
    else if (*prev_name && *start && start > line) {
#if INI_ALLOW_INLINE_COMMENTS
      end = find_chars_or_comment(start, NULL);
      if (*end)
        *end = '\0';
      rstrip(start);
#endif
      /* Non-blank line with leading whitespace, treat as continuation
         of previous name's value (as per Python configparser). */
      if (!HANDLER(user, section, prev_name, start) && !error)
        error = lineno;
    }
#endif
    else if (*start == '[') {
      /* A "[section]" line */
      end = find_chars_or_comment(start + 1, "]");
      if (*end == ']') {
        *end = '\0';
        strncpy0(section, start + 1, sizeof(section));
        *prev_name = '\0';
#if INI_CALL_HANDLER_ON_NEW_SECTION
        if (!HANDLER(user, section, NULL, NULL) && !error)
          error = lineno;
#endif
      } else if (!error) {
        /* No ']' found on section line */
        error = lineno;
      }
    } else if (*start) {
      /* Not a comment, must be a name[=:]value pair */
      end = find_chars_or_comment(start, "=:");
      if (*end == '=' || *end == ':') {
        *end = '\0';
        name = rstrip(start);
        value = end + 1;
#if INI_ALLOW_INLINE_COMMENTS
        end = find_chars_or_comment(value, NULL);
        if (*end)
          *end = '\0';
#endif
        value = lskip(value);
        rstrip(value);

        /* Valid name[=:]value pair found, call handler */
        strncpy0(prev_name, name, sizeof(prev_name));
        if (!HANDLER(user, section, name, value) && !error)
          error = lineno;
      } else if (!error) {
        /* No '=' or ':' found on name[=:]value line */
#if INI_ALLOW_NO_VALUE
        *end = '\0';
        name = rstrip(start);
        if (!HANDLER(user, section, name, NULL) && !error)
          error = lineno;
#else
        error = lineno;
#endif
      }
    }

#if INI_STOP_ON_FIRST_ERROR
    if (error)
      break;
#endif
  }
  return error;
}

/* See documentation in header file. */
static int ini_parse_file(FILE *file, ini_handler handler, void *user) {
  return ini_parse_stream((ini_reader)fgets, file, handler, user);
}

/* See documentation in header file. */
int ini_parse(const char *filename, ini_handler handler, void *user) {
  FILE *file;
  int error;
  config.stats_interval = 0;
  log_info("laod config file: %s", filename);
  file = fopen(filename, "r");
  if (!file) return -1;
  error = ini_parse_file(file, handler, user);
  fclose(file);
  return error;
}

int config_handler(void *user, const char *section, const char *name,
                   const char *value) {
  #define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
  sys_config *pc = (sys_config *)user;
  log_debug("load %s, %s, %s", section, name, value);

  if (MATCH("EZMESH_CONF", "name")) pc->ep_hw.name = strdup(value);
  else if (MATCH("EZMESH_CONF", "type")) pc->ep_hw.type = atoi(value);
  else if (MATCH("EZMESH_CONF", "port")) pc->ep_hw.port = strdup(value);
  else if (MATCH("EZMESH_CONF", "baudrate")) pc->ep_hw.baudrate = (unsigned int)atoi(value);
  else if (MATCH("EZMESH_CONF", "flowcontrol")) pc->ep_hw.flowcontrol = (uint8_t)atoi(value);
  else if (MATCH("EZMESH_CONF", "socket_path")) pc->ep_hw.socket_path = strdup(value);
  else if (MATCH("log", "level")) pc->log_level = atoi(value);
  else if (MATCH("log", "mode")) pc->log_mode = atoi(value);
  else {
    log_error("Nn match Config, label: %s, value: %s", section, name);
    return 0;
  }
  return 1;
}

const struct option argv_list[] =
{
    { "config", required_argument, 0, 'c' },
    { "help", no_argument, 0, 'h' },
    { "version", no_argument, 0, 'v' },
    { 0, 0, 0, 0 }
};

static void config_print_help(int exit_code)
{
    log_info("Start EZMESH daemon\n Usage:\n");
    log_info("\t-c/--config <file_path> : Set config file.\n");
    log_info("\t-v/--version : Show version\n");
    log_info("\t-h/--help : Help message.\n");
    exit(exit_code);
}

static void config_print_version(int exit_code)
{
    log_info("version:  %s %s\n", GIT_REFSPEC, GIT_SHA1);
    exit(exit_code);
}

void handle_cli_arg(int argc, char *argv[])
{
    int opt;
    
    while (1)
    {
        opt = getopt_long(argc, argv, "c:h:v", argv_list, NULL);
        if (opt == -1) break; 
        switch (opt)
        {
        case 'c':{
            if (ini_parse(optarg, config_handler, &config) < 0) log_error("Load Config file Failed");
            log_set_info(config.log_mode, config.log_level);
            break;}
        case 'v':{ config_print_version(0); break;}
        case 'h':{ config_print_help(0); break;}
        default:{ config_print_help(1); break;}
        }
    }
}


void config_restart(char **argv)
{
    log_info("Restarting EzMesh...");
    execv("/proc/self/exe", argv);
}