
/* inih -- simple .INI file parser
SPDX-License-Identifier: BSD-3-Clause
Copyright (C) 2009-2020, Ben Hoyt
inih is released under the New BSD license (see LICENSE.txt). Go to the project
home page for more info: https://github.com/benhoyt/inih
*/
#ifndef CONFIG_H
#define CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

typedef enum
{
   EP_TYPE_UART,
   EP_TYPE_SPI
}ez_ep_type_t;

typedef struct
{
   const char *name;
   ez_ep_type_t type;
   const char *port;
   const char *socket_path;
   unsigned int baudrate;
   uint8_t flowcontrol;
   uint8_t rf_cert_band;
}ez_ep_t;


typedef struct {
   int log_mode;
   int log_level;
   ez_ep_t ep_hw;
   int stats_interval;
} sys_config;

extern sys_config config;

/* Nonzero if ini_handler callback should accept lineno parameter. */
#ifndef INI_HANDLER_LINENO
#define INI_HANDLER_LINENO 0
#endif

/* Typedef for prototype of handler function. */
#if INI_HANDLER_LINENO
typedef int (*ini_handler)(void *user, const char *section, const char *name,
                           const char *value, int lineno);
#else
typedef int (*ini_handler)(void *user, const char *section, const char *name,
                           const char *value);
#endif

/* Typedef for prototype of fgets-style reader function. */
typedef char *(*ini_reader)(char *str, int num, void *stream);

int ini_parse(const char *filename, ini_handler handler, void *user);
void ini_deinit(void);
int config_handler(void *user, const char *section, const char *name,
                   const char *value);

void handle_cli_arg(int argc, char *argv[]);
void config_restart(char **argv);

/* Nonzero to allow multi-line value parsing, in the style of Python's
   configparser. If allowed, ini_parse() will call the handler with the same
   name for each subsequent line parsed. */
#ifndef INI_ALLOW_MULTILINE
#define INI_ALLOW_MULTILINE 1
#endif

/* Nonzero to allow a UTF-8 BOM sequence (0xEF 0xBB 0xBF) at the start of
   the file. See https://github.com/benhoyt/inih/issues/21 */
#ifndef INI_ALLOW_BOM
#define INI_ALLOW_BOM 1
#endif

/* Chars that begin a start-of-line comment. Per Python configparser, allow
   both ; and # comments at the start of a line by default. */
#ifndef INI_START_COMMENT_PREFIXES
#define INI_START_COMMENT_PREFIXES ";#"
#endif

/* Nonzero to allow inline comments (with valid inline comment characters
   specified by INI_INLINE_COMMENT_PREFIXES). Set to 0 to turn off and match
   Python 3.2+ configparser behaviour. */
#ifndef INI_ALLOW_INLINE_COMMENTS
#define INI_ALLOW_INLINE_COMMENTS 1
#endif
#ifndef INI_INLINE_COMMENT_PREFIXES
#define INI_INLINE_COMMENT_PREFIXES ";"
#endif

/* Maximum line length for any line in INI file (stack or heap). Note that
   this must be 3 more than the longest line (due to '\r', '\n', and '\0'). */
#ifndef INI_MAX_LINE
#define INI_MAX_LINE 200
#endif

/* Stop parsing on first error (default is to keep parsing). */
#ifndef INI_STOP_ON_FIRST_ERROR
#define INI_STOP_ON_FIRST_ERROR 1
#endif

/* Nonzero to call the handler at the start of each new section (with
   name and value NULL). Default is to only call the handler on
   each name=value pair. */
#ifndef INI_CALL_HANDLER_ON_NEW_SECTION
#define INI_CALL_HANDLER_ON_NEW_SECTION 0
#endif

/* Nonzero to allow a name without a value (no '=' or ':' on the line) and
   call the handler with value NULL in this case. Default is to treat
   no-value lines as an error. */
#ifndef INI_ALLOW_NO_VALUE
#define INI_ALLOW_NO_VALUE 0
#endif

#ifdef __cplusplus
}
#endif

#endif /* INI_H */