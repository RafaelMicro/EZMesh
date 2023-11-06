
#define _GNU_SOURCE

#include <fcntl.h>
#include <sys/errno.h>
#include <glob.h>
#include <limits.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/spi/spidev.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>

#include "sleep.h"
#include "config.h"
#include "logs.h"
#include "version.h"
#include "utils.h"

/*******************************************************************************
 **********************  DATA TYPES   ******************************************
 ******************************************************************************/
typedef struct
{
    char *val;
    char *name;
    bool has_arg;
} argv_exclude_t;

/*******************************************************************************
 **********************  GLOBAL CONFIGURATION VALUES   *************************
 ******************************************************************************/
config_t config =
{
    .file_path = CPCD_CONFIG_FILE_PATH,
    .instance_name = DEFAULT_INSTANCE_NAME,

    .socket_folder = CPC_SOCKET_DIR,
    .stdout_tracing = false,
    .file_tracing = true,
    .lttng_tracing = false,
    .enable_frame_trace = false,
    .traces_folder = "/dev/shm/cpcd-traces",
    .bus = UNCHOSEN,
    // UART config
    .uart_baudrate = 115200,
    .uart_hardflow = false,
    .uart_file = NULL,
    .application_version_validation = NULL,
    .print_secondary_versions_and_exit = false,
    .use_noop_keep_alive = false,
    .reset_sequence = true,
    .uart_validation_test_option = NULL,
    .stats_interval = 0,
    .rlimit_nofile = 2000,
};

/*******************************************************************************
 **************************  LOCAL PROTOTYPES   ********************************
 ******************************************************************************/

static void config_print_version(FILE *stream, int exit_code);

static void config_print_help(FILE *stream, int exit_code);

static void config_parse_cli_arg(int argc, char *argv[]);

static void config_set_rlimit_nofile(void);

static void config_validate_configuration(void);

static void config_parse_config_file(void);


/*******************************************************************************
 ****************************  IMPLEMENTATION   ********************************
 ******************************************************************************/
static const char *config_bool_to_str(bool value)
{
    return value ? "true" : "false";
}

static const char *config_to_str(const char *value)
{
    return value ? value : "";
}

static const char *config_bus_to_str(bus_t value)
{
    switch (value)
    {
    case UART:
        return "UART";
    case SPI:
        return "SPI";
    case UNCHOSEN:
        return "UNCHOSEN";
    default:
        ERROR("bus_t value not supported (%d)", value);
    }
}

#define CONFIG_PREFIX_LEN(variable) (strlen(#variable) + 1)

#define CONFIG_PRINT_STR(value)                                           \
    do {                                                                    \
        PRINT_INFO("%s = %s", &(#value)[print_offset], config_to_str(value)); \
        run_time_total_size += (uint32_t)sizeof(value);                       \
    } while (0)

#define CONFIG_PRINT_BOOL_TO_STR(value)                                        \
    do {                                                                         \
        PRINT_INFO("%s = %s", &(#value)[print_offset], config_bool_to_str(value)); \
        run_time_total_size += (uint32_t)sizeof(value);                            \
    } while (0)

#define CONFIG_PRINT_OPERATION_MODE_TO_STR(value)                                        \
    do {                                                                                   \
        PRINT_INFO("%s = %s", &(#value)[print_offset], config_operation_mode_to_str(value)); \
        run_time_total_size += (uint32_t)sizeof(value);                                      \
    } while (0)

#define CONFIG_PRINT_BUS_TO_STR(value)                                        \
    do {                                                                        \
        PRINT_INFO("%s = %s", &(#value)[print_offset], config_bus_to_str(value)); \
        run_time_total_size += (uint32_t)sizeof(value);                           \
    } while (0)

#define CONFIG_PRINT_DEC(value)                            \
    do {                                                     \
        PRINT_INFO("%s = %d", &(#value)[print_offset], value); \
        run_time_total_size += (uint32_t)sizeof(value);        \
    } while (0)

static void config_print(void)
{
    PRINT_INFO("Reading configuration");

    size_t print_offset = CONFIG_PREFIX_LEN(config);

    uint32_t compile_time_total_size = (uint32_t)sizeof(config_t);
    uint32_t run_time_total_size = 0;

    CONFIG_PRINT_STR(config.file_path);

    CONFIG_PRINT_STR(config.instance_name);

    CONFIG_PRINT_STR(config.socket_folder);

    CONFIG_PRINT_BOOL_TO_STR(config.stdout_tracing);
    CONFIG_PRINT_BOOL_TO_STR(config.file_tracing);
    CONFIG_PRINT_BOOL_TO_STR(config.lttng_tracing);
    CONFIG_PRINT_BOOL_TO_STR(config.enable_frame_trace);
    CONFIG_PRINT_STR(config.traces_folder);

    CONFIG_PRINT_BUS_TO_STR(config.bus);

    CONFIG_PRINT_DEC(config.uart_baudrate);
    CONFIG_PRINT_BOOL_TO_STR(config.uart_hardflow);
    CONFIG_PRINT_STR(config.uart_file);


    CONFIG_PRINT_BOOL_TO_STR(config.application_version_validation);

    CONFIG_PRINT_BOOL_TO_STR(config.print_secondary_versions_and_exit);

    CONFIG_PRINT_BOOL_TO_STR(config.use_noop_keep_alive);

    CONFIG_PRINT_BOOL_TO_STR(config.reset_sequence);

    CONFIG_PRINT_STR(config.uart_validation_test_option);

    CONFIG_PRINT_DEC(config.stats_interval);

    CONFIG_PRINT_DEC(config.rlimit_nofile);

    if (run_time_total_size != compile_time_total_size)
    {
        ERROR("A new config was added to config_t but it was not printed. run_time_total_size (%d) != compile_time_total_size (%d)", run_time_total_size, compile_time_total_size);
    }
}

static void print_cli_args(int argc, char *argv[])
{
    char *cli_args;
    size_t cli_args_size = 0;

    for (int i = 0; i < argc; i++)
    {
        if (argv[i])
        {
            cli_args_size += strlen(argv[i]) + strlen(" ") + 1;
        }
    }

    cli_args = calloc_port(cli_args_size);
    ERROR_SYSCALL_ON(cli_args == NULL);

    for (int i = 0; i < argc; i++)
    {
        if (argv[i])
        {
            strcat(cli_args, argv[i]);
            strcat(cli_args, " ");
        }
    }

    PRINT_INFO("%s", cli_args);
    free(cli_args);
}

#define ARGV_OPT_CONF                   "conf"
#define ARGV_OPT_HELP                   "help"
#define ARGV_OPT_VERSION                "version"
#define ARGV_OPT_SECONDARY_VERSIONS     "secondary-versions"
#define ARGV_OPT_APP_VERSION            "app-version"

const struct option argv_opt_list[] =
{
    { ARGV_OPT_CONF, required_argument, 0, 'c' },
    { ARGV_OPT_HELP, no_argument, 0, 'h' },
    { ARGV_OPT_VERSION, no_argument, 0, 'v' },
    { ARGV_OPT_SECONDARY_VERSIONS, no_argument, 0, 'p' },
    { ARGV_OPT_APP_VERSION, required_argument, 0, 'a' },
    { 0, 0, 0, 0 }
};

static void config_parse_cli_arg(int argc, char *argv[])
{
    int opt;

    PRINT_INFO("Reading cli arguments");

    print_cli_args(argc, argv);

    while (1)
    {
        opt = getopt_long(argc, argv, "c:hpv:a:", argv_opt_list, NULL);

        if (opt == -1)
        {
            break;
        }

        switch (opt)
        {
        case 'c':
            config.file_path = optarg;
            break;
        case 'h':
            config_print_help(stdout, 0);
            break;
        case 'v':
            config_print_version(stdout, 0);
            break;
        case 'a':
            config.application_version_validation = optarg;
            break;
        case 'p':
            config.print_secondary_versions_and_exit = true;
            break;
        case '?':
        default:
            config_print_help(stderr, 1);
            break;
        }
    }
}

void config_restart_cpcd(char **argv)
{
    PRINT_INFO("Restarting CPCd...");
    sleep_s(1); // Wait for logs to be flushed
    execv("/proc/self/exe", argv);
}


static inline bool is_nul(char c)
{
    return c == '\0';
}

static inline bool is_white_space(char c)
{
    return c == ' ' || c == '\t';
}

static inline bool is_line_break(char c)
{
    return c == '\n' || c == '\r';
}

static inline bool is_comment(char c)
{
    return c == '#';
}

static int32_t non_leading_whitespaces_index(const char *str)
{
    int32_t i = 0;
    while (!is_nul(str[i]))
    {
        if (!is_white_space(str[i]))
        {
            break;
        }
        ++i;
    }
    return i;
}

static bool is_comment_or_newline(const char *line)
{
    char c = line[non_leading_whitespaces_index(line)];
    return is_nul(c) || is_line_break(c) || is_comment(c);
}

static void config_parse_config_file(void)
{
    FILE *config_file = NULL;
    char name[128] = { 0 };
    char val[128] = { 0 };
    char line[256] = { 0 };
    char *endptr = NULL;
    int tmp_config_file_tracing = 0;

    config_file = fopen(config.file_path, "r");

    if (config_file == NULL)
    {
        ERROR("Could not open the configuration file under: %s, please install the configuration file there or provide a valid path with --conf\n", config.file_path);
    }

    /* Iterate through every line of the file*/
    while (fgets(line, sizeof(line), config_file) != NULL)
    {
        if (is_comment_or_newline(line))
        {
            continue;
        }

        /* Extract name=value pair */
        if (sscanf(line, "%127[^: ]: %127[^\r\n #]%*c", name, val) != 2)
        {
            ERROR("Config file line \"%s\" doesn't respect syntax. Expecting YAML format (key: value). Please refer to the provided cpcd.conf", line);
        }

        if (0 == strcmp(name, "instance_name"))
        {
            config.instance_name = strdup(val);
            ERROR_ON(config.instance_name == NULL);
        } else if (0 == strcmp(name, "bus_type"))
        {
            if (0 == strcmp(val, "UART"))
            {
                config.bus = UART;
            } else if (0 == strcmp(val, "SPI"))
            {
                config.bus = SPI;
            } else
            {
                ERROR("Config file error : bad bus_type value\n");
            }
        } else if (0 == strcmp(name, "uart_device_file"))
        {
            config.uart_file = strdup(val);
            ERROR_ON(config.uart_file == NULL);
        } else if (0 == strcmp(name, "uart_device_baud"))
        {
            config.uart_baudrate = (unsigned int)strtoul(val, &endptr, 10);
            if (*endptr != '\0')
            {
                ERROR("Bad config line \"%s\"", line);
            }
        } else if (0 == strcmp(name, "uart_hardflow"))
        {
            if (0 == strcmp(val, "true"))
            {
                config.uart_hardflow = true;
            } else if (0 == strcmp(val, "false"))
            {
                config.uart_hardflow = false;
            } else
            {
                ERROR("Config file error : bad UART_HARDFLOW value");
            }
        } else if (0 == strcmp(name, "noop_keep_alive"))
        {
            if (0 == strcmp(val, "true"))
            {
                config.use_noop_keep_alive = true;
            } else if (0 == strcmp(val, "false"))
            {
                config.use_noop_keep_alive = false;
            } else
            {
                ERROR("Config file error : bad noop_keep_alive value");
            }
        } else if (0 == strcmp(name, "stdout_trace"))
        {
            if (0 == strcmp(val, "true"))
            {
                config.stdout_tracing = true;
            } else if (0 == strcmp(val, "false"))
            {
                config.stdout_tracing = false;
            } else
            {
                ERROR("Config file error : bad stdout_trace value");
            }
        } else if (0 == strcmp(name, "trace_to_file"))
        {
            if (0 == strcmp(val, "true"))
            {
                tmp_config_file_tracing = true;
            } else if (0 == strcmp(val, "false"))
            {
                tmp_config_file_tracing = false;
            } else
            {
                ERROR("Config file error : bad trace_to_file value");
            }
        } else if (0 == strcmp(name, "enable_frame_trace"))
        {
            if (0 == strcmp(val, "true"))
            {
                config.enable_frame_trace = true;
            } else if (0 == strcmp(val, "false"))
            {
                config.enable_frame_trace = false;
            } else
            {
                ERROR("Config file error : bad enable_frame_trace value");
            }
        } else if (0 == strcmp(name, "reset_sequence"))
        {
            if (0 == strcmp(val, "true"))
            {
                config.reset_sequence = true;
            } else if (0 == strcmp(val, "false"))
            {
                config.reset_sequence = false;
            } else
            {
                ERROR("Config file error : bad reset_sequence value");
            }
        } else if (0 == strcmp(name, "traces_folder"))
        {
            config.traces_folder = strdup(val);
            ERROR_ON(config.traces_folder == NULL);
        } else if (0 == strcmp(name, "rlimit_nofile"))
        {
            config.rlimit_nofile = strtoul(val, &endptr, 10);
            if (*endptr != '\0')
            {
                ERROR("Config file error : bad rlimit_nofile value");
            }
        }
    }

    config.file_tracing = tmp_config_file_tracing;

    fclose(config_file);
}

static void prevent_device_collision(const char *const device_name)
{
    int tmp_fd = open(device_name, O_RDWR | O_CLOEXEC);

    /* Try to apply a cooperative exclusive file lock on the device file. Don't block */
    int ret = flock(tmp_fd, LOCK_EX | LOCK_NB);

    if (ret == 0)
    {
        /* The device file is free to use, leave this file descriptor open
         * to preserve the lock. */
    } else if (errno == EWOULDBLOCK)
    {
        ERROR("The device \"%s\" is locked by another cpcd instance", device_name);
    } else
    {
        ERROR_SYSCALL_ON(0);
    }
}

static void prevent_instance_collision(const char *const instance_name)
{
    struct sockaddr_un name;
    int ctrl_sock_fd;

    /* Create datagram socket for control */
    ctrl_sock_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    ERROR_SYSCALL_ON(ctrl_sock_fd < 0);

    /* Clear struct for portability */
    memset(&name, 0, sizeof(name));

    name.sun_family = AF_UNIX;

    /* Create the control socket path */
    {
        int nchars;
        const size_t size = sizeof(name.sun_path) - sizeof('\0');

        nchars = snprintf(name.sun_path, size, "%s/cpcd/%s/ctrl.cpcd.sock", config.socket_folder, instance_name);

        /* Make sure the path fitted entirely */
        ERROR_ON(nchars < 0 || (size_t)nchars >= size);
    }

    /* Try to connect to the socket in order to see if we collide with another daemon */
    {
        int ret;

        ret = connect(ctrl_sock_fd, (const struct sockaddr *)&name, sizeof(name));

        (void)close(ctrl_sock_fd);

        if (ret == 0)
        {
            ERROR("Another daemon instance is already running with the same instance name : %s.", name.sun_path);
        } else
        {
            /* good to go */
        }
    }
}

static void config_validate_configuration(void)
{
    /* Validate bus configuration */
    {
        if (config.bus == UART)
        {
            if (config.uart_file == NULL)
            {
                ERROR("UART device file missing");
            }

            prevent_device_collision(config.uart_file);
        } else
        {
            ERROR("Invalid bus configuration.");
        }
    }

    prevent_instance_collision(config.instance_name);

    if (config.file_tracing)
    {
        init_file_logging();
    }

    if (config.stats_interval > 0)
    {
        init_stats_logging();
    }
}

static void config_set_rlimit_nofile(void)
{
    struct rlimit limit;
    int ret;

    /* Make sure RLIMIT_NOFILE (number of concurrent opened file descriptor)
     * is at least rlimit_nofile  */

    ret = getrlimit(RLIMIT_NOFILE, &limit);
    ERROR_SYSCALL_ON(ret < 0);

    if (limit.rlim_cur < config.rlimit_nofile)
    {
        if (config.rlimit_nofile > limit.rlim_max)
        {
            ERROR("The OS doesn't support our requested RLIMIT_NOFILE value");
        }

        limit.rlim_cur = config.rlimit_nofile;

        ret = setrlimit(RLIMIT_NOFILE, &limit);
        ERROR_SYSCALL_ON(ret < 0);
    }
}

static void config_print_version(FILE *stream, int exit_code)
{
#ifndef GIT_SHA1
#define GIT_SHA1 "missing SHA1"
#endif

#ifndef GIT_REFSPEC
#define GIT_REFSPEC "missing refspec"
#endif

    fprintf(stream, "%s\n", PROJECT_VER);
    fprintf(stream, "GIT commit: %s\n", GIT_SHA1);
    fprintf(stream, "GIT branch: %s\n", GIT_REFSPEC);
    fprintf(stream, "Sources hash: %s\n", SOURCES_HASH);
    exit(exit_code);
}

static void config_print_help(FILE *stream, int exit_code)
{
    fprintf(stream, "Start CPC daemon\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  cpcd -h/--help : prints this message.\n");
    fprintf(stream, "  cpcd -c/--conf <file> : manually specify the config file.\n");
    fprintf(stream, "  cpcd -v/--version : get the version of the daemon and exit.\n");
    fprintf(stream, "  cpcd -p/--secondary-versions : get all secondary versions (protocol, cpc, app) and exit.\n");
    fprintf(stream, "  cpcd -a/--app-version <version> : specify the application version to match.\n");
    exit(exit_code);
}

void config_init(int argc, char *argv[])
{
    config_parse_cli_arg(argc, argv);

    config_parse_config_file();

    config_validate_configuration();

    config_set_rlimit_nofile();

    config_print();
}
