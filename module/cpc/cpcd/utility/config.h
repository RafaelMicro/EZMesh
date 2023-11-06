

#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <sys/resource.h>

#ifndef DEFAULT_INSTANCE_NAME
  #define DEFAULT_INSTANCE_NAME "cpcd_0"
#endif

typedef enum
{
    UART,
    SPI,
    UNCHOSEN
}bus_t;

typedef struct __attribute__((packed))
{
    const char *file_path;
    const char *instance_name;

    const char *const socket_folder;

    bool stdout_tracing;
    bool file_tracing;

    int lttng_tracing;
    bool enable_frame_trace;
    const char *traces_folder;

    bus_t bus;

    unsigned int uart_baudrate;
    bool uart_hardflow;
    const char *uart_file;

    const char *application_version_validation;

    bool print_secondary_versions_and_exit;

    bool use_noop_keep_alive;

    bool reset_sequence;

    const char *uart_validation_test_option;

    long stats_interval;

    rlim_t rlimit_nofile;
} config_t;

extern config_t config;

void config_init(int argc, char *argv[]);
void config_restart_cpcd(char **argv);
void config_restart_cpcd_without_fw_update_args(void);

#endif //CONFIG_H
