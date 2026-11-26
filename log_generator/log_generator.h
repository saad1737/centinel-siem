#ifndef LOG_GENERATOR_H
#define LOG_GENERATOR_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>     /* For getopt_long() and struct option */
#include <arpa/inet.h>  /* Useful for inet_pton() if validating IP format */

#define TARGET_HOST_LEN 16
#define TARGET_PATH_LEN 256
#define VICTIM_IP_LEN 16
#define MAX_EPS 500000
#define MAX_BATCH_SIZE 4096

typedef enum {
    MODE_CONTINUOUS, // normal paced log streaming with specifies EPS
    MODE_BURST, // to alternate between calm periods and sudden attack spikes
    MODE_BENCHMARK // maximum unthrottled loop (as much CPU and socket allows)
} GeneratorMode;

typedef struct {
    char target_host[TARGET_HOST_LEN];
    uint16_t target_port;
    char target_path[TARGET_PATH_LEN]; // output log file
    GeneratorMode mode;
    uint32_t target_eps; // target events per second
    uint32_t duration_sec; // total runtime in pause mode; 0 means no limit
    uint32_t total_logs; // per run, or per write window in pause mode; 0 means no limit
    uint32_t write_sec; // write-window duration; 0 means no time limit
    uint32_t pause_sec; // pause after each write window; 0 disables pause mode
    uint32_t batch_size; // flush file output after this many generated logs
    // ratio of different event types (they must sum to 100%)
    uint8_t ratio_benign;
    uint8_t ratio_ssh_bf;
    uint8_t ratio_web_attack;
    uint8_t ratio_sudo_abuse; // aro ashte pare
    // attack entity simulation
    uint32_t attacker_ip_pool_size;
    char victim_ip[VICTIM_IP_LEN];
    bool verbosity; // true -> echo generated log lines to stdout
} GeneratorConfig;

void config_default_init(GeneratorConfig* cfg); // puts default values in the global cfg
void config_print_usage(void); // prints tutorial on how to use the generator
int config_parse_cli(GeneratorConfig* cfg, int argc, char** argv); // returns 1 for help, -1 for invalid arguments
int config_validate(const GeneratorConfig* cfg); // validate values given in the command line
void config_dump(const GeneratorConfig* cfg); // prints a little summary of the configuration during startup
void events_init(const GeneratorConfig* cfg);
void events_free(void);
size_t gen_event(char* buf, size_t cap, const GeneratorConfig* cfg);

#endif
