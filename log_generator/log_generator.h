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
#define TARGET_PATH_LEN 16
#define VICTIM_IP_LEN 16
#define MAX_EPS 500000
#define MAX_BATCH_SiZE 4096

typedef enum {
    MODE_CONTINUOUS, // normal paced log streaming with specifies EPS
    MODE_BURST, // to alternate between calm periods and sudden attack spikes
    MODE_BENCHMARK // maximum unthrottled loop (as much CPU and socket allows)
} GeneratorMode;

typedef struct {
    char target_host[TARGET_HOST_LEN]; // Stores address of the CWEB engine
    uint16_t target_port; // Stores CWEB engine server port
    char target_path[TARGET_PATH_LEN]; // Stores '/ws/ingest' endpoint
    GeneratorMode mode;
    uint32_t target_eps; // target events per second
    uint32_t duration_sec; // seconds the generator will run. 0 = infinite execution until SIGINT
    uint32_t batch_size; // number of logs sent per websocket connection
    // ratio of different event types (they must sum to 100%)
    uint8_t ratio_benign;
    uint8_t ratio_ssh_bf;
    uint8_t ratio_web_attack;
    uint8_t ratio_sudo_abuse;
    // attack entity simulation
    uint32_t attacker_ip_pool_size;
    char victim_ip[VICTIM_IP_LEN];
    bool verbosity; // true -> prints in the terminal (mainly output goes via websockets to the CWEB engine)
} GeneratorConfig;

void config_default_init(GeneratorConfig* cfg); // puts default values in the global cfg
void config_print_usage(void); // prints tutorial on how to use the generator
int config_parse_cli(GeneratorConfig* cfg, int argc, char** argv); // parse the command line for field values
int config_validate(const GeneratorConfig* cfg); // validate values given in the command line
void config_dump(const GeneratorConfig* cfg); // prints a little summary of the configuration during startup

#endif
