#include "log_generator.h"

void config_default_init(GeneratorConfig* cfg) {
    // zero out the struct memory first (full clear)
    memset(cfg, 0, sizeof(GeneratorConfig));

    cfg->target_port = 8080;
    cfg->target_eps = 1000;
    cfg->mode = MODE_CONTINUOUS;
    cfg->batch_size = 32;
    cfg->duration_sec = 0;
    cfg->ratio_benign = 70;
    cfg->ratio_ssh_bf = 15;
    cfg->ratio_web_attack = 10;
    cfg->ratio_sudo_abuse = 5;
    cfg->attacker_ip_pool_size = 10;
    cfg->verbosity = true;

    strncpy(cfg->target_host, "127.0.0.1", 9);
    cfg->target_host[9] = '\0'; // explicit null termination
    strncpy(cfg->target_path, "/ws/ingest", 10);
    cfg->target_path[10] = '\0'; // explicit null termination
    strncpy(cfg->victim_ip, "10.0.0.1", 8);
    cfg->victim_ip[8] = '\0';
}

void config_print_usage(void) {
    // print the full usage tutorial here
    printf("Centinel Log Generator\n");
    // code from here
    printf(
        "Usage: ./centinel_log_gen [OPTIONS]\n"
        "Connection Options:\n"
        "  -h, --host <string>       CWEB server host (Default: \"127.0.0.1\")\n"
        "  -p, --port <int>          CWEB server port (Default: 8080)\n"
        "  -u, --uri <string>        WebSocket path (Default: \"/ws/ingest\")\n"
        "Load & Execution Options:\n"
        "  -e, --eps <int>           Target events/sec (Default: 1000)\n"
        "  -m, --mode <string>       \"continuous\", \"burst\", \"bench\"\n"
        "  -b, --batch <int>         Batch flush size (Default: 32)\n"
        "  -d, --duration <int>      Duration in seconds (0 = infinite)\n"
        "Traffic Mix Options (Percentages):\n"
        "      --benign <int>        Benign traffic %% (Default: 70)\n"
        "      --ssh-bf <int>        SSH brute force %% (Default: 15)\n"
        "      --web-attack <int>    Web exploit %% (Default: 10)\n"
        "      --sudo-abuse <int>    Sudo abuse %% (Default: 5)\n"
        "      --ip-pool <int>       Number of attacker IPs (Default: 10)\n"
        "General Options:\n"
        "  -v, --verbose             Enable verbose stdout logging\n"
        "  -?, --help                Print formatted usage guide & exit\n"
    );

    exit(0); // generator must exit after showing the tutorial string
}

// the parser down below is made following these rules
// ┌───────┬──────────────────────┬─────────────────┬───────────────────────────────────────────┐
// │ Short │ Long Option          │ Argument Type   │ Description & Default                     │
// ├───────┼──────────────────────┼─────────────────┼───────────────────────────────────────────┤
// │ -h    │ --host               │ Required String │ CWEB server host (Default: "127.0.0.1")   │
// │ -p    │ --port               │ Required Int    │ CWEB server port (Default: 8080)          │
// │ -u    │ --uri                │ Required String │ WebSocket path (Default: "/ws/ingest")    │
// │ -e    │ --eps                │ Required Int    │ Target events/sec (Default: 1000)         │
// │ -m    │ --mode               │ Required String │ "continuous", "burst", "bench"            │
// │ -b    │ --batch              │ Required Int    │ Batch flush size (Default: 32)            │
// │ -d    │ --duration           │ Required Int    │ Duration in seconds (0 = infinite)        │
// │       │ --benign             │ Required Int    │ Benign traffic % (Default: 70)            │
// │       │ --ssh-bf             │ Required Int    │ SSH brute force % (Default: 15)           │
// │       │ --web-attack         │ Required Int    │ Web exploit % (Default: 10)               │
// │       │ --sudo-abuse         │ Required Int    │ Sudo abuse % (Default: 5)                 │
// │       │ --ip-pool            │ Required Int    │ Number of attacker IPs (Default: 10)      │
// │ -v    │ --verbose            │ No Argument     │ Enable verbose stdout logging             │
// │ -?    │ --help               │ No Argument     │ Print formatted usage guide & exit        │
// └───────┴──────────────────────┴─────────────────┴───────────────────────────────────────────┘

int config_parse_cli(GeneratorConfig* cfg, int argc, char** argv) {
    // helper enum for the long options who don't have a short option
    enum { // starting from a number where no ascii characters fall
        OPT_BENIGN = 1000,
        OPT_SSH_BF,
        OPT_WEB_ATTACK,
        OPT_SUDO_ABUSE,
        OPT_IP_POOL
    };
    // defining the option array
    static struct option options[] = {
        {"host", 1, 0, 'h'},
        {"port", 1, 0, 'p'},
        {"uri", 1, 0, 'u'},
        {"eps", 1, 0, 'e'},
        {"mode", 1, 0, 'm'},
        {"batch", 1, 0, 'b'},
        {"duration", 1, 0, 'd'},
        {"verbose", 0, 0, 'v'}, // no value comes after this option
        {"help", 0, 0, '?'}, // no value comes after this option
        {"benign", 1, 0, OPT_BENIGN},
        {"ssh-bf", 1, 0, OPT_SSH_BF},
        {"web-attack", 1, 0, OPT_WEB_ATTACK},
        {"sudo-abuse", 1, 0, OPT_SUDO_ABUSE},
        {"ip-pool", 1, 0, OPT_IP_POOL},
        {0, 0, 0, 0}   // centinel: tells getopt_long where the table ends to avoid Undefined Behaviour (UB)
    };

    int idx = 0;
    const char* short_options = "h:p:u:e:m:b:d:v";

    // check `man getopt_long` for details on the function usage
    int opt = getopt_long(argc, argv, short_options, options, &idx);
    while (opt != -1) {
        // switch case better and faster than a complex if/else tree
        switch (opt) { // value for the option is stored in `optarg`
            case 'h': {
                if (!optarg) {
                    fprintf(stderr, "No host ip given\n");
                    return -1; // abort
                }

                size_t size = strlen(optarg);
                if (size >= TARGET_HOST_LEN) {
                    fprintf(stderr, "Host IP too large\n");
                    return -1;
                }

                // safely copy the target host ip in the required config field
                snprintf(cfg->target_host, sizeof(cfg->target_host), "%s", optarg);
                cfg->target_host[size] = '\0'; // explicit null termination
                break;
            }
            case 'p': {
                if (!optarg) {
                    fprintf(stderr, "No port given\n");
                    return -1; // abort
                }

                // convert the string to unsigned long
                unsigned long port = strtoul(optarg, NULL, 10);

                // port validation before the typecast
                if (port == 0 || port > 65535) {
                    fprintf(stderr, "Invalid port\n");
                    return -1;
                }

                // put port in target_port
                cfg->target_port = (uint16_t)port;
                break;
            }
            case 'u': {
                if (!optarg) {
                    fprintf(stderr, "No uri given\n");
                    return -1; // abort
                }

                size_t size = strlen(optarg);
                if (size >= TARGET_PATH_LEN) {
                    fprintf(stderr, "URI too large\n");
                    return -1;
                }

                // safely copy the target uri in the required config field
                snprintf(cfg->target_path, sizeof(cfg->target_path), "%s",optarg);
                cfg->target_path[size] = '\0'; // explicit null termination
                break;
            }
            case 'e': {
                if (!optarg) {
                    fprintf(stderr, "No eps given\n");
                    return -1; // abort
                }

                // convert the string to unsigned long
                unsigned long eps = strtoul(optarg, NULL, 10);

                // put eps in eps field
                cfg->target_eps = (uint32_t)eps;
                break;
            }
            case 'm': {
                if (!optarg) {
                    fprintf(stderr, "No mode given\n");
                    return -1; // abort
                }

                if (!strcasecmp(optarg, "continuous")) cfg->mode = MODE_CONTINUOUS;
                else if (!strcasecmp(optarg, "burst")) cfg->mode = MODE_BURST;
                else if (!strcasecmp(optarg, "bench")) cfg->mode = MODE_BENCHMARK;
                else {
                    fprintf(stderr, "Unrecognized mode\n");
                    return -1;
                }
                break;
            }
            case 'b': {
                if (!optarg) {
                    fprintf(stderr, "No batch size given\n");
                    return -1; // abort
                }

                // convert the string to unsigned long
                unsigned long batch = strtoul(optarg, NULL, 10);

                cfg->batch_size = (uint32_t)batch;
                break;
            }
            case 'd': {
                if (!optarg) {
                    fprintf(stderr, "No duration given\n");
                    return -1; // abort
                }

                // convert the string to unsigned long
                unsigned long duration = strtoul(optarg, NULL, 10);

                cfg->duration_sec = (uint32_t)duration;
                break;
            }
            case 'v': { // no optarg for this
                // turn thye verbosity flag true
                cfg->verbosity = true;
                break;
            }
            case '?': { // no optarg for this
                // print the usage tutorial
                config_print_usage();
                break;
            }
            case OPT_BENIGN: {
                if (!optarg) {
                    fprintf(stderr, "No benign ratio given\n");
                    return -1; // abort
                }

                // convert the string to unsigned long
                unsigned long benign = strtoul(optarg, NULL, 10);

                cfg->ratio_benign = (uint8_t)benign;
                break;
            }
            case OPT_IP_POOL: {
                if (!optarg) {
                    fprintf(stderr, "No ip_pool size given\n");
                    return -1; // abort
                }

                // convert the string to unsigned long
                unsigned long ip_pool = strtoul(optarg, NULL, 10);

                cfg->attacker_ip_pool_size = (uint32_t)ip_pool;
                break;
            }
            case OPT_SSH_BF: {
                if (!optarg) {
                    fprintf(stderr, "No ssh-bf ratio given\n");
                    return -1; // abort
                }

                // convert the string to unsigned long
                unsigned long ssh = strtoul(optarg, NULL, 10);

                cfg->ratio_ssh_bf = (uint8_t)ssh;
                break;
            }
            case OPT_SUDO_ABUSE: {
                if (!optarg) {
                    fprintf(stderr, "No sudo abuse ratio given\n");
                    return -1; // abort
                }

                // convert the string to unsigned long
                unsigned long sudo = strtoul(optarg, NULL, 10);

                cfg->ratio_sudo_abuse = (uint8_t)sudo;
                break;
            }
            case OPT_WEB_ATTACK: {
                if (!optarg) {
                    fprintf(stderr, "No web attack ratio given\n");
                    return -1; // abort
                }

                // convert the string to unsigned long
                unsigned long web = strtoul(optarg, NULL, 10);

                cfg->ratio_web_attack = (uint8_t)web;
                break;
            }
        }
        opt = getopt_long(argc, argv, short_options, options, &idx);
    }

    return 0;
}

// helper function to convert mode into string
static const char* mode_to_str(GeneratorMode mode) {
    switch (mode) {
        case MODE_CONTINUOUS: return "continuous";
        case MODE_BURST:      return "burst";
        case MODE_BENCHMARK:  return "benchmark (unthrottled)";
    }
    return "unknown";
}

int config_validate(const GeneratorConfig* cfg) { // abort the program if this function returns -1
    // check NULL
    if (cfg == NULL) {
        fprintf(stderr, "Config is null.\n");
        return -1;
    }

    // events per second validation
    if (cfg->target_eps == 0 || cfg->target_eps > MAX_EPS) {
        fprintf(stderr, "EPS out of allowed range\n");
        return -1;
    }

    // batch size validation
    if (cfg->batch_size == 0 || cfg->batch_size > MAX_BATCH_SiZE) {
        fprintf(stderr, "Batch size out of allowed range\n");
        return -1;
    }

    // ratio sum validation
    int ratio_sum = cfg->ratio_benign + cfg->ratio_ssh_bf + cfg->ratio_sudo_abuse + cfg->ratio_web_attack;
    if (ratio_sum != 100) {
        fprintf(stderr, "Ratio sum must be equal to 100 percent (got %d)\n", ratio_sum);
        return -1;
    }

    // check if the host ip is correct (ipv4 format)
    struct in_addr addr;
    if (inet_pton(AF_INET, cfg->target_host, &addr) != 1) {
        fprintf(stderr, "Invalid target host \"%s\"\n", cfg->target_host);
        return -1;
    }

    // check if the victim is correct (ipv4 format)
    struct in_addr victim;
    if (inet_pton(AF_INET, cfg->victim_ip, &victim) != 1) {
        fprintf(stderr, "Invalid victim IP \"%s\"\n", cfg->victim_ip);
        return -1;
    }

    // check the target path
    if (cfg->target_path[0] != '/') {
        fprintf(stderr, "URI must start with '/' (got \"%s\")\n", cfg->target_path);
        return -1;
    }

    // other validity checks if needed
    

    return 0;
}

void config_dump(const GeneratorConfig* cfg) {
    // Print generator config summary here on startup
    printf("Centinel SIEM - High Performance VPS Attack Log Generator\n");
    // Print summary from here...
    // well, if the formatting is bad then it can be improved.
    printf("=============================================================================\n");
    printf("    Target  : ws://%s:%u%s\n", cfg->target_host, (unsigned)cfg->target_port, cfg->target_path);
    printf("    Mode    : %s\n", mode_to_str(cfg->mode));

    if (cfg->mode == MODE_BENCHMARK) {
        printf("    Target EPS  : unlimited\n"); // unlimited in CPU's capacity
    } else {
        printf("    Target EPS  : %u\n", cfg->target_eps);
    }   

    printf("    Batch size  : %u\n", cfg->batch_size);

    if (cfg->duration_sec == 0) {
        printf("    Duration    : infinite (Ctrl+C to stop)\n");
    } else {
        printf("    Duration    : %u s\n", cfg->duration_sec);
    }

    printf("    Traffic mix : benign %u%% | ssh-bf %u%% | web-attack %u%% | sudo-abuse %u%%\n",
           (unsigned)cfg->ratio_benign, (unsigned)cfg->ratio_ssh_bf,
           (unsigned)cfg->ratio_web_attack, (unsigned)cfg->ratio_sudo_abuse);
    printf("    Attackers : %u unique IPs -> victim %s\n", cfg->attacker_ip_pool_size, cfg->victim_ip);
    printf("    Verbose   : %s\n", cfg->verbosity ? "on" : "off");
    printf("=============================================================================\n");
    fflush(stdout);
}
