#include "log_generator.h"
#include <errno.h>

static int parse_u32_arg(const char* text, const char* name, uint32_t* value) {
    char* end = NULL;
    unsigned long long parsed;

    if (!text || !text[0] || text[0] == '-') {
        fprintf(stderr, "Invalid %s: %s\n", name, text ? text : "(missing)");
        return -1;
    }

    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno == ERANGE || end == text || *end != '\0' || parsed > UINT32_MAX) {
        fprintf(stderr, "Invalid %s: %s\n", name, text);
        return -1;
    }

    *value = (uint32_t)parsed;
    return 0;
}

void config_default_init(GeneratorConfig* cfg) {
    // zero out the struct memory first (full clear)
    memset(cfg, 0, sizeof(GeneratorConfig));

    cfg->target_port = 8080;
    cfg->target_eps = 1000;
    cfg->mode = MODE_CONTINUOUS;
    cfg->batch_size = 32;
    cfg->duration_sec = 0;
    cfg->total_logs = 0;
    cfg->write_sec = 0;
    cfg->pause_sec = 0;
    cfg->ratio_benign = 70;
    cfg->ratio_ssh_bf = 15;
    cfg->ratio_web_attack = 10;
    cfg->ratio_sudo_abuse = 5;
    cfg->attacker_ip_pool_size = 10;
    cfg->verbosity = true;

    snprintf(cfg->target_host, sizeof cfg->target_host, "127.0.0.1");
    snprintf(cfg->target_path, sizeof cfg->target_path, "/tmp/test.log");
    snprintf(cfg->victim_ip,   sizeof cfg->victim_ip,   "10.0.0.1");
}

void config_print_usage(void) {
    printf(
        "Usage: ./centinel_log_gen <logs> <seconds> [OPTIONS]  (normal mode)\n"
        "       ./centinel_log_gen -n <logs> -w <seconds> -P <pause> [OPTIONS]\n"
        "Output Options:\n"
        "  -o, --output <file>       Log file to append to (Default: /tmp/test.log)\n"
        "  -q, --quiet               Do not echo generated logs to the terminal\n"
        "Load & Execution Options:\n"
        "  -e, --eps <int>           Target events/sec (Default: 1000)\n"
        "  -n, --count <int>         Number of logs (per window in pause mode)\n"
        "  -w, --write-time <int>    Write-window duration in seconds\n"
        "  -P, --pause <int>         Pause after each write window\n"
        "  -m, --mode <string>       \"continuous\", \"burst\", \"bench\"\n"
        "  -b, --batch <int>         Batch flush size (Default: 32)\n"
        "  -d, --duration <int>      Normal write time; pause-mode total runtime\n"
        "Traffic Mix Options (Percentages):\n"
        "      --benign <int>        Benign traffic %% (Default: 70)\n"
        "      --ssh-bf <int>        SSH brute force %% (Default: 15)\n"
        "      --web-attack <int>    Web exploit %% (Default: 10)\n"
        "      --sudo-abuse <int>    Sudo abuse %% (Default: 5)\n"
        "      --ip-pool <int>       Number of attacker IPs (Default: 10)\n"
        "General Options:\n"
        "  -v, --verbose             Enable verbose stdout logging\n"
        "  -?, --help                Print formatted usage guide\n"
        "Legacy connection options -h/--host, -p/--port, and -u/--uri are unused.\n"
    );
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
        OPT_HELP = 1000,
        OPT_BENIGN,
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
        {"output", 1, 0, 'o'},
        {"eps", 1, 0, 'e'},
        {"mode", 1, 0, 'm'},
        {"batch", 1, 0, 'b'},
        {"duration", 1, 0, 'd'},
        {"count", 1, 0, 'n'},
        {"write-time", 1, 0, 'w'},
        {"pause", 1, 0, 'P'},
        {"verbose", 0, 0, 'v'}, // no value comes after this option
        {"quiet", 0, 0, 'q'},
        {"help", 0, 0, OPT_HELP},
        {"benign", 1, 0, OPT_BENIGN},
        {"ssh-bf", 1, 0, OPT_SSH_BF},
        {"web-attack", 1, 0, OPT_WEB_ATTACK},
        {"sudo-abuse", 1, 0, OPT_SUDO_ABUSE},
        {"ip-pool", 1, 0, OPT_IP_POOL},
        {0, 0, 0, 0}   // centinel: tells getopt_long where the table ends to avoid Undefined Behaviour (UB)
    };

    int idx = 0;
    bool count_option_set = false;
    bool write_option_set = false;
    const char* short_options = "h:p:u:o:e:m:b:d:n:w:P:vq?";

    optind = 1;
    opterr = 0;
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
                break;
            }
            case 'o': {
                if (!optarg || !optarg[0] || strlen(optarg) >= TARGET_PATH_LEN) {
                    fprintf(stderr, "Invalid output path\n");
                    return -1;
                }
                snprintf(cfg->target_path, sizeof(cfg->target_path), "%s", optarg);
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
            case 'n': {
                if (parse_u32_arg(optarg, "log count", &cfg->total_logs) != 0) return -1;
                count_option_set = true;
                break;
            }
            case 'w': {
                if (parse_u32_arg(optarg, "write time", &cfg->write_sec) != 0) return -1;
                write_option_set = true;
                break;
            }
            case 'P': {
                if (parse_u32_arg(optarg, "pause duration", &cfg->pause_sec) != 0) return -1;
                break;
            }
            case 'v': { // no optarg for this
                // turn thye verbosity flag true
                cfg->verbosity = true;
                break;
            }
            case 'q': {
                cfg->verbosity = false;
                break;
            }
            case OPT_HELP: {
                config_print_usage();
                return 1;
            }
            case '?': {
                if (optind > 0 && strcmp(argv[optind - 1], "-?") == 0) {
                    config_print_usage();
                    return 1;
                }
                fprintf(stderr, "Unknown option or missing option value near \"%s\"\n",
                        optind > 0 ? argv[optind - 1] : "");
                return -1;
            }
            case OPT_BENIGN: {
                if (!optarg) {
                    fprintf(stderr, "No benign ratio given\n");
                    return -1; // abort
                }

                // convert the string to unsigned long
                unsigned long benign = strtoul(optarg, NULL, 10);

                if (benign > 100) {
                    fprintf(stderr, "Benign ratio must be between 0 and 100\n");
                    return -1;
                }
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

                if (ssh > 100) {
                    fprintf(stderr, "SSH brute-force ratio must be between 0 and 100\n");
                    return -1;
                }
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

                if (sudo > 100) {
                    fprintf(stderr, "Sudo-abuse ratio must be between 0 and 100\n");
                    return -1;
                }
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

                if (web > 100) {
                    fprintf(stderr, "Web attack ratio must be between 0 and 100\n");
                    return -1;
                }
                cfg->ratio_web_attack = (uint8_t)web;
                break;
            }
        }
        opt = getopt_long(argc, argv, short_options, options, &idx);
    }

    if (optind < argc) {
        uint32_t logs;
        uint32_t seconds;

        if (argc - optind != 2 || count_option_set || write_option_set ||
            parse_u32_arg(argv[optind], "number of logs", &logs) != 0 ||
            parse_u32_arg(argv[optind + 1], "number of seconds", &seconds) != 0 ||
            (logs == 0 && seconds == 0)) {
            fprintf(stderr, "Usage: ./centinel_log_gen <number_of_logs> <number_of_seconds>\n");
            return -1;
        }
        cfg->total_logs = logs;
        cfg->write_sec = seconds;
    }

    if (cfg->pause_sec > 0) {
        cfg->mode = MODE_BURST;
    } else if (cfg->duration_sec > 0) {
        if (cfg->write_sec == 0) {
            cfg->write_sec = cfg->duration_sec;
        } else if (cfg->write_sec != cfg->duration_sec) {
            fprintf(stderr, "Conflicting --duration and --write-time values\n");
            return -1;
        }
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
    if (cfg->batch_size == 0 || cfg->batch_size > MAX_BATCH_SIZE) {
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

    if (cfg->target_path[0] == '\0') {
        fprintf(stderr, "Output path cannot be empty\n");
        return -1;
    }

    // check attacker_ip_pool_size
    if (cfg->attacker_ip_pool_size == 0) {
        fprintf(stderr, "IP pool size must be at least 1\n");
        return -1;
    }

    if (cfg->mode == MODE_BURST && cfg->pause_sec == 0) {
        fprintf(stderr, "Pause mode requires --pause <seconds>\n");
        return -1;
    }
    if (cfg->pause_sec > 0 && cfg->total_logs == 0 && cfg->write_sec == 0) {
        fprintf(stderr, "Pause mode requires --count or --write-time to define a write window\n");
        return -1;
    }
    if (cfg->total_logs > 0 && cfg->write_sec > 0 &&
        (uint64_t)cfg->total_logs > (uint64_t)MAX_EPS * cfg->write_sec) {
        fprintf(stderr, "%u logs in %u seconds exceeds the maximum rate of %d EPS\n",
                cfg->total_logs, cfg->write_sec, MAX_EPS);
        return -1;
    }

    return 0;
}

void config_dump(const GeneratorConfig* cfg) {
    // Print generator config summary here on startup
    printf("Centinel SIEM - High Performance VPS Attack Log Generator\n");
    // Print summary from here...
    // well, if the formatting is bad then it can be improved.
    printf("=============================================================================\n");
    printf("    Output Path : %s\n", cfg->target_path);
    printf("    Mode        : %s\n", mode_to_str(cfg->mode));

    if (cfg->mode == MODE_BENCHMARK) {
        printf("    Target EPS  : unlimited\n");
    } else if (cfg->total_logs > 0 && cfg->write_sec > 0) {
        printf("    Rate        : %u logs in %u s (%.2f logs/s)\n", cfg->total_logs,
               cfg->write_sec, (double)cfg->total_logs / cfg->write_sec);
    } else {
        printf("    Target EPS  : %u\n", cfg->target_eps);
    }

    if (cfg->total_logs > 0) {
        printf("    Log count   : %u%s\n", cfg->total_logs,
               cfg->pause_sec ? " per write window" : "");
    }
    if (cfg->write_sec > 0) {
        printf("    Write time  : %u s%s\n", cfg->write_sec,
               cfg->pause_sec ? " per window" : "");
    }
    if (cfg->pause_sec > 0) {
        printf("    Pause       : %u s after each write window\n", cfg->pause_sec);
        if (cfg->duration_sec > 0) {
            printf("    Total time  : %u s\n", cfg->duration_sec);
        } else {
            printf("    Total time  : infinite (Ctrl+C to stop)\n");
        }
    } else if (cfg->total_logs > 0 && cfg->write_sec == 0) {
        printf("    Duration    : until all logs are written\n");
    } else if (cfg->write_sec == 0 && cfg->total_logs == 0) {
        printf("    Duration    : infinite (Ctrl+C to stop)\n");
    }

    printf("    Batch size  : %u\n", cfg->batch_size);

    printf("    Traffic mix : benign %u%% | ssh-bf %u%% | web-attack %u%% | sudo-abuse %u%%\n",
           (unsigned)cfg->ratio_benign, (unsigned)cfg->ratio_ssh_bf,
           (unsigned)cfg->ratio_web_attack, (unsigned)cfg->ratio_sudo_abuse);
    printf("    Attackers   : %u unique IPs -> victim %s\n", cfg->attacker_ip_pool_size, cfg->victim_ip);
    printf("    Verbose     : %s\n", cfg->verbosity ? "on" : "off");
    printf("=============================================================================\n");
    fflush(stdout);
}
