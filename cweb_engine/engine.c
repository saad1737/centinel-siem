#include "engine.h"

static EngineConfig config = {
    .port = ENGINE_DEFAULT_PORT,
    .batch_threshold = DEFAULT_BATCH_THRESHOLD
};

// server health check
HandlerState get_health_handler(CwebContext* ctx) {
    send_json(ctx, 200, "{\"status\":\"ok\"}");
    return DB_DONE;
}

// log ingestion handler
HandlerState ws_ingest_handler(CwebContext* ctx) {
    // websockets check
    if (!ctx->is_websocket) { // upgrade from HTTP to WS first
        upgrade_to_websocket(ctx);
        if (ctx->is_websocket)
            printf("[Worker %d] WebSocket client upgraded\n", getpid());
        fflush(stdout);
        return DB_DONE;
    }

    // handle websocket communication when it is 100% ensured that the connection is properly upgraded
    if (ctx->is_websocket) {
        // error guard
        if (!ctx->ws_payload || ctx->ws_payload_len == 0) { // no frame received
            send_ws_text(ctx, "ACK");
            return DB_DONE;
        }
    
        // print the frame for verification
        printf("[Worker %d] Frame (%zu bytes):\n%.*s\n", getpid(), ctx->ws_payload_len, (int)ctx->ws_payload_len, ctx->ws_payload);
        fflush(stdout);
    
        send_ws_text(ctx, "ACK"); // sending acknowledgement of the received frame (prevent a 0 byte send from CWEB)
        return DB_DONE;
    }

    return 0; // just so LSP shuts up about it
}

void print_usage(const char *prog_name) {
    printf("Centinel SIEM Engine\n");
    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("Options:\n");
    printf("  -p, --port <port>         SIEM server port (default: 8765)\n");
    printf("  -b, --batch <batchSize>   Batch size for ingestion\n");
    printf("  -h, --help                Display this manual\n\n");
}

int main(int argc, char** argv) {
    // options for cli parsing
    static struct option long_options[] = {
        {"port", 1, 0, 'p'},
        {"batch", 1, 0, 'b'},
        {"help", 0, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    char end;
    char* endptr = &end;
    *endptr = '\0';
    while ((opt = getopt_long(argc, argv, "p:b:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p': {
                if (!optarg || optarg[0] == '\0' || optarg[0] == '-') {
                    fprintf(stderr, "Error: Invalid value for options\n");
                    return EXIT_FAILURE;
                }
                
                unsigned long p = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    fprintf(stderr, "Error: Invalid value for options\n");
                    return EXIT_FAILURE;
                }
                if (p == 0 || p > 65535) {
                    fprintf(stderr, "Error: Invalid port number: %s\n", optarg);
                    return EXIT_FAILURE;
                }
                config.port = (int)p;
                break;
            }
            case 'b': {
                if (!optarg || optarg[0] == '\0' || optarg[0] == '-') {
                    fprintf(stderr, "Error: Invalid value for options\n");
                    return EXIT_FAILURE;
                }
                
                size_t b = (size_t)strtoul(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    fprintf(stderr, "Error: Invalid value for options\n");
                    return EXIT_FAILURE;
                }
                if (b >= 1 && b <= MAX_BATCH_CAPACITY) {
                    config.batch_threshold = b;
                }
                else {
                    fprintf(stderr, "Error: Invalid batch size number: %s\n", optarg);
                    return EXIT_FAILURE;
                }
                break;
            }
            case 'h': 
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            default:
                fprintf(stderr, "Error parsing the cmd line\n");
                return EXIT_FAILURE;
        }
    }
    
    // insert all endpoints with their handlers
    insert_route(GET, "/health", get_health_handler);
    insert_route(GET, "/ws/ingest", ws_ingest_handler);

    return cweb_run_server(config.port, NULL, 0);
}