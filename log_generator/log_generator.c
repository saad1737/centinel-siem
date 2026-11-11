#include "log_generator.h"

// declare the global config struct here
static GeneratorConfig config;

int main(int argc, char** argv) {
    // fill the config with default values
    config_default_init(&config);

    // parse command line and update the config accordingly
    if (config_parse_cli(&config, argc, argv) ==  -1) {
        fprintf(stderr, "Parsing error\n");
        return -1;
    }

    // validate the parsed values
    if (config_validate(&config) == -1) {
        fprintf(stderr, "Validation error\n");
        return -1;
    }

    // print summary
    config_dump(&config);

    // more logic goes here

    return 0;
}
