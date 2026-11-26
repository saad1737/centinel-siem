#!/usr/bin/env bash
# Centinel SIEM demo pipeline: engine + follower + log generator.
#
# Usage:
#   ./run_pipeline.sh [mode] [-d <logs_per_second> <total_seconds>] [-q]
#
# Modes (each has a default rate and duration):
#   slow             5 logs/s for 20 s
#   normal           100 logs/s for 20 s         (used when no mode is given)
#   pause            5 logs/s in 10 s write windows, 5 s pause between them,
#                    for 40 s total
#   custom <eps> <sec>   your own rate and duration
#   <eps> <sec>          same as "custom" (old style: ./run_pipeline.sh 500 10)
#
# Options:
#   -d, --duration <logs_per_second> <total_seconds>
#                          override the rate AND the total run time of any mode
#   -q, --quiet            do not echo the generated logs to the terminal
#   -h, --help             show this help
#
# Examples:
#   ./run_pipeline.sh slow
#   ./run_pipeline.sh normal -d 200 60       # 200 logs/s for 60 s
#   ./run_pipeline.sh slow -d 2 30           # 2 logs/s for 30 s
#   ./run_pipeline.sh pause -d 20 120 -q     # 20 logs/s windows, 120 s total
#   ./run_pipeline.sh 500 10
#
# Ctrl+C stops the generator cleanly and still prints the final count.

# not made yet.