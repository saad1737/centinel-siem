# T0 - build everything (once)
make -C cweb_engine && make -C log_follower && make -C log_generator

# T1 - engine
sudo ./cweb_engine/centinel-engine -p 8765

# T2 - reset, then follower
rm -f /tmp/test.log /tmp/ckpt.db
: > /tmp/test.log
./log_follower/centinel_log_fol -s 127.0.0.1 -p 8765 -u /ws/ingest \
  -c /tmp/ckpt.db /tmp/test.log

# T3 - generator, printing each log as it is written
./log_generator/centinel_log_gen -e 100 -d 20              # ~2000 logs
./log_generator/centinel_log_gen -n 50 -w 10 -P 5 -d 40    # pause mode, auto-stops

## FOR T3 (log_generator)

# Rate-based: vary EPS for slow or normal speed
./log_generator/centinel_log_gen -e <eps> -d <duration_seconds>

# Pause mode: repeat write windows until the total duration ends
./log_generator/centinel_log_gen \
  -n <logs_per_window> \
  -w <write_window_seconds> \
  -P <pause_seconds> \
  -d <total_duration_seconds>