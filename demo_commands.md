# Centinel SIEM — Live Pipeline Demo Commands

End-to-end live flow:
**`centinel_log_gen` $\rightarrow$ `/tmp/test.log` $\rightarrow$ `centinel_log_fol` (inotify + WebSocket) $\rightarrow$ `centinel-engine` (CWEB `io_uring`) $\rightarrow$ Terminal**

---

## Step 0: Compile All Components

Run once (or after editing any source file) from the `sentinel_siem` root directory:

```bash
cd "/home/nigger/System Programming/sentinel_siem"

# Clean & build all three binaries
make -C cweb_engine clean && make -C cweb_engine
make -C log_follower clean && make -C log_follower
make -C log_generator clean && make -C log_generator
```

Expected executables:
- `./cweb_engine/centinel-engine`
- `./log_follower/centinel_log_fol`
- `./log_generator/centinel_log_gen`

---

## Step 1 (Terminal 1): Start the CWEB SIEM Engine

`cweb_engine` binds port `8765`, forks one worker per CPU core, drops privileges to `nobody`, and sandboxes via `chroot`/`seccomp`, so it must be launched with `sudo`:

```bash
cd "/home/nigger/System Programming/sentinel_siem"
sudo ./cweb_engine/centinel-engine -p 8765 -b 16
```

**Expected output:**
```text
Server started with <N> Workers on Port 8765...
```

*(Optional)* Verify the HTTP health endpoint from another terminal:
```bash
curl -i http://127.0.0.1:8765/health
# Expected: HTTP/1.1 200 OK -> {"status":"ok"}
```

---

## Step 2 (Terminal 2): Reset State & Start the Log Follower

Reset `/tmp/test.log` and `/tmp/ckpt.db` before launching the follower so tracking starts cleanly from byte offset `0`:

```bash
cd "/home/nigger/System Programming/sentinel_siem"
rm -f /tmp/test.log /tmp/ckpt.db
: > /tmp/test.log

./log_follower/centinel_log_fol \
  -s 127.0.0.1 \
  -p 8765 \
  -u /ws/ingest \
  -c /tmp/ckpt.db \
  /tmp/test.log
```

**Expected output:**
- **Terminal 2 (`centinel_log_fol`):** `[WS] Connected to CWEB SIEM at ws://127.0.0.1:8765/ws/ingest`
- **Terminal 1 (`centinel-engine`):** `[Worker <pid>] WebSocket client upgraded`

---

## Step 3 (Terminal 3): Generate Logs & Watch Live Transfers

Run **one** of the following scenarios in Terminal 3 while watching NDJSON frames stream live onto **Terminal 1 (`centinel-engine`)**:

### A. Slow Readable Demo (10 logs/sec for 15s = 150 logs)
Best for visually comparing lines generated in Terminal 3 with WebSocket NDJSON batches printed in Terminal 1:
```bash
cd "/home/nigger/System Programming/sentinel_siem"
./log_generator/centinel_log_gen -o /tmp/test.log -e 10 -d 15
```

### B. Standard Continuous Stream (~2,000 logs at 100 EPS)
```bash
cd "/home/nigger/System Programming/sentinel_siem"
./log_generator/centinel_log_gen -o /tmp/test.log -e 100 -d 20
```

### C. Pause / Keep-Alive Demo (50 logs/10s window, 5s idle pauses for 40s)
Demonstrates `centinel_log_fol` sending WebSocket `PING` frames during quiet windows so CWEB keeps the tunnel open past its 5-second Slowloris timeout:
```bash
cd "/home/nigger/System Programming/sentinel_siem"
./log_generator/centinel_log_gen -o /tmp/test.log -n 50 -w 10 -P 5 -d 40
```

### D. Unthrottled Flood & Backpressure Demo (5,000 logs, quiet generator)
Uses `-q` to avoid stdout bottlenecking, flooding `/tmp/test.log` fast enough to trigger the 48-chunk high watermark pause and 16-chunk low watermark resume in Terminal 2:
```bash
cd "/home/nigger/System Programming/sentinel_siem"
./log_generator/centinel_log_gen -o /tmp/test.log -m bench -n 5000 -b 256 -q
```

### E. Attack-Heavy Traffic Mix (90% Attacks / 10% Benign)
```bash
cd "/home/nigger/System Programming/sentinel_siem"
./log_generator/centinel_log_gen \
  -o /tmp/test.log -e 50 -d 10 \
  --benign 10 --ssh-bf 50 --web-attack 30 --sudo-abuse 10 --ip-pool 5
```

---

## Step 4: Live File Rotation / Truncation & Clean Teardown

### Test In-Place Truncation (`copytruncate`) While Running
Wait for any active generator in Terminal 3 to exit, truncate `/tmp/test.log` in place, and stream again:
```bash
: > /tmp/test.log
./log_generator/centinel_log_gen -o /tmp/test.log -e 20 -d 5
```

### Test Delete & Recreate (`logrotate`) While Running
Wait for any active generator to exit (so no open descriptor stays on the unlinked inode), remove and recreate the file, then stream again:
```bash
rm -f /tmp/test.log && : > /tmp/test.log
./log_generator/centinel_log_gen -o /tmp/test.log -e 20 -d 5
```

### Graceful Shutdown Order
Press **`Ctrl+C`** in reverse startup order:
1. **Terminal 3** (`centinel_log_gen`, if still running)
2. **Terminal 2** (`centinel_log_fol` $\rightarrow$ `fsync`s `/tmp/ckpt.db` and prints `Stopped monitoring.`)
3. **Terminal 1** (`centinel-engine` $\rightarrow$ cleanly exits worker processes)

---

## CLI Parameter Quick Reference (`centinel_log_gen`)

```bash
# Rate-based continuous mode
./log_generator/centinel_log_gen -o /tmp/test.log -e <eps> -d <duration_seconds>

# Windowed burst + pause mode
./log_generator/centinel_log_gen \
  -o /tmp/test.log \
  -n <logs_per_window> \
  -w <write_window_seconds> \
  -P <pause_seconds> \
  -d <total_duration_seconds>
```
