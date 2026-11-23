# Centinel SIEM — High-Performance Log Follower Daemon

A lightweight, zero-dependency, production-grade Linux log shipping daemon written in C99. Modeled after the architectural core of **Fluent Bit**, Centinel is engineered specifically for resource-constrained Linux VPS instances and edge environments where memory footprint, CPU utilization, and zero-loss guarantees are paramount.

Centinel continuously tails standard Linux log files (`/var/log/*`), automatically handles log rotations and truncations, frames streaming logs into structured NDJSON, bounds memory using a watermark-driven ring buffer backpressure engine, atomically checkpoints file offsets to disk, and streams encrypted or raw WebSocket frames via a non-blocking RFC 6455 client to a custom high-concurrency C SIEM ingestion framework (**CWEB**).

---

## Architectural Highlights

- **Ultra-Low Memory Footprint**: Operates stably at **~2.8 MB RSS**, bounded by design. Hardened with a `MemoryMax=32M` Linux cgroup ceiling.
- **Event-Driven Non-Blocking Reactor**: Powered by a single-threaded Linux `epoll` reactor multiplexing `inotify` file watchers, `timerfd` periodic ticks, and non-blocking TCP socket state machines.
- **Zero Loss / Zero Duplicate Guarantee**: Atomic binary checkpointing (`pread`/`pwrite`) records device IDs, inode numbers, and byte offsets. Survives daemon restarts, system reboots, and network blackouts.
- **Intelligent Rotation & Truncation Handling**: Seamlessly distinguishes between classic file rotations (`mv` / `IN_MOVE_SELF`), new inode creation (`IN_CREATE`), and `copytruncate` log zeroing (`st_size < offset`).
- **Watermark Backpressure Engine**: 64-slot memory ring buffer with High Watermark (75% / 48 chunks) pause and Low Watermark (25% / 16 chunks) resume logic, offloading bursts safely to the Linux page cache.
- **CWEB-Compliant RFC 6455 Client**: Native WebSocket protocol implementation featuring 24-character Base64 handshake verification, 4-byte client XOR payload masking, exponential reconnect backoff, and 2.5-second heartbeat PINGs to disarm server-side Slowloris watchdogs.

---

## System Architecture

```
                                  +--------------------------------------------------+
                                  |                 LINUX KERNEL                     |
                                  |                                                  |
  +------------------+            |   +-------------------+   +------------------+   |
  |  /var/log/*.log  | ---------> |   | inotify Subsystem |   | timerfd (500ms)  |   |
  +------------------+            |   +-------------------+   +------------------+   |
                                  +-------------|-----------------------|------------+
                                                |                       |
                                                v                       v
+------------------------------------------------------------------------------------+
|                         CENTINEL EPOLL REACTOR (Single-Threaded)                   |
|                                                                                    |
|   +-------------------------+      +-------------------------+                     |
|   |   Sliding Carryover     | ---> |    NDJSON Serializer    |                     |
|   |      Line Buffer        |      |    & JSON Escaping      |                     |
|   +-------------------------+      +-------------------------+                     |
|                                                 |                                  |
|                                                 v                                  |
|                                    +-------------------------+                     |
|                                    | 64-Chunk Ring Buffer    |                     |
|                                    | (12 KB Chunks, ~768 KB) |                     |
|                                    +-------------------------+                     |
|                                      |                     ^                       |
|         High Watermark (48 chunks)   |                     | Low Watermark (16)    |
|         [PAUSE INOTIFY READS] -------+                     +-- [RESUME INGESTION]  |
|                                      |                                             |
|                                      v                                             |
|                        +---------------------------+                               |
|                        | RFC 6455 WebSocket Client |                               |
|                        | (Non-blocking / Masked)   |                               |
|                        +---------------------------+                               |
+--------------------------------------|---------------------------------------------+
                                       |
                   TCP / WebSocket     |  Heartbeat PING (every 2.5s)
                   (Port 8765)         v  HTTP 101 Switching Protocols
                         +---------------------------+
                         |     CWEB SIEM SERVER      |
                         | (io_uring Ingestion Core) |
                         +---------------------------+
```

---

## Core Systems & Deep Internals

### 1. Inotify Deduplication & Rotation Lifecycle
Linux's `inotify` API presents significant challenges during file rotation:
- **Directory Watch Deduplication**: To catch newly created rotated files (`auth.log.1` -> `auth.log`), parent directories must be monitored. If multiple tracked files reside in `/var/log`, Centinel registers a single watch descriptor (`wd`) for `/var/log` using an internal reference-counted hashmap (`dirs_by_wd`).
- **Classic Rotation (`mv`)**: When a log is rotated, the kernel emits `IN_MOVE_SELF` or `IN_DELETE_SELF`. Centinel flushes remaining unread bytes from the old file descriptor, disarms its file watch, and keeps the parent directory watch active. When the replacement file is created (`IN_CREATE` or `IN_MOVED_TO`), Centinel dynamically attaches a new file watch, inspects the new inode, and resets the offset to 0.
- **Copytruncate Handling**: Loggers like Docker or `logrotate` with `copytruncate` zero out files in-place without altering the inode. On every `IN_MODIFY` event, Centinel executes `fstat()`. If `st_size < file->offset`, truncation is detected; the file pointer is rewound to offset 0, the checkpoint is updated, and reads continue seamlessly.

### 2. Sliding Carryover Buffer & NDJSON Framing
Logs are delivered in arbitrary byte chunks that rarely align with line boundaries (`\n`).
- Centinel maintains an internal carryover buffer for each file. Unfinished line fragments at the end of a read are preserved using `memmove()` sliding shifts.
- When newline delimiters are encountered, records are serialized into standard NDJSON:
  ```json
  {"ts":1700770000,"file":"auth.log","msg":"Accepted publickey for root from 192.168.1.100 port 54321 ssh2"}
  ```
- All characters are safely escaped (`"`, `\`, `\n`, `\r`, `\t`, and ASCII control characters) in place.
- **Oversized Line Protection**: If an application outputs an unbroken line exceeding the buffer capacity (>8 KB without `\n`), Centinel forcefully seals the chunk to avoid buffer starvation or denial-of-service.

### 3. Atomic Binary Flat-File Checkpointing
To guarantee that zero logs are lost or re-streamed across daemon crashes or VPS reboots:
- Checkpoints are saved in a compact binary database (`/var/lib/centinel/centinel_checkpoint.db` or configured path).
- Each record is a fixed 32-byte struct:
  ```c
  typedef struct {
      dev_t  dev;        // Device ID (8 bytes)
      ino_t  inode;      // Inode number (8 bytes)
      off_t  offset;     // Last read byte offset (8 bytes)
      time_t last_seen;  // Unix timestamp (8 bytes)
  } CheckpointEntry;
  ```
- Updates use `pwrite()` and lookups use `pread()`. File cursors are never altered, eliminating multi-threaded or multi-descriptor seek race conditions.
- When Centinel launches:
  - If a file's `(dev, inode)` exists in the database, it resumes from the saved byte offset (catching up on logs written while offline).
  - If it is a newly monitored file not present in the database, Centinel seeks to `SEEK_END` (tailing mode) to prevent re-ingesting gigabytes of historical logs.

### 4. Memory Ring Buffer & Dual-Watermark Backpressure
When SIEM ingestion endpoints experience network partitions or latency spikes, unbound logging agents quickly exhaust VPS RAM.
- Centinel implements a ring buffer of 64 discrete chunks (`CHUNK_CAPACITY = 12 KB` each, total memory capped at ~768 KB).
- **High Watermark (48 chunks / 75%)**: When the queue fills to 48 chunks, Centinel sets `ctx->is_paused = true`. Inotify file draining stops immediately. Pending file data remains buffered in the Linux kernel VFS page cache.
- **Low Watermark (16 chunks / 25%)**: Once the network recovers and the consumer drains the queue down to 16 chunks, Centinel releases backpressure, unpauses ingestion, and executes a catch-up sweep (`follower_catchup_all`) across all active files.

### 5. CWEB-Compliant RFC 6455 WebSocket Engine
The WebSocket client is built entirely in raw C on non-blocking POSIX sockets:
- **Strict Handshake**: Complies with RFC 6455. Generates a cryptographically random 16-byte key encoded to an exact 24-character Base64 string (`strlen == 24`), required by CWEB.
- **Client Frame Masking**: All outgoing client payload frames are masked using a 4-byte pseudo-random XOR key, in strict accordance with RFC 6455 Section 5.3.
- **Anti-Slowloris Keep-Alive**: The CWEB SIEM server terminates idle WebSocket connections after 5 seconds of inactivity. Centinel tracks transmission timestamps and automatically dispatches a 6-byte WebSocket PING frame (`opcode 0x9`) if the connection remains idle for $\ge 2.5\text{ seconds}$. When CWEB replies with PONG (`opcode 0xA`), the connection watchdog is disarmed.
- **Exponential Reconnect Backoff**: If the socket drops or the SIEM server restarts, Centinel attempts reconnection at increasing intervals (1s, 2s, 4s, 8s, up to 30s max), preventing socket storming.

---

## CLI Reference & Options

```
Centinel SIEM Log Follower Daemon
Usage: centinel_log_fol [OPTIONS] <target_log_1> [target_log_2 ...]

Options:
  -s, --server <host>       SIEM server IP or hostname (default: 127.0.0.1)
  -p, --port <port>         SIEM server port (default: 8765)
  -u, --path <uri>          WebSocket URI endpoint (default: /ws/ingest)
  -c, --checkpoint <path>   Path to checkpoint DB (default: /var/lib/centinel/centinel_checkpoint.db)
  -h, --help                Display this manual

Examples:
  centinel_log_fol /var/log/auth.log /var/log/syslog
  centinel_log_fol -s 10.0.0.1 -p 8765 -u /logs -c /var/lib/centinel/checkpoints.db /var/log/*.log
```

---

## Production Deployment & Systemd Hardening

Centinel is designed to operate safely inside a hardened systemd sandbox on production Linux servers.

### 1. Configuration File (`/etc/default/centinel-log-follower`)

```ini
# Target SIEM WebSocket Endpoint
SERVER="127.0.0.1"
PORT="8765"
WS_PATH="/ws/ingest"

# Persistent binary checkpoint file
CHECKPOINT_DB="/var/lib/centinel/centinel_checkpoint.db"

# Space-separated list of log files to monitor (supports wildcards)
LOG_TARGETS="/var/log/auth.log /var/log/syslog"
```

### 2. Hardened Service Unit (`/etc/systemd/system/centinel-log-follower.service`)

```ini
[Unit]
Description=Centinel SIEM High-Performance Log Follower
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/default/centinel-log-follower
ExecStart=/usr/local/bin/centinel_log_fol -s ${SERVER} -p ${PORT} -u ${WS_PATH} -c ${CHECKPOINT_DB} ${LOG_TARGETS}

# Process Lifecycle & Self-Healing
Restart=always
RestartSec=2s
KillMode=mixed
TimeoutStopSec=5s

# Resource Hardening (VPS Protection)
MemoryMax=32M
MemoryHigh=24M
CPUWeight=50

# Security Sandboxing
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/var/log

# Automatic State Directory (/var/lib/centinel)
StateDirectory=centinel

[Install]
WantedBy=multi-user.target
```

### Security Directives Explained:
- `ProtectSystem=strict`: Mounts the entire filesystem read-only for the daemon process.
- `ReadOnlyPaths=/var/log`: Guarantees that the follower daemon can never corrupt, truncate, or delete host log files.
- `StateDirectory=centinel`: Systemd provisions `/var/lib/centinel` with read-write access for persistence across runs, disallowing writes anywhere else.
- `MemoryMax=32M`: Hardware cgroup limit. If memory usage exceeds 32 MB under any condition, systemd restarts the daemon.

---

## Build & Installation

### Requirements
- Linux OS (kernel 2.6.36+ for `inotify`, `epoll_create1`, and `timerfd`)
- GCC or Clang supporting C99 / GNU99
- Standard GNU Make

### Building from Source

```bash
cd sentinel_siem/log_follower
make clean && make
```

### System Installation

```bash
sudo make install
```
Installs:
- Binary: `/usr/local/bin/centinel_log_fol`
- Service: `/etc/systemd/system/centinel-log-follower.service`
- Config: `/etc/default/centinel-log-follower`

### Enable & Start Daemon

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now centinel-log-follower
sudo systemctl status centinel-log-follower
```

### Uninstallation

```bash
sudo systemctl stop centinel-log-follower
sudo make uninstall
sudo systemctl daemon-reload
```

---

## Verification & Automated Test Suite

A comprehensive test suite verifies every edge case under realistic conditions:

```bash
python3 scratch/prod_test.py
```

### Test Verification Matrix:
| Feature / Subsystem | Test Case | Result |
| :--- | :--- | :--- |
| **RFC 6455 Handshake** | Key verification (24 chars) & 101 Switching Protocols | **PASSED** |
| **Cold Boot Tailing** | Ignores pre-existing historical logs upon first discovery | **PASSED** |
| **Live Inotify Tailing** | Real-time NDJSON framing, escaping, and streaming | **PASSED** |
| **Multi-File Tailing** | Concurrent tracking across independent files & directory watches | **PASSED** |
| **Anti-Slowloris Ping** | Heartbeat PING emission after $\ge 2.5\text{s}$ idle | **PASSED** |
| **Copytruncate Handling** | In-place zeroing detection (`st_size < offset`) & offset rewind | **PASSED** |
| **Classic Rotation** | Inode changes via `mv` / `IN_CREATE` tracked without data loss | **PASSED** |
| **Ring Buffer Backpressure**| 8,000 burst logs, 75% watermark pause & 25% resume | **PASSED** |
| **Checkpoint Persistence** | Daemon restart reads binary offsets; catches up offline logs with 0 loss and 0 duplicates | **PASSED** |
| **Clean Shutdown** | Graceful SIGTERM flush, queue drain, and clean exit (code 0) | **PASSED** |

---

## License

Centinel SIEM Log Follower is proprietary systems software designed for high-reliability, resource-constrained monitoring infrastructures.
