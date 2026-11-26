#ifndef WS_CLIENT_H
#define WS_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include "ws_frame.h"

typedef enum {
    WS_STATE_DISCONNECTED = 0,
    WS_STATE_CONNECTING,     // Non-blocking TCP 3-way handshake in flight
    WS_STATE_HANDSHAKING,    // HTTP Upgrade sent, waiting for 101 response
    WS_STATE_CONNECTED       // Ready to stream log chunks
} WsClientState;

typedef struct {
    int sock_fd;             // Socket file descriptor (-1 when disconnected)
    WsClientState state;     // Current connection state
    char host[128];          // Remote server host/IP
    int port;                // Remote port (e.g. 8080)
    char path[128];          // WebSocket URI path (e.g. "/ws/siem" or "/")
    char expected_key[32];   // 24-character Base64 key sent in handshake

    // Heartbeat tracking (for CWEB 5s DDoS timeout)
    time_t last_activity;    // Timestamp of last frame sent or received

    // Exponential backoff reconnect tracking
    time_t next_reconnect;   // Earliest timestamp to attempt next connect
    int backoff_delay_sec;   // Current backoff interval (1, 2, 4, 8... max 30)

    // Handshake reception buffer
    char handshake_buf[1024];
    size_t handshake_len;

    // In-flight frame buffer & Stop-and-Wait ACK pacing (protects CWEB's 16KB recv buffer)
    uint8_t send_buf[16384]; // 16 KB same as CWEB's buffer size
    size_t send_len;
    size_t send_offset;
    bool awaiting_ack;
} WsClient;

// Lifecycle
void ws_client_init(WsClient* ws, const char* host, int port, const char* path);
void ws_client_destroy(WsClient* ws, int epoll_fd);

// Reactor integration
int ws_client_connect(WsClient* ws, int epoll_fd);
void ws_client_disconnect(WsClient* ws, int epoll_fd);
void ws_client_handle_event(WsClient* ws, uint32_t events, int epoll_fd);
void ws_client_tick(WsClient* ws, int epoll_fd); // Called every 500ms by reactor timer

// Transmission
ssize_t ws_client_send_chunk(WsClient* ws, const char* data, size_t len, int epoll_fd);
int ws_client_flush_pending(WsClient* ws, int epoll_fd); // Returns 1 if finished, 0 if EAGAIN, -1 on error

#endif