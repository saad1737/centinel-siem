#include "ws_client.h"
#include "ws_frame.h"
#include <asm-generic/errno.h>
#include <sys/epoll.h>

void ws_client_init(WsClient* ws, const char* host, int port, const char* path) {
    if (!ws || !host || !path) return; // invalid arguments
    // set values
    ws->sock_fd = -1;
    ws->state = WS_STATE_DISCONNECTED;
    ws->port = port;
    snprintf(ws->host, sizeof(ws->host), "%s", host);
    snprintf(ws->path, sizeof(ws->path), "%s", path);
    ws->backoff_delay_sec = 1;
    ws->next_reconnect = 0;
    ws->last_activity = 0;
    ws->handshake_len = 0;
    ws->send_len = 0;
    ws->send_offset = 0;
    ws->awaiting_ack = false;
}

void ws_client_destroy(WsClient* ws, int epoll_fd) {
    if (!ws) return;
    ws_client_disconnect(ws, epoll_fd);
}

int ws_client_connect(WsClient* ws, int epoll_fd) {
    if (!ws) return -1; // invalid arguments

    // check if already connected or connecting
    if (ws->sock_fd >= 0) return 0;

    // create non blocking socket
    ws->sock_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (ws->sock_fd < 0) {
        perror("Non blocking socket initialization failed");
        return -1;
    }

    struct sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(ws->port); // port

    if (!strncmp(ws->host, "localhost", 9)) snprintf(ws->host, sizeof(ws->host), "%s", "127.0.0.1");
    if (inet_pton(AF_INET, ws->host, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "[WS] Invalid address: %s\n", ws->host);
        close(ws->sock_fd);
        ws->sock_fd = -1;
        return -1;
    }

    // connect
    int res = connect(ws->sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (res == 0 || (res == -1 && errno == EINPROGRESS)) {
        // normal in linux. the kernel is negotiatin the 3-way handshake
        // add the socket to epoll
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLOUT | EPOLLIN | EPOLLERR | EPOLLHUP;
        ev.data.fd = ws->sock_fd;
        res = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ws->sock_fd, &ev);
        if (res < 0) {
            perror("failed to add socket in epoll");
            ws_client_disconnect(ws, epoll_fd);
            return -1;
        }
        ws->state = WS_STATE_CONNECTING;
    }
    else if (res == -1) {ws_client_disconnect(ws, epoll_fd); return -1;}

    // connection successful
    return 0;
}

void ws_client_disconnect(WsClient* ws, int epoll_fd) {
    if (!ws) return; // invalid arguments

    if (ws->sock_fd >= 0) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ws->sock_fd, NULL); // remove from epoll
        close(ws->sock_fd); // close the socket
        ws->sock_fd = -1; // reset
    }

    ws->state = WS_STATE_DISCONNECTED;

    // schedule exponential backoff
    ws->next_reconnect = time(NULL) + ws->backoff_delay_sec;
    fprintf(stderr, "[WS] Disconnected. Reconnecting in %d seconds...\n", ws->backoff_delay_sec);
    ws->backoff_delay_sec = (ws->backoff_delay_sec * 2 > 30) ? 30 : ws->backoff_delay_sec * 2;

    // reset transmission
    ws->handshake_len = 0;
    ws->send_len = 0;
    ws->send_offset = 0;
    ws->awaiting_ack = false;
}

void ws_client_handle_event(WsClient* ws, uint32_t events, int epoll_fd) {
    if (!ws) return; // inalid arguments

    if (events & (EPOLLERR | EPOLLHUP)) { // epoll error, disconnect immediately
        ws_client_disconnect(ws, epoll_fd);
        return;
    }

    switch (ws->state) {
        case WS_STATE_CONNECTING: {
            int err = 0;
            socklen_t optlen = sizeof(err);
            getsockopt(ws->sock_fd, SOL_SOCKET, SO_ERROR, &err, &optlen);

            if (err) {
                // tcp connection failed
                ws_client_disconnect(ws, epoll_fd);
                return;
            }

            // generate handshake key
            ws_generate_handshake_key(ws->expected_key, sizeof(ws->expected_key));

            // build the request
            ws_build_handshake_request(ws->host, ws->port, ws->path, ws->expected_key, ws->handshake_buf, sizeof(ws->handshake_buf));

            // send request
            write(ws->sock_fd, ws->handshake_buf, strlen(ws->handshake_buf));

            // switch epoll mask to only watch POLLIN, POLLERR and POLLHUP
            struct epoll_event ev;
            memset(&ev, 0, sizeof(ev));
            ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
            ev.data.fd = ws->sock_fd;
            int res = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ws->sock_fd, &ev);
            if (res < 0) {
                perror("failed to add socket in epoll");
                ws_client_disconnect(ws, epoll_fd);
                return;
            }

            // transition state
            ws->state = WS_STATE_HANDSHAKING;

            // update last activity
            ws->last_activity = time(NULL);
            break;
        }

        case WS_STATE_HANDSHAKING: {
            if (!(events & EPOLLIN)) return;
            
            // read incoming bytes
            ssize_t bytes_read = read(ws->sock_fd, ws->handshake_buf + ws->handshake_len, sizeof(ws->handshake_buf) - ws->handshake_len - 1);
            if (bytes_read <= 0) { // server closed socket
                if (errno == EAGAIN || errno == EWOULDBLOCK) return; // do not disconnect
                ws_client_disconnect(ws, epoll_fd);
                return;
            }

            ws->handshake_len += (size_t)bytes_read;
            ws->handshake_buf[ws->handshake_len] = '\0';

            char* ptr = strstr(ws->handshake_buf, "\r\n\r\n");
            if (!ptr) { // full response headers did not arrive
                // go to sleep. wait for more
                return;
            }

            // verify response
            bool verified = ws_verify_handshake_response(ws->handshake_buf, ws->handshake_len);
            if (!verified) {
                fprintf(stderr, "[WS] Handshake rejected by server\n");
                ws_client_disconnect(ws, epoll_fd);
                return;
            }

            // Handshake verified!
            ws->state = WS_STATE_CONNECTED;
            ws->backoff_delay_sec = 1;
            ws->handshake_len = 0;
            ws->last_activity = time(NULL);
            printf("[WS] Connected to CWEB SIEM at ws://%s:%d%s\n", ws->host, ws->port, ws->path);
            fflush(stdout);

            break;
        }

        case WS_STATE_CONNECTED: {
            if (events & EPOLLOUT) {
                if (ws_client_flush_pending(ws, epoll_fd) < 0) return;
            }
            if (!(events & EPOLLIN)) return;

            char buf[256];
            ssize_t n = read(ws->sock_fd, buf, sizeof(buf));
            if (n <= 0) {
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
                ws_client_disconnect(ws, epoll_fd);
                return;
            }

            // Walk all frames received in buf (e.g., coalesced ACK + PONG)
            size_t pos = 0;
            while (pos + 2 <= (size_t)n) {
                uint8_t opcode = (uint8_t)buf[pos] & 0x0F;
                size_t plen = (uint8_t)buf[pos + 1] & 0x7F;
                size_t hdr = 2;
                if (plen == 126) {
                    if (pos + 4 > (size_t)n) break;
                    plen = ((uint8_t)buf[pos + 2] << 8) | (uint8_t)buf[pos + 3];
                    hdr = 4;
                }
                if (opcode == WS_OP_CLOSE) {
                    ws_client_disconnect(ws, epoll_fd);
                    return;
                } 
                else if (opcode == WS_OP_PONG) {
                    ws->last_activity = time(NULL);
                } 
                else if (opcode == WS_OP_TEXT) {
                    ws->last_activity = time(NULL);
                    ws->awaiting_ack = false; // Server ACK received: safe to send next chunk
                }
                if (pos + hdr + plen > (size_t)n) break;
                pos += hdr + plen;
            }
            break;
        }

        case WS_STATE_DISCONNECTED: break;
    }
}

static int ws_set_epoll_events(int sock_fd, int epoll_fd, uint32_t events) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.fd = sock_fd;
    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, sock_fd, &ev);
}

int ws_client_flush_pending(WsClient* ws, int epoll_fd) {
    if (!ws || ws->state != WS_STATE_CONNECTED) return -1;
    if (ws->send_len == 0) return 1;

    while (ws->send_offset < ws->send_len) {
        ssize_t n = write(ws->sock_fd, ws->send_buf + ws->send_offset, ws->send_len - ws->send_offset);
        if (n > 0) {
            ws->send_offset += (size_t)n;
            ws->last_activity = time(NULL);
        } 
        else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // Socket buffer full: ask epoll for EPOLLOUT and resume later without losing bytes
            ws_set_epoll_events(ws->sock_fd, epoll_fd, EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP);
            return 0;
        } 
        else {
            ws_client_disconnect(ws, epoll_fd);
            return -1;
        }
    }

    // Full frame transmitted! Stop watching EPOLLOUT, arm Stop-and-Wait ACK
    ws_set_epoll_events(ws->sock_fd, epoll_fd, EPOLLIN | EPOLLERR | EPOLLHUP);
    ws->send_len = 0;
    ws->send_offset = 0;
    ws->awaiting_ack = true;
    return 1;
}

ssize_t ws_client_send_chunk(WsClient* ws, const char* data, size_t len, int epoll_fd) {
    if (!ws || !data || len == 0) return -1;
    if (ws->state != WS_STATE_CONNECTED || ws->send_len > 0 || ws->awaiting_ack) return 0;

    size_t frame_len = ws_encode_frame(WS_OP_TEXT, data, len, ws->send_buf, sizeof(ws->send_buf));
    if (frame_len == 0) return -1; // Frame exceeded send_buf

    ws->send_len = frame_len;
    ws->send_offset = 0;
    int fl = ws_client_flush_pending(ws, epoll_fd);
    return (fl < 0) ? -1 : 1;
}

void ws_client_tick(WsClient* ws, int epoll_fd) {
    if (!ws) return;
    time_t now = time(NULL);

    // Auto-Reconnect with Backoff
    if (ws->state == WS_STATE_DISCONNECTED) {
        if (now >= ws->next_reconnect) {
            ws_client_connect(ws, epoll_fd);
        }
        return;
    }

    // CWEB 2.5s Heartbeat Ping
    // CWEB Keep-Alive & Stalled-ACK Watchdog
    if (ws->state == WS_STATE_CONNECTED) {
        if (ws->send_len > 0 || ws->awaiting_ack) {
            if (now - ws->last_activity >= 10) {
                ws_client_disconnect(ws, epoll_fd);
            }
            return;
        }
        if (now - ws->last_activity >= 2) {
            uint8_t ping_buf[16];
            size_t ping_len = ws_encode_frame(WS_OP_PING, NULL, 0, ping_buf, sizeof(ping_buf));
            ssize_t w = write(ws->sock_fd, ping_buf, ping_len);
            if (w > 0) {
                ws->last_activity = now;
            } else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                ws_client_disconnect(ws, epoll_fd);
            }
        }
    }
}