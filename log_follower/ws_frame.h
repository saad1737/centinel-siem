#ifndef WS_FRAME_H
#define WS_FRAME_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/random.h>

typedef enum {
    WS_OP_TEXT   = 0x1,
    WS_OP_BINARY = 0x2,
    WS_OP_CLOSE  = 0x8,
    WS_OP_PING   = 0x9,
    WS_OP_PONG   = 0xA
} WsOpcode; 

void ws_generate_handshake_key(char* out_key, size_t out_len); // generates 16 random bytes and encodes into a 24-character base64 string ending in ==
void ws_build_handshake_request(const char* host, int port, const char* path, const char* key, char* out_buf, size_t max_len); // constructs the HTTP 1.1 upgrade request compliant with CWEB
bool ws_verify_handshake_response(const char* resp, size_t len); // checks if the response starts with HTTP/1.1 101 and headers contain Upgrade: websocket
size_t ws_encode_frame(WsOpcode op, const char* payload, size_t payload_len, uint8_t* out_buf, size_t max_out_len); // Serializes an RFC 6455 masked frame into out_buf and returns the total frame size in bytes.

#endif