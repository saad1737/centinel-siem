#include "ws_frame.h"

void ws_generate_handshake_key(char* out_key, size_t out_len) {
    if (!out_key || out_len < 25) return; // inalid arguments

    // generate the random 16 byte nonce
    uint8_t raw[16];
    if (getrandom(raw, sizeof(raw), 0) < 0) {
        // Fallback if getrandom syscall fails
        for (int i = 0; i < 16; i++) 
            raw[i] = (uint8_t)(rand() & 0xFF);
    }

    // lookup string mapping all 64 printable ASCII characters. '=' strictly reserved for padding
    const char* ascii = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // every 3 input bytes form a 24 bit integer, yields 4 (6 bit) base64 characters
    for (size_t i = 0, j = 0; i < 15; i += 3) {
        // create the 24 bit integer using 3 bytes
        uint32_t val = (raw[i] << 16) | (raw[i + 1] << 8) | (raw[i + 2]);
        // slicing 24 bits into 4 6 bit chunks and then mapping it with ascii lookup string
        out_key[j++] = ascii[(val >> 18) & 0x3F];
        out_key[j++] = ascii[(val >> 12) & 0x3F];
        out_key[j++] = ascii[(val >> 6) & 0x3F];
        out_key[j++] = ascii[val & 0x3F];
    }

    // 15 raw bytes handled -> 20 base 64 bytes. Now to handle the last byte
    // 16th byte (raw[15]) -> 2 Base64 characters + 2 padding '=' characters
    uint32_t val = (uint32_t)raw[15] << 16;
    out_key[20] = ascii[(val >> 18) & 0x3F];
    out_key[21] = ascii[(val >> 12) & 0x3F];
    out_key[22] = '=';
    out_key[23] = '=';
    out_key[24] = '\0'; // Exactly 24 characters + null terminator
}

void ws_build_handshake_request(const char* host, int port, const char* path, const char* key, char* out_buf, size_t max_len) {
    snprintf(out_buf, max_len,
            "GET %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n",
            (path && path[0]) ? path : "/",
            host, port, key);
}

bool ws_verify_handshake_response(const char* resp, size_t len) {
    if (!resp || len < 12) return false; // invalid arguments. length of string "HTTP/1.1 101" is 12

    // check the starting status line starts with "HTTP/1.1 101"
    if (strncmp(resp, "HTTP/1.1 101", 12) != 0) return false;

    // check headers contain "Upgrade: websocket" (case insensitive)
    if (!strcasestr(resp, "Upgrade: websocket")) return false;

    // verify the end of the HTTP headers block
    if (!strstr(resp, "\r\n\r\n")) return false;

    return true; // all checks passed
}

size_t ws_encode_frame(WsOpcode op, const char* payload, size_t payload_len, uint8_t* out_buf, size_t max_out_len) {
    // if payload length <= 125, 2 byte header + 4 byte mask = 6 byte total header
    // if payload length >= 126 and <= 65535, 4 byte header + 4 byte mask = 8  byte total header
    // payload is nullable to pass PING, PONG and DISCONNECT frames
    if (max_out_len < payload_len + ((payload_len >= 126 && payload_len <= 65535) ? 8 : 6))
        return 0; // error

    // assemble the header
    size_t pos = 0;
    out_buf[pos++] = (uint8_t)(0x80 | (op & 0x0F)); // FIN + opcode
    if (payload_len <= 125) {
        out_buf[pos++] = (uint8_t)(0x80 | payload_len); // Mask bit set + length
    } 
    else {
        out_buf[pos++] = (uint8_t)(0x80 | 126); // Mask bit set + 126
        out_buf[pos++] = (uint8_t)((payload_len >> 8) & 0xFF); // High byte
        out_buf[pos++] = (uint8_t)(payload_len & 0xFF); // Low byte
    }

    // generate and append 4 byte mask
    uint8_t mask[4];
    if (getrandom(mask, 4, 0) < 0) {
        // fallback
        for (int i = 0; i < 4; i++) mask[i] = (uint8_t)(rand() & 0xFF);
    }
    memcpy(out_buf + pos, mask, 4);
    pos += 4;

    // apply mask XOR transformation to payload
    if (payload && payload_len > 0) {
        for (size_t i = 0; i < payload_len; i++) {
            out_buf[pos + i] = ((const uint8_t*)payload)[i] ^ mask[i % 4];
        }
    }

    // return total frame size
    return pos + payload_len;
}