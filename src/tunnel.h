#pragma once
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <winsock2.h>
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <atomic>
#include "config.h"

enum TunnelState { STATE_DISCONNECTED = 0, STATE_CONNECTING = 1, STATE_CONNECTED = 2, STATE_FAILED = 3 };
enum PingStatus  { PING_IDLE = -3, PING_TIMEOUT = -2, PING_TESTING = -1 };

extern std::atomic<TunnelState> g_State;
extern std::atomic<uint64_t>    g_TotalRx;
extern std::atomic<uint64_t>    g_TotalTx;
extern std::atomic<int>         g_LastPingMs;
extern ULONGLONG                g_ConnectTick;
extern std::string              g_StatusMsg;

void run_silent_cmd(const std::string& cmd);
void start_tunnel_async();
void stop_tunnel();
void trigger_async_ping();

inline int build_vless_header(uint8_t* out, uint8_t cmd, uint32_t dst_ip_net, uint16_t dst_port_net) {
    out[0] = 0x00;
    std::memcpy(out + 1, g_cfg.vless_uuid, 16);
    int off = 17;
    if (g_cfg.vless_flow == "xtls-rprx-vision") {
        out[off++] = 0x12; // Addons length = 18 bytes
        out[off++] = 0x0A; // Protobuf Tag: Field 1 (Flow), Wire type 2 (string)
        out[off++] = 0x10; // Length: 16 bytes
        std::memcpy(out + off, "xtls-rprx-vision", 16);
        off += 16;
    } else {
        out[off++] = 0x00; // No addons
    }
    out[off++] = cmd;
    std::memcpy(out + off, &dst_port_net, 2); off += 2;
    out[off++] = 0x01; // IPv4
    std::memcpy(out + off, &dst_ip_net, 4); off += 4;
    return off;
}

inline int build_vless_header_domain(uint8_t* out, uint8_t cmd, const std::string& domain, uint16_t dst_port_net) {
    out[0] = 0x00;
    std::memcpy(out + 1, g_cfg.vless_uuid, 16);
    int off = 17;
    if (g_cfg.vless_flow == "xtls-rprx-vision") {
        out[off++] = 0x12; // Addons length = 18 bytes
        out[off++] = 0x0A; // Protobuf Tag: Field 1 (Flow), Wire type 2 (string)
        out[off++] = 0x10; // Length: 16 bytes
        std::memcpy(out + off, "xtls-rprx-vision", 16);
        off += 16;
    } else {
        out[off++] = 0x00; // No addons
    }
    out[off++] = cmd;
    std::memcpy(out + off, &dst_port_net, 2); off += 2;
    out[off++] = 0x02; // Address type: Domain name
    uint8_t dlen = static_cast<uint8_t>(domain.size() > 255 ? 255 : domain.size());
    out[off++] = dlen;
    std::memcpy(out + off, domain.data(), dlen); off += dlen;
    return off;
}

inline int build_trojan_header(uint8_t* out, uint8_t cmd, uint32_t dst_ip_net, uint16_t dst_port_net, const std::string& hex_hash) {
    if (hex_hash.size() < 56) return 0;
    std::memcpy(out, hex_hash.data(), 56);
    int off = 56;
    out[off++] = 0x0D; // \r
    out[off++] = 0x0A; // \n
    out[off++] = cmd;  // 0x01 (TCP Connect) or 0x03 (UDP Associate)
    out[off++] = 0x01; // ATYP: IPv4
    std::memcpy(out + off, &dst_ip_net, 4); off += 4;
    std::memcpy(out + off, &dst_port_net, 2); off += 2;
    out[off++] = 0x0D; // \r
    out[off++] = 0x0A; // \n
    return off;
}

inline int build_trojan_header_domain(uint8_t* out, uint8_t cmd, const std::string& domain, uint16_t dst_port_net, const std::string& hex_hash) {
    if (hex_hash.size() < 56) return 0;
    std::memcpy(out, hex_hash.data(), 56);
    int off = 56;
    out[off++] = 0x0D; // \r
    out[off++] = 0x0A; // \n
    out[off++] = cmd;  // 0x01 (TCP Connect) or 0x03 (UDP Associate)
    out[off++] = 0x03; // ATYP: Domain
    uint8_t dlen = static_cast<uint8_t>(domain.size() > 255 ? 255 : domain.size());
    out[off++] = dlen;
    std::memcpy(out + off, domain.data(), dlen); off += dlen;
    std::memcpy(out + off, &dst_port_net, 2); off += 2;
    out[off++] = 0x0D; // \r
    out[off++] = 0x0A; // \n
    return off;
}

inline int build_trojan_udp_packet(uint8_t* out, uint32_t dst_ip_net, uint16_t dst_port_net, const uint8_t* payload, uint16_t payload_len) {
    int off = 0;
    out[off++] = 0x01; // ATYP: IPv4
    std::memcpy(out + off, &dst_ip_net, 4); off += 4;
    std::memcpy(out + off, &dst_port_net, 2); off += 2;
    uint16_t plen_net = htons(payload_len);
    std::memcpy(out + off, &plen_net, 2); off += 2;
    out[off++] = 0x0D; // \r
    out[off++] = 0x0A; // \n
    std::memcpy(out + off, payload, payload_len); off += payload_len;
    return off;
}