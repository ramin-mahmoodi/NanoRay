#pragma once
#include <string>
#include <cstdint>

enum ChainType { CHAIN_NONE = 0, CHAIN_SOCKS5 = 1, CHAIN_HTTP = 2 };
enum OutboundProto { PROTO_VLESS = 0, PROTO_TROJAN = 1 };

struct AppConfig {
    std::string   raw_vless_uri   = "";
    std::string   vless_ip        = "";
    uint16_t      vless_port      = 0;
    std::string   vless_remark    = "Not Configured";
    uint8_t       vless_uuid[16]{};
    bool          vless_valid     = false;
    OutboundProto outbound_proto  = PROTO_VLESS;
    std::string   trojan_password = "";
    std::string   trojan_hash_hex = "";

    // Advanced VLESS attributes
    std::string vless_security   = "none";
    std::string vless_encryption = "none";
    bool        vless_allow_insecure = false;
    std::string vless_resolved_ip = "";
    std::string vless_sni        = "";
    std::string vless_alpn       = "";
    std::string vless_type     = "tcp";
    std::string vless_path     = "/";
    std::string vless_host     = "";
    std::string vless_fp       = "chrome";
    std::string vless_pbk      = "";
    std::string vless_sid      = "";
    std::string vless_spx      = "";
    std::string vless_flow     = "";
    std::string vless_packet_encoding = "xudp";
    std::string vless_mode     = "auto";
    std::string vless_extra    = "";
    int         vless_pad_min  = 100;
    int         vless_pad_max  = 1000;

    ChainType   chain_type     = CHAIN_NONE;
    std::string chain_addr_str = "";
    std::string chain_auth_str = "";
    std::string chain_ip       = "";
    uint16_t    chain_port     = 0;
    std::string chain_user     = "";
    std::string chain_pass     = "";

    const char* tun_ip_str     = "10.66.66.1";
    const char* tun_peer_str   = "10.66.66.2";
    uint16_t    relay_port     = 10888;
    bool        is_dark_mode   = true;
};

extern AppConfig g_cfg;

bool parse_vless_uri(const std::string& uri_in);
void sync_chain_fields();
void load_config_ini();
void save_config_ini();