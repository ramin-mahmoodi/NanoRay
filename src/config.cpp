#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include "config.h"
#include "tunnel.h"
#include "crypto_reality.h"
#include <winsock2.h>
#include <windows.h>
#include <cstdlib>
#include <cstring>

AppConfig g_cfg;
std::recursive_mutex g_cfg_mtx;

AppConfig get_config_snapshot() {
    std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
    return g_cfg;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool parse_uuid_bytes(const std::string& s, uint8_t out[16]) {
    std::string hex;
    for (char c : s) if (c != '-') hex.push_back(c);
    if (hex.size() != 32) return false;
    for (int i = 0; i < 16; ++i) {
        int hi = hex_val(hex[i * 2]), lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

static std::string url_decode(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size()) {
            int hi = hex_val(in[i + 1]), lo = hex_val(in[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        } else if (in[i] == '+') {
            out.push_back(' ');
            continue;
        }
        out.push_back(in[i]);
    }
    return out;
}

bool parse_vless_uri(const std::string& uri_in) {
    std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
    std::string s = uri_in;
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ')) s.pop_back();
    while (!s.empty() && (s.front() == ' ')) s.erase(s.begin());

    bool is_trojan = (s.rfind("trojan://", 0) == 0);
    bool is_vless  = (s.rfind("vless://", 0) == 0);
    if (!is_trojan && !is_vless) { g_cfg.vless_valid = false; return false; }

    std::string body = is_trojan ? s.substr(9) : s.substr(8);
    std::string remark = is_trojan ? "Trojan Node" : "VLESS Node";
    size_t hash_pos = body.find('#');
    if (hash_pos != std::string::npos) {
        remark = url_decode(body.substr(hash_pos + 1));
        body = body.substr(0, hash_pos);
    }

    std::string query_str;
    size_t q_pos = body.find('?');
    if (q_pos != std::string::npos) {
        query_str = body.substr(q_pos + 1);
        body = body.substr(0, q_pos);
    }

    size_t at_pos = body.find('@');
    if (at_pos == std::string::npos) { g_cfg.vless_valid = false; return false; }

    std::string cred_str = body.substr(0, at_pos), host_port = body.substr(at_pos + 1);
    size_t colon_pos = host_port.rfind(':');
    if (colon_pos == std::string::npos) { g_cfg.vless_valid = false; return false; }

    std::string host = host_port.substr(0, colon_pos);
    int port = std::atoi(host_port.substr(colon_pos + 1).c_str());
    if (host.empty() || port <= 0 || port > 65535) { g_cfg.vless_valid = false; return false; }

    uint8_t uuid_tmp[16]{};
    if (is_vless) {
        if (!parse_uuid_bytes(cred_str, uuid_tmp)) { g_cfg.vless_valid = false; return false; }
        g_cfg.outbound_proto = PROTO_VLESS;
        g_cfg.trojan_password.clear();
        g_cfg.trojan_hash_hex.clear();
    } else { // Trojan
        if (cred_str.empty()) { g_cfg.vless_valid = false; return false; }
        g_cfg.outbound_proto = PROTO_TROJAN;
        g_cfg.trojan_password = cred_str;
        g_cfg.trojan_hash_hex = reality::sha224_hex(cred_str);
    }

    // Reset extended fields to defaults
    g_cfg.vless_security = is_trojan ? "tls" : "none"; // Trojan defaults to TLS
    g_cfg.vless_sni      = "";
    g_cfg.vless_alpn     = "";
    g_cfg.vless_type     = "tcp";
    g_cfg.vless_path     = "/";
    g_cfg.vless_host     = "";
    g_cfg.vless_fp       = "chrome";
    g_cfg.vless_pbk      = "";
    g_cfg.vless_sid      = "";
    g_cfg.vless_spx      = "";
    g_cfg.vless_flow     = "";
    g_cfg.vless_packet_encoding = "xudp";
    g_cfg.vless_mode     = "auto";
    g_cfg.vless_extra    = "";
    g_cfg.vless_pad_min  = 100;
    g_cfg.vless_pad_max  = 1000;

    // Parse query params (k1=v1&k2=v2)
    if (!query_str.empty()) {
        size_t start = 0;
        while (start < query_str.size()) {
            size_t amp = query_str.find('&', start);
            std::string pair = (amp != std::string::npos) ? query_str.substr(start, amp - start) : query_str.substr(start);
            size_t eq = pair.find('=');
            if (eq != std::string::npos) {
                std::string k = pair.substr(0, eq);
                std::string v = url_decode(pair.substr(eq + 1));
                if (k == "security") g_cfg.vless_security = v;
                else if (k == "encryption") g_cfg.vless_encryption = v;
                else if (k == "allowInsecure") g_cfg.vless_allow_insecure = (v == "1" || v == "true");
                else if (k == "packetEncoding") g_cfg.vless_packet_encoding = v;
                else if (k == "sni") g_cfg.vless_sni = v;
                else if (k == "alpn") g_cfg.vless_alpn = v;
                else if (k == "type") g_cfg.vless_type = v;
                else if (k == "path") g_cfg.vless_path = v;
                else if (k == "host") g_cfg.vless_host = v;
                else if (k == "fp") g_cfg.vless_fp = v;
                else if (k == "pbk") g_cfg.vless_pbk = v;
                else if (k == "sid") g_cfg.vless_sid = v;
                else if (k == "spx") g_cfg.vless_spx = v;
                else if (k == "flow") g_cfg.vless_flow = v;
                else if (k == "mode") g_cfg.vless_mode = v;
                else if (k == "extra") {
                    g_cfg.vless_extra = v;
                    size_t pad_pos = v.find("xPaddingBytes");
                    if (pad_pos != std::string::npos) {
                        size_t colon = v.find(':', pad_pos);
                        if (colon != std::string::npos) {
                            size_t q1 = v.find('"', colon);
                            size_t q2 = (q1 != std::string::npos) ? v.find('"', q1 + 1) : std::string::npos;
                            if (q1 != std::string::npos && q2 != std::string::npos) {
                                std::string range = v.substr(q1 + 1, q2 - q1 - 1);
                                size_t dash = range.find('-');
                                if (dash != std::string::npos) {
                                    g_cfg.vless_pad_min = std::atoi(range.substr(0, dash).c_str());
                                    g_cfg.vless_pad_max = std::atoi(range.substr(dash + 1).c_str());
                                }
                            }
                        }
                    }
                }
                else if (k == "xPaddingBytes") {
                    size_t dash = v.find('-');
                    if (dash != std::string::npos) {
                        g_cfg.vless_pad_min = std::atoi(v.substr(0, dash).c_str());
                        g_cfg.vless_pad_max = std::atoi(v.substr(dash + 1).c_str());
                    }
                }
            }
            if (amp == std::string::npos) break;
            start = amp + 1;
        }
    }

    if (g_cfg.vless_type == "splithttp") g_cfg.vless_type = "xhttp";
    if (g_cfg.vless_type == "grpc" || g_cfg.vless_type == "quic") {
        g_cfg.vless_valid = false;
        set_status_msg("Error: Unsupported transport '" + g_cfg.vless_type + "' (only tcp, ws, xhttp, httpupgrade supported)");
        return false;
    }
    if (g_cfg.vless_sni.empty()) g_cfg.vless_sni = host;
    if (g_cfg.vless_host.empty()) g_cfg.vless_host = g_cfg.vless_sni;
    if (g_cfg.vless_path.empty()) g_cfg.vless_path = "/";
    if (g_cfg.vless_path.front() != '/') g_cfg.vless_path = "/" + g_cfg.vless_path;

    if (g_cfg.vless_type == "xhttp" && !g_cfg.vless_mode.empty() && g_cfg.vless_mode != "auto" && g_cfg.vless_mode != "stream-up") {
        g_cfg.vless_valid = false;
        set_status_msg("Error: Unsupported XHTTP mode '" + g_cfg.vless_mode + "' (only stream-up supported)");
        return false;
    }

    if (is_vless) std::memcpy(g_cfg.vless_uuid, uuid_tmp, 16);
    g_cfg.vless_ip      = host;
    g_cfg.vless_port    = static_cast<uint16_t>(port);
    g_cfg.vless_remark  = remark.empty() ? (is_trojan ? "Trojan Node" : "VLESS Node") : remark;
    g_cfg.raw_vless_uri = s;
    g_cfg.vless_valid   = true;
    return true;
}

void sync_chain_fields() {
    std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
    std::string a = g_cfg.chain_addr_str;
    while (!a.empty() && a.back() == ' ') a.pop_back();
    size_t cpos = a.rfind(':');
    if (cpos != std::string::npos) {
        g_cfg.chain_ip = a.substr(0, cpos);
        int p = std::atoi(a.substr(cpos + 1).c_str());
        g_cfg.chain_port = (p > 0 && p <= 65535) ? static_cast<uint16_t>(p) : 0;
    } else {
        g_cfg.chain_ip = a;
        g_cfg.chain_port = 0;
    }
    std::string u = g_cfg.chain_auth_str;
    size_t upos = u.find(':');
    if (upos != std::string::npos) {
        g_cfg.chain_user = u.substr(0, upos);
        g_cfg.chain_pass = u.substr(upos + 1);
    } else {
        g_cfg.chain_user = u;
        g_cfg.chain_pass = "";
    }
}

static std::string get_ini_path() {
    char path[MAX_PATH]{};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    std::string s(path);
    size_t pos = s.find_last_of("\\/");
    std::string dir = (pos != std::string::npos ? s.substr(0, pos + 1) : "");
    std::string target = dir + "nanoray.ini";
    DWORD attr = GetFileAttributesA(target.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        std::string legacy = dir + "vless_tun.ini";
        if (GetFileAttributesA(legacy.c_str()) != INVALID_FILE_ATTRIBUTES) {
            CopyFileA(legacy.c_str(), target.c_str(), FALSE);
        }
    }
    return target;
}

void save_config_ini() {
    std::string uri, addr, auth;
    int ctype;
    bool dark;
    {
        std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
        uri = g_cfg.raw_vless_uri;
        ctype = static_cast<int>(g_cfg.chain_type);
        addr = g_cfg.chain_addr_str;
        auth = g_cfg.chain_auth_str;
        dark = g_cfg.is_dark_mode;
    }
    std::string ini = get_ini_path();
    WritePrivateProfileStringA("VLESS", "URI", uri.c_str(), ini.c_str());
    WritePrivateProfileStringA("CHAIN", "Type", std::to_string(ctype).c_str(), ini.c_str());
    WritePrivateProfileStringA("CHAIN", "Addr", addr.c_str(), ini.c_str());
    WritePrivateProfileStringA("CHAIN", "Auth", auth.c_str(), ini.c_str());
    WritePrivateProfileStringA("UI", "DarkMode", dark ? "1" : "0", ini.c_str());
}

void load_config_ini() {
    std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
    std::string ini = get_ini_path();
    char buf[8192]{};
    GetPrivateProfileStringA("VLESS", "URI", "", buf, sizeof(buf), ini.c_str());
    if (buf[0] != '\0') { g_cfg.raw_vless_uri = buf; parse_vless_uri(buf); }
    int ctype = GetPrivateProfileIntA("CHAIN", "Type", 0, ini.c_str());
    if (ctype >= 0 && ctype <= 2) g_cfg.chain_type = static_cast<ChainType>(ctype);
    GetPrivateProfileStringA("CHAIN", "Addr", "", buf, sizeof(buf), ini.c_str());
    g_cfg.chain_addr_str = buf;
    GetPrivateProfileStringA("CHAIN", "Auth", "", buf, sizeof(buf), ini.c_str());
    g_cfg.chain_auth_str = buf;
    g_cfg.is_dark_mode = (GetPrivateProfileIntA("UI", "DarkMode", 1, ini.c_str()) != 0);
    sync_chain_fields();
}