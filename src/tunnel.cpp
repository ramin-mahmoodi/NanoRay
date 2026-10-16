#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include "tunnel.h"
#include "config.h"
#include "ui_flyout.h"
#include "transport.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <winhttp.h>
#include <psapi.h>
#include <process.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <memory>
#include <unordered_map>
#include <vector>
#include <string>

#ifndef IP_UNICAST_IF
#define IP_UNICAST_IF 31
#endif

typedef void* WINTUN_ADAPTER_HANDLE;
typedef void* WINTUN_SESSION_HANDLE;
typedef WINTUN_ADAPTER_HANDLE(WINAPI* fn_WintunCreateAdapter)(LPCWSTR, LPCWSTR, const GUID*);
typedef WINTUN_ADAPTER_HANDLE(WINAPI* fn_WintunOpenAdapter)(LPCWSTR);
typedef void (WINAPI* fn_WintunCloseAdapter)(WINTUN_ADAPTER_HANDLE);
typedef void (WINAPI* fn_WintunGetAdapterLUID)(WINTUN_ADAPTER_HANDLE, NET_LUID*);
typedef WINTUN_SESSION_HANDLE(WINAPI* fn_WintunStartSession)(WINTUN_ADAPTER_HANDLE, DWORD);
typedef void (WINAPI* fn_WintunEndSession)(WINTUN_SESSION_HANDLE);
typedef HANDLE(WINAPI* fn_WintunGetReadWaitEvent)(WINTUN_SESSION_HANDLE);
typedef BYTE* (WINAPI* fn_WintunReceivePacket)(WINTUN_SESSION_HANDLE, DWORD*);
typedef void (WINAPI* fn_WintunReleaseReceivePacket)(WINTUN_SESSION_HANDLE, const BYTE*);
typedef BYTE* (WINAPI* fn_WintunAllocateSendPacket)(WINTUN_SESSION_HANDLE, DWORD);
typedef void (WINAPI* fn_WintunSendPacket)(WINTUN_SESSION_HANDLE, const BYTE*);

static fn_WintunCreateAdapter        WintunCreateAdapter        = nullptr;
static fn_WintunOpenAdapter          WintunOpenAdapter          = nullptr;
static fn_WintunCloseAdapter         WintunCloseAdapter         = nullptr;
static fn_WintunGetAdapterLUID       WintunGetAdapterLUID       = nullptr;
static fn_WintunStartSession         WintunStartSession         = nullptr;
static fn_WintunEndSession           WintunEndSession           = nullptr;
static fn_WintunGetReadWaitEvent     WintunGetReadWaitEvent     = nullptr;
static fn_WintunReceivePacket        WintunReceivePacket        = nullptr;
static fn_WintunReleaseReceivePacket WintunReleaseReceivePacket = nullptr;
static fn_WintunAllocateSendPacket   WintunAllocateSendPacket   = nullptr;
static fn_WintunSendPacket           WintunSendPacket           = nullptr;

#pragma pack(push, 1)
struct IPv4Header {
    uint8_t ihl_ver, tos; uint16_t tot_len, id, frag_off;
    uint8_t ttl, protocol; uint16_t check; uint32_t saddr, daddr;
};
struct TCPHeader {
    uint16_t source, dest; uint32_t seq, ack_seq;
    uint16_t res1_doff_flags, window, check, urg_ptr;
};
struct UDPHeader { uint16_t source, dest, len, check; };
#pragma pack(pop)

struct NatEntry { uint32_t orig_dst_ip; uint16_t orig_dst_port; };

static NatEntry                 g_nat_table[65536];
static WINTUN_ADAPTER_HANDLE    g_Adapter     = nullptr;
static WINTUN_SESSION_HANDLE    g_Session     = nullptr;
static SOCKET                   g_ListenSock  = INVALID_SOCKET;
static std::mutex               g_TunTxMutex;
static std::atomic<bool>        g_TunnelRun{ false };
static AppConfig                g_active_cfg;
static std::atomic<DWORD>       g_master_thread_id{ 0 };
static DWORD                    g_PhysIfIndex = 0;
static std::string              g_PhysGateway = "";
static NET_LUID                 g_TunLuid{};
static DWORD                    g_TunIfIndex  = 0;
static std::wstring             g_TunAlias    = L"NanoRayTun";

struct DnsCacheEntry {
    std::vector<uint8_t> payload; // response data from byte 2 onwards
    ULONGLONG expire_tick = 0;
};
static std::mutex                                     g_dns_cache_mtx;
static std::unordered_map<std::string, DnsCacheEntry> g_dns_cache;

static bool native_add_route(NET_LUID luid, DWORD if_index, const char* dest, uint8_t prefix_len, const char* nexthop, DWORD metric = 1) {
    if (!dest || !nexthop) return false;
    MIB_IPFORWARD_ROW2 r{};
    InitializeIpForwardEntry(&r);
    r.InterfaceLuid = luid;
    if (if_index != 0) r.InterfaceIndex = if_index;
    r.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    r.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = inet_addr(dest);
    r.DestinationPrefix.PrefixLength = prefix_len;
    r.NextHop.Ipv4.sin_family = AF_INET;
    r.NextHop.Ipv4.sin_addr.s_addr = inet_addr(nexthop);
    r.Metric = metric;

    DeleteIpForwardEntry2(&r);
    DWORD res = CreateIpForwardEntry2(&r);
    return (res == NO_ERROR || res == ERROR_OBJECT_ALREADY_EXISTS);
}

static bool native_delete_route(NET_LUID luid, DWORD if_index, const char* dest, uint8_t prefix_len, const char* nexthop = nullptr) {
    if (!dest) return false;
    MIB_IPFORWARD_ROW2 r{};
    InitializeIpForwardEntry(&r);
    r.InterfaceLuid = luid;
    if (if_index != 0) r.InterfaceIndex = if_index;
    r.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    r.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = inet_addr(dest);
    r.DestinationPrefix.PrefixLength = prefix_len;
    if (nexthop && nexthop[0] != '\0') {
        r.NextHop.Ipv4.sin_family = AF_INET;
        r.NextHop.Ipv4.sin_addr.s_addr = inet_addr(nexthop);
    }
    DWORD res = DeleteIpForwardEntry2(&r);
    return (res == NO_ERROR);
}

static bool find_physical_adapter(DWORD& out_if_index, std::string& out_gateway) {
    ULONG buf_len = sizeof(IP_ADAPTER_INFO) * 16;
    IP_ADAPTER_INFO* adapters = static_cast<IP_ADAPTER_INFO*>(std::malloc(buf_len));
    if (!adapters) return false;
    if (GetAdaptersInfo(adapters, &buf_len) == ERROR_BUFFER_OVERFLOW) {
        std::free(adapters);
        adapters = static_cast<IP_ADAPTER_INFO*>(std::malloc(buf_len));
        if (!adapters) return false;
    }
    bool found = false;
    if (GetAdaptersInfo(adapters, &buf_len) == NO_ERROR) {
        IP_ADAPTER_INFO* p = adapters;
        while (p) {
            std::string gw = p->GatewayList.IpAddress.String;
            std::string ip = p->IpAddressList.IpAddress.String;
            std::string desc = p->Description;
            for (char& c : desc) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
            bool is_virtual = (desc.find("tun") != std::string::npos ||
                               desc.find("tap") != std::string::npos ||
                               desc.find("wintun") != std::string::npos ||
                               desc.find("sing-tun") != std::string::npos ||
                               desc.find("wireguard") != std::string::npos ||
                               desc.find("virtual") != std::string::npos);
            if (!is_virtual && !gw.empty() && gw != "0.0.0.0" && ip != "0.0.0.0" && ip != "127.0.0.1" && ip != "10.66.66.1") {
                out_if_index = p->Index;
                out_gateway = gw;
                found = true;
                break;
            }
            p = p->Next;
        }
    }
    std::free(adapters);
    return found;
}

static bool is_other_vpn_active() {
    ULONG buf_len = sizeof(IP_ADAPTER_INFO) * 16;
    IP_ADAPTER_INFO* adapters = static_cast<IP_ADAPTER_INFO*>(std::malloc(buf_len));
    if (!adapters) return false;
    if (GetAdaptersInfo(adapters, &buf_len) == ERROR_BUFFER_OVERFLOW) {
        std::free(adapters);
        adapters = static_cast<IP_ADAPTER_INFO*>(std::malloc(buf_len));
        if (!adapters) return false;
    }
    bool conflict = false;
    if (GetAdaptersInfo(adapters, &buf_len) == NO_ERROR) {
        IP_ADAPTER_INFO* p = adapters;
        while (p) {
            std::string desc = p->Description;
            for (char& c : desc) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
            std::string ip = p->IpAddressList.IpAddress.String;
            if ((desc.find("sing-tun") != std::string::npos || (desc.find("wintun") != std::string::npos && desc.find("nanoray") == std::string::npos && desc.find("vlesstun") == std::string::npos)) &&
                ip != "0.0.0.0" && ip != "10.66.66.1") {
                conflict = true;
                break;
            }
            p = p->Next;
        }
    }
    std::free(adapters);
    return conflict;
}

std::atomic<TunnelState> g_State{ STATE_DISCONNECTED };
std::atomic<uint64_t>    g_TotalRx{ 0 };
std::atomic<uint64_t>    g_TotalTx{ 0 };
std::atomic<int>         g_LastPingMs{ PING_IDLE };
ULONGLONG                g_ConnectTick = 0;
static std::mutex g_status_mtx;
static std::string g_StatusMsg = "Ready - Paste a VLESS URI to start";

void set_status_msg(const std::string& msg) {
    std::lock_guard<std::mutex> lk(g_status_mtx);
    g_StatusMsg = msg;
}

std::string get_status_msg() {
    std::lock_guard<std::mutex> lk(g_status_mtx);
    return g_StatusMsg;
}

static std::string mask_ip(uint32_t ip_net) {
    uint32_t h = ntohl(ip_net);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%u.%u.x.x", (h >> 24) & 0xFF, (h >> 16) & 0xFF);
    return buf;
}

static void log_msg(const char* fmt, ...) {
    static std::mutex log_mtx;
    std::lock_guard<std::mutex> lk(log_mtx);

    char exe_path[MAX_PATH];
    std::string log_file = "nanoray.log";
    if (GetModuleFileNameA(nullptr, exe_path, MAX_PATH)) {
        char* last_slash = std::strrchr(exe_path, '\\');
        if (last_slash) *(last_slash + 1) = '\0';
        log_file = std::string(exe_path) + "nanoray.log";
    }

    FILE* check_f = std::fopen(log_file.c_str(), "rb");
    if (check_f) {
        std::fseek(check_f, 0, SEEK_END);
        long sz = std::ftell(check_f);
        std::fclose(check_f);
        if (sz > 512 * 1024) {
            FILE* tr = std::fopen(log_file.c_str(), "w");
            if (tr) std::fclose(tr);
        }
    }

    FILE* f = std::fopen(log_file.c_str(), "a");
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::fprintf(f, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    std::vfprintf(f, fmt, ap);
    std::fprintf(f, "\n");
    va_end(ap);
    std::fclose(f);
}

void run_silent_cmd(const std::string& cmd) {
    log_msg("EXEC: %s", cmd.c_str());
    STARTUPINFOA si{}; PROCESS_INFORMATION pi{};
    si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    std::string full = "cmd.exe /c " + cmd;
    if (CreateProcessA(nullptr, &full[0], nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        DWORD exit_code = 0;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        if (exit_code != 0) {
            log_msg("EXIT CODE %lu: %s", exit_code, cmd.c_str());
        }
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
}

static uint16_t calc_checksum(const void* data, int len, uint32_t sum = 0) {
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    while (len > 1) {
        sum += (static_cast<uint16_t>(ptr[0]) << 8) | static_cast<uint16_t>(ptr[1]);
        ptr += 2;
        len -= 2;
    }
    if (len > 0) {
        sum += (static_cast<uint16_t>(ptr[0]) << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return htons(static_cast<uint16_t>(~sum));
}

static void update_ipv4_checksum(IPv4Header* ip) {
    ip->check = 0;
    ip->check = calc_checksum(ip, (ip->ihl_ver & 0x0F) * 4);
}

static void update_l4_checksum(IPv4Header* ip, void* l4_hdr, uint16_t* check_field) {
    int ihl = (ip->ihl_ver & 0x0F) * 4;
    int l4_len = ntohs(ip->tot_len) - ihl;
    *check_field = 0;
    const uint8_t* s = reinterpret_cast<const uint8_t*>(&ip->saddr);
    const uint8_t* d = reinterpret_cast<const uint8_t*>(&ip->daddr);
    uint32_t sum = ((static_cast<uint16_t>(s[0]) << 8) | s[1]) +
                   ((static_cast<uint16_t>(s[2]) << 8) | s[3]) +
                   ((static_cast<uint16_t>(d[0]) << 8) | d[1]) +
                   ((static_cast<uint16_t>(d[2]) << 8) | d[3]) +
                   static_cast<uint16_t>(ip->protocol) +
                   static_cast<uint16_t>(l4_len);
    *check_field = calc_checksum(l4_hdr, l4_len, sum);
    if (ip->protocol == IPPROTO_UDP && *check_field == 0) *check_field = 0xFFFF;
}

static void tun_send_packet(const uint8_t* buf, DWORD len) {
    std::lock_guard<std::mutex> lock(g_TunTxMutex);
    if (!g_Session || !g_TunnelRun) return;
    BYTE* pkt = WintunAllocateSendPacket(g_Session, len);
    if (pkt) { std::memcpy(pkt, buf, len); WintunSendPacket(g_Session, pkt); }
}

static void send_icmp_port_unreachable(const uint8_t* orig_pkt, DWORD pkt_len) {
    if (pkt_len < sizeof(IPv4Header) + 8) return;
    const IPv4Header* orig_ip = reinterpret_cast<const IPv4Header*>(orig_pkt);
    int orig_ihl = (orig_ip->ihl_ver & 0x0F) * 4;
    if (pkt_len < static_cast<DWORD>(orig_ihl + 8)) return;

    uint16_t icmp_payload_len = static_cast<uint16_t>(orig_ihl + 8);
    uint16_t total_len = static_cast<uint16_t>(sizeof(IPv4Header) + 8 + icmp_payload_len);
    uint8_t buf[256];
    std::memset(buf, 0, total_len);

    IPv4Header* ip = reinterpret_cast<IPv4Header*>(buf);
    ip->ihl_ver = 0x45; ip->tos = 0; ip->tot_len = htons(total_len);
    ip->id = htons(static_cast<uint16_t>(GetTickCount64() & 0xFFFF));
    ip->frag_off = 0; ip->ttl = 64; ip->protocol = 1; // IPPROTO_ICMP
    ip->saddr = orig_ip->daddr; ip->daddr = orig_ip->saddr;

    uint8_t* icmp = buf + sizeof(IPv4Header);
    icmp[0] = 3; // Type: Destination Unreachable
    icmp[1] = 3; // Code: Port Unreachable
    std::memcpy(icmp + 8, orig_pkt, icmp_payload_len);

    uint16_t icmp_chk = calc_checksum(icmp, 8 + icmp_payload_len);
    std::memcpy(icmp + 2, &icmp_chk, 2);

    update_ipv4_checksum(ip);
    tun_send_packet(buf, total_len);
}

static bool send_all(SOCKET s, const void* data, int len) {
    const char* ptr = static_cast<const char*>(data);
    while (len > 0) {
        int sent = send(s, ptr, len, 0);
        if (sent <= 0) return false;
        ptr += sent; len -= sent;
    }
    return true;
}

static bool recv_exact(SOCKET s, void* buf, int len) {
    char* ptr = static_cast<char*>(buf);
    while (len > 0) {
        int r = recv(s, ptr, len, 0);
        if (r <= 0) return false;
        ptr += r; len -= r;
    }
    return true;
}

static std::string base64_encode(const std::string& in) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; int val = 0, valb = -6;
    for (uint8_t c : in) {
        val = (val << 8) + c; valb += 8;
        while (valb >= 0) { out.push_back(tbl[(val >> valb) & 0x3F]); valb -= 6; }
    }
    if (valb > -6) out.push_back(tbl[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

static SOCKET create_outbound_socket(const char* target_ip, uint16_t target_port, int timeout_ms = 6000, const AppConfig* pcfg = nullptr) {
    const AppConfig& cfg = pcfg ? *pcfg : g_active_cfg;
    if (!target_ip || target_ip[0] == '\0' || target_port == 0) return INVALID_SOCKET;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    BOOL nodelay = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
    int buf_sz = 262144;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&buf_sz), sizeof(buf_sz));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&buf_sz), sizeof(buf_sz));
    DWORD tv = timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));

    uint32_t ip_addr = inet_addr(target_ip);
    if (ip_addr == INADDR_NONE) {
        if (!cfg.vless_resolved_ip.empty() && target_ip == cfg.vless_ip) {
            ip_addr = inet_addr(cfg.vless_resolved_ip.c_str());
        } else if (!cfg.chain_resolved_ip.empty() && target_ip == cfg.chain_ip) {
            ip_addr = inet_addr(cfg.chain_resolved_ip.c_str());
        }
    }
    if (ip_addr == INADDR_NONE) {
        hostent* he = gethostbyname(target_ip);
        if (he && he->h_addr_list[0]) ip_addr = *reinterpret_cast<uint32_t*>(he->h_addr_list[0]);
        else { closesocket(s); return INVALID_SOCKET; }
    }

    if ((ntohl(ip_addr) >> 24) != 127 && g_PhysIfIndex != 0) {
        DWORD net_if = htonl(g_PhysIfIndex);
        setsockopt(s, IPPROTO_IP, IP_UNICAST_IF, reinterpret_cast<const char*>(&net_if), sizeof(net_if));
    }

    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(target_port); addr.sin_addr.s_addr = ip_addr;
    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        log_msg("create_outbound_socket to %s:%u FAILED! WSAError=%d", target_ip, target_port, WSAGetLastError());
        closesocket(s); return INVALID_SOCKET;
    }

    DWORD zero_tv = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&zero_tv), sizeof(zero_tv));
    return s;
}

static std::string resolve_to_ip_str(const std::string& host) {
    if (host.empty()) return "";
    uint32_t a = inet_addr(host.c_str());
    if (a != INADDR_NONE) return host;
    hostent* he = gethostbyname(host.c_str());
    if (he && he->h_addr_list && he->h_addr_list[0]) {
        in_addr in{};
        in.s_addr = *reinterpret_cast<uint32_t*>(he->h_addr_list[0]);
        char* s = inet_ntoa(in);
        if (s) return std::string(s);
    }
    return host;
}

static SOCKET dial_proxy_to_dest(uint32_t target_ip_net, uint16_t target_port_net, const AppConfig* pcfg = nullptr) {
    const AppConfig& cfg = pcfg ? *pcfg : g_active_cfg;
    if (cfg.chain_type == CHAIN_NONE) return INVALID_SOCKET;

    SOCKET s = create_outbound_socket(cfg.chain_ip.c_str(), cfg.chain_port, 6000, &cfg);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    if (cfg.chain_type == CHAIN_SOCKS5) {
        bool has_auth = !cfg.chain_user.empty();
        uint8_t greet[3] = { 0x05, 0x01, static_cast<uint8_t>(has_auth ? 0x02 : 0x00) }, resp[2];
        if (!send_all(s, greet, 3) || !recv_exact(s, resp, 2) || resp[0] != 0x05) { closesocket(s); return INVALID_SOCKET; }
        if (resp[1] == 0x02) {
            uint8_t auth_pkt[515];
            uint8_t ulen = static_cast<uint8_t>(cfg.chain_user.size()), plen = static_cast<uint8_t>(cfg.chain_pass.size());
            int idx = 0; auth_pkt[idx++] = 0x01; auth_pkt[idx++] = ulen;
            std::memcpy(auth_pkt + idx, cfg.chain_user.data(), ulen); idx += ulen;
            auth_pkt[idx++] = plen;
            std::memcpy(auth_pkt + idx, cfg.chain_pass.data(), plen); idx += plen;
            if (!send_all(s, auth_pkt, idx) || !recv_exact(s, resp, 2) || resp[1] != 0x00) { closesocket(s); return INVALID_SOCKET; }
        } else if (resp[1] != 0x00) { closesocket(s); return INVALID_SOCKET; }

        uint8_t req[10] = { 0x05, 0x01, 0x00, 0x01 }, rpl[10];
        std::memcpy(req + 4, &target_ip_net, 4); std::memcpy(req + 8, &target_port_net, 2);
        if (!send_all(s, req, 10) || !recv_exact(s, rpl, 4) || rpl[1] != 0x00) { closesocket(s); return INVALID_SOCKET; }
        int rest = (rpl[3] == 0x01) ? 6 : (rpl[3] == 0x04 ? 18 : 0);
        if (rpl[3] == 0x03) { uint8_t dlen = 0; recv_exact(s, &dlen, 1); rest = dlen + 2; }
        uint8_t trash[512];
        if (rest > 0 && (rest > (int)sizeof(trash) || !recv_exact(s, trash, rest))) { closesocket(s); return INVALID_SOCKET; }
        return s;
    }

    if (cfg.chain_type == CHAIN_HTTP) {
        in_addr tip; tip.s_addr = target_ip_net;
        char req[1024];
        std::string auth_hdr = cfg.chain_user.empty() ? "" :
            ("Proxy-Authorization: Basic " + base64_encode(cfg.chain_user + ":" + cfg.chain_pass) + "\r\n");
        int len = std::snprintf(req, sizeof(req),
            "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n%sProxy-Connection: Keep-Alive\r\n\r\n",
            inet_ntoa(tip), ntohs(target_port_net), inet_ntoa(tip), ntohs(target_port_net), auth_hdr.c_str());
        if (len <= 0 || len >= (int)sizeof(req) || !send_all(s, req, len)) { closesocket(s); return INVALID_SOCKET; }
        std::string http_resp; char ch;
        while (http_resp.size() < 2048 && recv(s, &ch, 1, 0) == 1) {
            http_resp.push_back(ch);
            if (http_resp.size() >= 4 && http_resp.substr(http_resp.size() - 4) == "\r\n\r\n") break;
        }
        if (http_resp.find(" 200 ") == std::string::npos) { closesocket(s); return INVALID_SOCKET; }
        return s;
    }
    closesocket(s); return INVALID_SOCKET;
}

static SOCKET dial_vless_tunnel(const AppConfig* pcfg = nullptr) {
    const AppConfig& cfg = pcfg ? *pcfg : g_active_cfg;
    if (!cfg.vless_valid) return INVALID_SOCKET;
    if (cfg.chain_type == CHAIN_NONE) return create_outbound_socket(cfg.vless_ip.c_str(), cfg.vless_port, 6000, &cfg);

    uint32_t vip = inet_addr(cfg.vless_resolved_ip.empty() ? resolve_to_ip_str(cfg.vless_ip).c_str() : cfg.vless_resolved_ip.c_str());
    if (vip == INADDR_NONE) {
        std::string ip_str = resolve_to_ip_str(cfg.vless_ip);
        vip = inet_addr(ip_str.c_str());
    }
    uint16_t vport = htons(cfg.vless_port);
    return dial_proxy_to_dest(vip, vport, &cfg);
}

static ITransportStream* dial_vless_transport(bool enable_vision = false, const AppConfig* pcfg = nullptr) {
    const AppConfig& cfg = pcfg ? *pcfg : g_active_cfg;
    if (!cfg.vless_valid) return nullptr;
    SOCKET s = dial_vless_tunnel(&cfg);
    if (s == INVALID_SOCKET) return nullptr;

    ITransportStream* stream = new TcpStream(s, true);

    if (cfg.vless_security == "reality") {
        std::string sni = cfg.vless_sni.empty() ? cfg.vless_ip : cfg.vless_sni;
        RealityStream* reality = new RealityStream(stream, sni, cfg.vless_pbk, cfg.vless_sid, cfg.vless_spx, cfg.vless_fp);
        if (!reality->handshake()) {
            log_msg("REALITY handshake to %s failed!", sni.c_str());
            delete reality;
            return nullptr;
        }
        stream = reality;
    } else if (cfg.vless_security == "tls") {
        std::string sni = cfg.vless_sni.empty() ? cfg.vless_ip : cfg.vless_sni;
        SchannelStream* tls = new SchannelStream(stream, sni, cfg.vless_allow_insecure);
        if (!tls->handshake()) {
            log_msg("TLS handshake to %s failed!", sni.c_str());
            delete tls;
            return nullptr;
        }
        stream = tls;
    }

    if (cfg.vless_type == "ws") {
        std::string path = cfg.vless_path.empty() ? "/" : cfg.vless_path;
        std::string host = cfg.vless_host.empty() ? cfg.vless_sni : cfg.vless_host;
        WsStream* ws = new WsStream(stream, path, host);
        if (!ws->handshake()) {
            log_msg("WebSocket handshake to %s%s failed!", host.c_str(), path.c_str());
            delete ws;
            return nullptr;
        }
        stream = ws;
    } else if (cfg.vless_type == "xhttp") {
        std::string path = cfg.vless_path.empty() ? "/" : cfg.vless_path;
        std::string host = cfg.vless_host.empty() ? (cfg.vless_sni.empty() ? cfg.vless_ip : cfg.vless_sni) : cfg.vless_host;
        XhttpStream* xhttp = new XhttpStream(stream, host, path, cfg.vless_mode, cfg.vless_pad_min, cfg.vless_pad_max);
        if (!xhttp->handshake()) {
            log_msg("XHTTP handshake to %s%s failed!", host.c_str(), path.c_str());
            delete xhttp;
            return nullptr;
        }
        stream = xhttp;
    } else if (cfg.vless_type == "httpupgrade") {
        std::string path = cfg.vless_path.empty() ? "/" : cfg.vless_path;
        std::string host = cfg.vless_host.empty() ? (cfg.vless_sni.empty() ? cfg.vless_ip : cfg.vless_sni) : cfg.vless_host;
        HttpUpgradeStream* hu = new HttpUpgradeStream(stream, path, host);
        if (!hu->handshake()) {
            log_msg("HTTPUpgrade handshake to %s%s failed!", host.c_str(), path.c_str());
            delete hu;
            return nullptr;
        }
        stream = hu;
    }

    if (enable_vision && cfg.outbound_proto == PROTO_VLESS && cfg.vless_flow == "xtls-rprx-vision") {
        stream = new VisionStream(stream, cfg.vless_uuid);
    }

    return stream;
}


struct SessionArgs { SOCKET client_sock; uint32_t orig_dst_ip; uint16_t orig_dst_port; };
struct PipeStreamArgs { ITransportStream* v_stream; SOCKET c_sock; bool is_vless; };

static unsigned __stdcall downlink_worker(void* arg) {
    PipeStreamArgs* p = static_cast<PipeStreamArgs*>(arg);
    ITransportStream* v_stream = p->v_stream;
    SOCKET c_sock = p->c_sock;
    bool is_vless = p->is_vless;
    delete p;

    if (is_vless) {
        ITransportStream* raw = v_stream->unwrap_vision();
        uint8_t vless_resp[2];
        if (!raw->recv_exact(vless_resp, 2)) {
            shutdown(c_sock, SD_BOTH);
            return 0;
        }
        if (vless_resp[1] > 0) {
            uint8_t addons[256];
            if (!raw->recv_exact(addons, vless_resp[1])) {
                shutdown(c_sock, SD_BOTH);
                return 0;
            }
        }
    }

    char buf[65536];
    while (g_TunnelRun) {
        int n = v_stream->recv_some(buf, sizeof(buf));
        if (n <= 0) break;
        g_TotalRx += n;
        if (!send_all(c_sock, buf, n)) break;
    }
    shutdown(c_sock, SD_BOTH);
    return 0;
}

static unsigned __stdcall tcp_session_thread(void* arg) {
    SessionArgs* sa = static_cast<SessionArgs*>(arg);
    SOCKET c_sock = sa->client_sock; uint32_t dst_ip = sa->orig_dst_ip; uint16_t dst_port = sa->orig_dst_port; delete sa;
    BOOL nodelay = TRUE;
    setsockopt(c_sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
    int buf_sz = 262144;
    setsockopt(c_sock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&buf_sz), sizeof(buf_sz));
    setsockopt(c_sock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&buf_sz), sizeof(buf_sz));

    ITransportStream* stream = nullptr;
    if (g_active_cfg.vless_valid) {
        stream = dial_vless_transport(g_active_cfg.outbound_proto == PROTO_VLESS && g_active_cfg.vless_flow == "xtls-rprx-vision");
    } else if (g_active_cfg.chain_type != CHAIN_NONE) {
        SOCKET p_sock = dial_proxy_to_dest(dst_ip, dst_port);
        if (p_sock != INVALID_SOCKET) {
            setsockopt(p_sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
            setsockopt(p_sock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&buf_sz), sizeof(buf_sz));
            setsockopt(p_sock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&buf_sz), sizeof(buf_sz));
            stream = new TcpStream(p_sock, true);
        }
    }
    if (!stream) { closesocket(c_sock); return 0; }

    if (g_active_cfg.vless_valid) {
        uint8_t first_pkt[16384];
        int hdr_len = 0;
        if (g_active_cfg.outbound_proto == PROTO_TROJAN) {
            hdr_len = build_trojan_header(first_pkt, 0x01, dst_ip, dst_port, g_active_cfg.trojan_hash_hex);
        } else {
            hdr_len = build_vless_header(first_pkt, 0x01, dst_ip, dst_port, g_active_cfg.vless_uuid, g_active_cfg.vless_flow);
        }
        u_long available = 0;
        int initial_payload = 0;
        if (ioctlsocket(c_sock, FIONREAD, &available) == 0 && available > 0) {
            int to_read = (static_cast<int>(available) < static_cast<int>(sizeof(first_pkt) - hdr_len)) ?
                          static_cast<int>(available) : static_cast<int>(sizeof(first_pkt) - hdr_len);
            int r = recv(c_sock, reinterpret_cast<char*>(first_pkt + hdr_len), to_read, 0);
            if (r > 0) { initial_payload = r; g_TotalTx += r; }
        } else {
            fd_set rfds; FD_ZERO(&rfds); FD_SET(c_sock, &rfds);
            timeval tv{ 0, 5000 }; // 5ms micro-wait instead of 150ms stall
            if (select(0, &rfds, nullptr, nullptr, &tv) > 0) {
                int r = recv(c_sock, reinterpret_cast<char*>(first_pkt + hdr_len), sizeof(first_pkt) - hdr_len, 0);
                if (r > 0) { initial_payload = r; g_TotalTx += r; }
            }
        }
        ITransportStream* raw = stream->unwrap_vision();
        if (!raw->send_all(first_pkt, hdr_len)) { stream->close(); delete stream; closesocket(c_sock); return 0; }
        if (initial_payload > 0) {
            if (!stream->send_all(first_pkt + hdr_len, initial_payload)) { stream->close(); delete stream; closesocket(c_sock); return 0; }
        }
    }

    bool is_vless_downlink = (g_active_cfg.vless_valid && g_active_cfg.outbound_proto == PROTO_VLESS);
    uintptr_t hDown = _beginthreadex(nullptr, 65536, downlink_worker, new PipeStreamArgs{ stream, c_sock, is_vless_downlink }, 0, nullptr);

    DWORD tv_c = 2000;
    setsockopt(c_sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv_c), sizeof(tv_c));

    char buf[65536];
    ULONGLONG last_act = GetTickCount64();
    while (g_TunnelRun) {
        int n = recv(c_sock, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (n < 0 && WSAGetLastError() == WSAETIMEDOUT) {
                if (hDown && WaitForSingleObject(reinterpret_cast<HANDLE>(hDown), 0) == WAIT_OBJECT_0) {
                    break;
                }
                if (GetTickCount64() - last_act >= 120000) {
                    break;
                }
                continue;
            }
            break;
        }
        last_act = GetTickCount64();
        g_TotalTx += n;
        if (!stream->send_all(buf, n)) break;
    }
    // TCP Half-close: signal upstream send shutdown and stop local receives
    stream->shutdown_send();
    shutdown(c_sock, SD_RECEIVE);

    if (hDown) {
        for (int i = 0; i < 10 && g_TunnelRun; ++i) {
            DWORD wr = WaitForSingleObject(reinterpret_cast<HANDLE>(hDown), 100);
            if (wr == WAIT_OBJECT_0) break;
        }
        stream->close();
        shutdown(c_sock, SD_BOTH);
        WaitForSingleObject(reinterpret_cast<HANDLE>(hDown), INFINITE);
        CloseHandle(reinterpret_cast<HANDLE>(hDown));
    } else {
        stream->close();
        shutdown(c_sock, SD_BOTH);
    }
    delete stream;
    closesocket(c_sock);
    return 0;
}

static std::atomic<int> g_active_dns_workers{ 0 };
struct DnsJob { uint32_t src_ip, dst_ip; uint16_t src_port, dst_port, payload_len; uint8_t payload[1500]; };

static unsigned __stdcall dns_hijack_worker(void* arg) {
    struct DnsWorkerGuard {
        ~DnsWorkerGuard() { g_active_dns_workers.fetch_sub(1); }
    } guard;
    DnsJob* job = static_cast<DnsJob*>(arg);
    if (!job) return 0;

    // Fast DNS cache lookup (serves frequent queries in 0.05ms)
    if (job->payload_len >= 12) {
        std::string qkey(reinterpret_cast<const char*>(job->payload + 2), job->payload_len - 2);
        ULONGLONG now = GetTickCount64();
        bool hit = false;
        std::vector<uint8_t> cached_body;
        {
            std::lock_guard<std::mutex> lk(g_dns_cache_mtx);
            auto it = g_dns_cache.find(qkey);
            if (it != g_dns_cache.end()) {
                if (now < it->second.expire_tick) {
                    hit = true;
                    cached_body = it->second.payload;
                } else {
                    g_dns_cache.erase(it);
                }
            }
        }
        if (hit && !cached_body.empty()) {
            uint16_t ans_len = static_cast<uint16_t>(cached_body.size() + 2);
            uint8_t raw_ip_pkt[2048];
            if (ans_len <= 1400) {
                uint8_t* udp_data = raw_ip_pkt + sizeof(IPv4Header) + sizeof(UDPHeader);
                udp_data[0] = job->payload[0]; // Echo transaction ID
                udp_data[1] = job->payload[1];
                std::memcpy(udp_data + 2, cached_body.data(), cached_body.size());

                g_TotalRx += ans_len;
                IPv4Header* ip = reinterpret_cast<IPv4Header*>(raw_ip_pkt);
                UDPHeader* udp = reinterpret_cast<UDPHeader*>(raw_ip_pkt + sizeof(IPv4Header));
                uint16_t total_len = static_cast<uint16_t>(sizeof(IPv4Header) + sizeof(UDPHeader) + ans_len);
                ip->ihl_ver = 0x45; ip->tos = 0; ip->tot_len = htons(total_len);
                ip->id = htons(static_cast<uint16_t>(GetTickCount64() & 0xFFFF));
                ip->frag_off = 0; ip->ttl = 64; ip->protocol = IPPROTO_UDP;
                ip->saddr = job->dst_ip; ip->daddr = job->src_ip;
                udp->source = job->dst_port; udp->dest = job->src_port;
                udp->len = htons(sizeof(UDPHeader) + ans_len);
                update_ipv4_checksum(ip); update_l4_checksum(ip, udp, &udp->check);
                tun_send_packet(raw_ip_pkt, total_len);
                delete job;
                return 0;
            }
        }
    }

    log_msg("dns_hijack: intercepted DNS query len=%u from port %u", job->payload_len, ntohs(job->src_port));
    ITransportStream* stream = nullptr;
    if (g_active_cfg.vless_valid) {
        stream = dial_vless_transport();
    } else if (g_active_cfg.chain_type != CHAIN_NONE) {
        SOCKET s = dial_proxy_to_dest(inet_addr("1.1.1.1"), htons(53));
        if (s != INVALID_SOCKET) stream = new TcpStream(s, true);
    }

    if (stream) {
        stream->set_rcv_timeout(3500);
        uint8_t pkt[2048];
        int offset = 0;
        if (g_active_cfg.vless_valid) {
            if (g_active_cfg.outbound_proto == PROTO_TROJAN) {
                offset = build_trojan_header(pkt, 0x01, inet_addr("1.1.1.1"), htons(53), g_active_cfg.trojan_hash_hex);
            } else {
                offset = build_vless_header(pkt, 0x01, inet_addr("1.1.1.1"), htons(53), g_active_cfg.vless_uuid, g_active_cfg.vless_flow);
            }
        }
        uint16_t tcp_dns_len = htons(job->payload_len);
        std::memcpy(pkt + offset, &tcp_dns_len, 2);
        std::memcpy(pkt + offset + 2, job->payload, job->payload_len);
        g_TotalTx += job->payload_len;
        if (stream->send_all(pkt, offset + 2 + job->payload_len)) {
            bool ok = true;
            if (g_active_cfg.vless_valid && g_active_cfg.outbound_proto == PROTO_VLESS) {
                uint8_t v_resp[2];
                if (!stream->recv_exact(v_resp, 2)) ok = false;
                else if (v_resp[1] > 0) {
                    uint8_t ad[256];
                    if (!stream->recv_exact(ad, v_resp[1])) ok = false;
                }
            }
            if (ok) {
                uint16_t ans_len_net = 0;
                if (stream->recv_exact(&ans_len_net, 2)) {
                    uint16_t ans_len = ntohs(ans_len_net);
                    uint8_t raw_ip_pkt[2048];
                    if (ans_len > 0 && ans_len <= 1400 &&
                        stream->recv_exact(raw_ip_pkt + sizeof(IPv4Header) + sizeof(UDPHeader), ans_len)) {
                        g_TotalRx += ans_len;
                        IPv4Header* ip = reinterpret_cast<IPv4Header*>(raw_ip_pkt);
                        UDPHeader* udp = reinterpret_cast<UDPHeader*>(raw_ip_pkt + sizeof(IPv4Header));
                        uint16_t total_len = static_cast<uint16_t>(sizeof(IPv4Header) + sizeof(UDPHeader) + ans_len);
                        ip->ihl_ver = 0x45; ip->tos = 0; ip->tot_len = htons(total_len);
                        ip->id = htons(static_cast<uint16_t>(GetTickCount64() & 0xFFFF));
                        ip->frag_off = 0; ip->ttl = 64; ip->protocol = IPPROTO_UDP;
                        ip->saddr = job->dst_ip; ip->daddr = job->src_ip;
                        udp->source = job->dst_port; udp->dest = job->src_port;
                        udp->len = htons(sizeof(UDPHeader) + ans_len);
                        update_ipv4_checksum(ip); update_l4_checksum(ip, udp, &udp->check);
                        tun_send_packet(raw_ip_pkt, total_len);
                        log_msg("dns_hijack: resolved %u bytes answer -> injected to port %u", ans_len, ntohs(job->src_port));

                        // Cache successful response (TTL 3 minutes)
                        if (ans_len > 12 && job->payload_len >= 12) {
                            const uint8_t* resp_ptr = raw_ip_pkt + sizeof(IPv4Header) + sizeof(UDPHeader);
                            if ((resp_ptr[3] & 0x0F) == 0) { // NOERROR
                                std::string qkey(reinterpret_cast<const char*>(job->payload + 2), job->payload_len - 2);
                                ULONGLONG now = GetTickCount64();
                                std::lock_guard<std::mutex> lk(g_dns_cache_mtx);
                                if (g_dns_cache.size() > 2048) {
                                    for (auto it = g_dns_cache.begin(); it != g_dns_cache.end(); ) {
                                        if (now >= it->second.expire_tick) it = g_dns_cache.erase(it);
                                        else ++it;
                                    }
                                    if (g_dns_cache.size() > 2048) g_dns_cache.clear();
                                }
                                DnsCacheEntry entry;
                                entry.payload.assign(resp_ptr + 2, resp_ptr + ans_len);
                                entry.expire_tick = now + 180000; // 3 min
                                g_dns_cache[qkey] = std::move(entry);
                            }
                        }
                    }
                }
            }
        }
        delete stream;
    }
    delete job;
    return 0;
}

struct UdpNatSession {
    uint16_t local_port;    // host byte order
    uint32_t dst_ip;        // network byte order
    uint16_t dst_port;      // network byte order
    ITransportStream* v_stream = nullptr;
    std::mutex send_mtx;
    std::atomic<bool> alive{ true };
    ULONGLONG last_tick = 0;
    uint64_t session_key = 0;
};

struct UdpInitArgs {
    std::shared_ptr<UdpNatSession> session;
    std::vector<uint8_t> first_payload;
};

static std::mutex g_udp_table_mtx;
static std::unordered_map<uint64_t, std::shared_ptr<UdpNatSession>> g_udp_map;

static inline uint64_t make_udp_key(uint16_t src_port_net, uint32_t dst_ip, uint16_t dst_port_net) {
    return (static_cast<uint64_t>(src_port_net) << 48) |
           (static_cast<uint64_t>(dst_port_net) << 32) |
           static_cast<uint64_t>(dst_ip);
}

static unsigned __stdcall udp_session_worker(void* arg) {
    auto* args = static_cast<UdpInitArgs*>(arg);
    auto sess = args->session;
    std::vector<uint8_t> first_data = std::move(args->first_payload);
    delete args;

    ITransportStream* v_stream = dial_vless_transport(false);
    if (!v_stream) {
        sess->alive.store(false);
        std::lock_guard<std::mutex> lk(g_udp_table_mtx);
        auto it = g_udp_map.find(sess->session_key);
        if (it != g_udp_map.end() && it->second == sess) g_udp_map.erase(it);
        return 0;
    }
    v_stream->set_rcv_timeout(2000); // 2s receive timeout to check session expiration without cutting active uploads

    std::vector<uint8_t> init_pkt;
    if (g_active_cfg.outbound_proto == PROTO_TROJAN) {
        uint8_t req_hdr[128];
        int req_len = build_trojan_header(req_hdr, 0x03, sess->dst_ip, sess->dst_port, g_active_cfg.trojan_hash_hex);
        init_pkt.insert(init_pkt.end(), req_hdr, req_hdr + req_len);
        uint8_t udp_buf[2048];
        int u_len = build_trojan_udp_packet(udp_buf, sess->dst_ip, sess->dst_port, first_data.data(), static_cast<uint16_t>(first_data.size()));
        init_pkt.insert(init_pkt.end(), udp_buf, udp_buf + u_len);
    } else {
        uint8_t hdr[128];
        int hlen = build_vless_header(hdr, 0x02, sess->dst_ip, sess->dst_port, g_active_cfg.vless_uuid, g_active_cfg.vless_flow);
        uint16_t flen_net = htons(static_cast<uint16_t>(first_data.size()));
        init_pkt.insert(init_pkt.end(), hdr, hdr + hlen);
        init_pkt.push_back(static_cast<uint8_t>((flen_net >> 8) & 0xFF));
        init_pkt.push_back(static_cast<uint8_t>(flen_net & 0xFF));
        init_pkt.insert(init_pkt.end(), first_data.begin(), first_data.end());
    }

    {
        std::lock_guard<std::mutex> lk(sess->send_mtx);
        sess->v_stream = v_stream;
        g_TotalTx += first_data.size();
        if (!v_stream->send_all(init_pkt.data(), static_cast<int>(init_pkt.size()))) {
            sess->alive.store(false);
            delete v_stream;
            sess->v_stream = nullptr;
            std::lock_guard<std::mutex> lk2(g_udp_table_mtx);
            auto it = g_udp_map.find(sess->session_key);
            if (it != g_udp_map.end() && it->second == sess) g_udp_map.erase(it);
            return 0;
        }
    }

    if (g_active_cfg.outbound_proto == PROTO_VLESS) {
        uint8_t v_resp[2];
        if (!v_stream->recv_exact(v_resp, 2)) {
            sess->alive.store(false);
            delete v_stream;
            sess->v_stream = nullptr;
            std::lock_guard<std::mutex> lk2(g_udp_table_mtx);
            auto it = g_udp_map.find(sess->session_key);
            if (it != g_udp_map.end() && it->second == sess) g_udp_map.erase(it);
            return 0;
        }
        if (v_resp[1] > 0) {
            uint8_t addons[256];
            if (!v_stream->recv_exact(addons, v_resp[1])) {
                sess->alive.store(false);
                delete v_stream;
                sess->v_stream = nullptr;
                std::lock_guard<std::mutex> lk2(g_udp_table_mtx);
                auto it = g_udp_map.find(sess->session_key);
                if (it != g_udp_map.end() && it->second == sess) g_udp_map.erase(it);
                return 0;
            }
        }
    }

    uint32_t tun_ip_net = inet_addr(g_active_cfg.tun_ip_str);
    while (g_TunnelRun && sess->alive.load()) {
        uint16_t dlen = 0;
        uint32_t src_ip_resp = sess->dst_ip;
        uint16_t src_port_resp = sess->dst_port;

        if (g_active_cfg.outbound_proto == PROTO_TROJAN) {
            uint8_t atyp = 0;
            if (!v_stream->recv_exact(&atyp, 1)) {
                if (WSAGetLastError() == WSAETIMEDOUT && (GetTickCount64() - sess->last_tick < 12000)) continue;
                break;
            }
            if (atyp == 0x01) { // IPv4
                uint32_t rip; uint16_t rport;
                if (!v_stream->recv_exact(&rip, 4)) break;
                if (!v_stream->recv_exact(&rport, 2)) break;
                src_ip_resp = rip;
                src_port_resp = rport;
            } else if (atyp == 0x03) { // Domain
                uint8_t dlen_domain = 0;
                if (!v_stream->recv_exact(&dlen_domain, 1)) break;
                char dname[256];
                if (!v_stream->recv_exact(dname, dlen_domain)) break;
                uint16_t rport;
                if (!v_stream->recv_exact(&rport, 2)) break;
                src_port_resp = rport;
            } else if (atyp == 0x04) { // IPv6
                uint8_t ip6[16];
                if (!v_stream->recv_exact(ip6, 16)) break;
                uint16_t rport;
                if (!v_stream->recv_exact(&rport, 2)) break;
                src_port_resp = rport;
            } else {
                break;
            }
            uint8_t lbytes[2];
            if (!v_stream->recv_exact(lbytes, 2)) break;
            dlen = (static_cast<uint16_t>(lbytes[0]) << 8) | lbytes[1];
            uint8_t crlf[2];
            if (!v_stream->recv_exact(crlf, 2)) break;
        } else {
            uint8_t len_bytes[2];
            if (!v_stream->recv_exact(len_bytes, 2)) {
                if (WSAGetLastError() == WSAETIMEDOUT && (GetTickCount64() - sess->last_tick < 12000)) continue;
                break;
            }
            dlen = (static_cast<uint16_t>(len_bytes[0]) << 8) | len_bytes[1];
        }

        if (dlen == 0 || dlen > 1460) break;

        uint8_t raw_ip_pkt[2048];
        uint8_t* dptr = raw_ip_pkt + sizeof(IPv4Header) + sizeof(UDPHeader);
        if (!v_stream->recv_exact(dptr, dlen)) break;

        g_TotalRx += dlen;
        sess->last_tick = GetTickCount64();

        IPv4Header* ip = reinterpret_cast<IPv4Header*>(raw_ip_pkt);
        UDPHeader* udp = reinterpret_cast<UDPHeader*>(raw_ip_pkt + sizeof(IPv4Header));
        uint16_t total_len = static_cast<uint16_t>(sizeof(IPv4Header) + sizeof(UDPHeader) + dlen);

        ip->ihl_ver = 0x45;
        ip->tos = 0;
        ip->tot_len = htons(total_len);
        ip->id = htons(static_cast<uint16_t>(GetTickCount64() & 0xFFFF));
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP;
        ip->saddr = src_ip_resp;
        ip->daddr = tun_ip_net;

        udp->source = src_port_resp;
        udp->dest = htons(sess->local_port);
        udp->len = htons(sizeof(UDPHeader) + dlen);

        update_ipv4_checksum(ip);
        update_l4_checksum(ip, udp, &udp->check);

        tun_send_packet(raw_ip_pkt, total_len);
    }

    sess->alive.store(false);
    {
        std::lock_guard<std::mutex> lk(sess->send_mtx);
        delete v_stream;
        sess->v_stream = nullptr;
    }
    {
        std::lock_guard<std::mutex> lk(g_udp_table_mtx);
        auto it = g_udp_map.find(sess->session_key);
        if (it != g_udp_map.end() && it->second == sess) g_udp_map.erase(it);
    }
    return 0;
}

static void handle_udp_packet(uint16_t src_port_net, uint32_t dst_ip, uint16_t dst_port_net, const uint8_t* payload, uint16_t payload_len) {
    if (!g_active_cfg.vless_valid) return;
    uint16_t lport = ntohs(src_port_net);
    uint64_t key = make_udp_key(src_port_net, dst_ip, dst_port_net);
    std::shared_ptr<UdpNatSession> sess;
    ULONGLONG now = GetTickCount64();

    {
        std::lock_guard<std::mutex> lk(g_udp_table_mtx);
        static ULONGLONG s_last_reap = 0;
        if (now - s_last_reap >= 3000) {
            s_last_reap = now;
            ULONGLONG timeout_thresh = (g_udp_map.size() > 40) ? 5000 : 12000;
            for (auto it = g_udp_map.begin(); it != g_udp_map.end(); ) {
                if (!it->second->alive.load() || (now - it->second->last_tick >= timeout_thresh)) {
                    it->second->alive.store(false);
                    if (it->second->v_stream) it->second->v_stream->close();
                    it = g_udp_map.erase(it);
                } else {
                    ++it;
                }
            }
        }

        auto it = g_udp_map.find(key);
        if (it != g_udp_map.end()) {
            sess = it->second;
            if (!sess->alive.load()) {
                if (sess->v_stream) sess->v_stream->close();
                g_udp_map.erase(it);
                sess.reset();
            }
        }

        if (!sess) {
            sess = std::make_shared<UdpNatSession>();
            sess->local_port = lport;
            sess->dst_ip = dst_ip;
            sess->dst_port = dst_port_net;
            sess->v_stream = nullptr;
            sess->alive.store(true);
            sess->last_tick = now;
            sess->session_key = key;
            g_udp_map[key] = sess;

            UdpInitArgs* args = new UdpInitArgs{ sess, std::vector<uint8_t>(payload, payload + payload_len) };
            uintptr_t h = _beginthreadex(nullptr, 65536, udp_session_worker, args, 0, nullptr);
            if (h) CloseHandle(reinterpret_cast<HANDLE>(h));
            return;
        }
    }

    if (sess && sess->alive.load() && sess->v_stream) {
        std::lock_guard<std::mutex> lk(sess->send_mtx);
        if (sess->alive.load() && sess->v_stream) {
            uint8_t buf[2048];
            if (g_cfg.outbound_proto == PROTO_TROJAN) {
                if (payload_len + 11 <= sizeof(buf)) {
                    int tlen = build_trojan_udp_packet(buf, sess->dst_ip, sess->dst_port, payload, payload_len);
                    g_TotalTx += payload_len;
                    if (!sess->v_stream->send_all(buf, tlen)) {
                        sess->alive.store(false);
                    } else {
                        sess->last_tick = GetTickCount64();
                    }
                }
            } else {
                uint16_t len_net = htons(payload_len);
                if (payload_len + 2 <= sizeof(buf)) {
                    std::memcpy(buf, &len_net, 2);
                    std::memcpy(buf + 2, payload, payload_len);
                    g_TotalTx += payload_len;
                    if (!sess->v_stream->send_all(buf, payload_len + 2)) {
                        sess->alive.store(false);
                    } else {
                        sess->last_tick = GetTickCount64();
                    }
                }
            }
        }
    }
}

static unsigned __stdcall tcp_listener_thread(void* arg) {
    SOCKET listen_sock = reinterpret_cast<SOCKET>(arg);
    while (g_TunnelRun) {
        sockaddr_in client_addr{}; int addr_len = sizeof(client_addr);
        SOCKET c_sock = accept(listen_sock, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
        if (c_sock == INVALID_SOCKET) break;
        uint16_t c_port = ntohs(client_addr.sin_port);
        NatEntry entry = g_nat_table[c_port];
        if (entry.orig_dst_ip == 0) {
            log_msg("tcp_listener: port %u has no NAT entry! Dropping.", c_port);
            closesocket(c_sock); continue;
        }
        log_msg("tcp_listener: ACCEPT port %u -> target %s:%u", c_port, mask_ip(entry.orig_dst_ip).c_str(), ntohs(entry.orig_dst_port));
        uintptr_t h = _beginthreadex(nullptr, 65536, tcp_session_thread, new SessionArgs{ c_sock, entry.orig_dst_ip, entry.orig_dst_port }, 0, nullptr);
        if (h) CloseHandle(reinterpret_cast<HANDLE>(h));
    }
    return 0;
}

static bool load_wintun_dll() {
    if (WintunCreateAdapter) return true;
    HMODULE mod = LoadLibraryExW(L"wintun.dll", nullptr, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!mod) return false;
    WintunCreateAdapter        = reinterpret_cast<fn_WintunCreateAdapter>(GetProcAddress(mod, "WintunCreateAdapter"));
    WintunOpenAdapter          = reinterpret_cast<fn_WintunOpenAdapter>(GetProcAddress(mod, "WintunOpenAdapter"));
    WintunCloseAdapter         = reinterpret_cast<fn_WintunCloseAdapter>(GetProcAddress(mod, "WintunCloseAdapter"));
    WintunGetAdapterLUID       = reinterpret_cast<fn_WintunGetAdapterLUID>(GetProcAddress(mod, "WintunGetAdapterLUID"));
    WintunStartSession         = reinterpret_cast<fn_WintunStartSession>(GetProcAddress(mod, "WintunStartSession"));
    WintunEndSession           = reinterpret_cast<fn_WintunEndSession>(GetProcAddress(mod, "WintunEndSession"));
    WintunGetReadWaitEvent     = reinterpret_cast<fn_WintunGetReadWaitEvent>(GetProcAddress(mod, "WintunGetReadWaitEvent"));
    WintunReceivePacket        = reinterpret_cast<fn_WintunReceivePacket>(GetProcAddress(mod, "WintunReceivePacket"));
    WintunReleaseReceivePacket = reinterpret_cast<fn_WintunReleaseReceivePacket>(GetProcAddress(mod, "WintunReleaseReceivePacket"));
    WintunAllocateSendPacket   = reinterpret_cast<fn_WintunAllocateSendPacket>(GetProcAddress(mod, "WintunAllocateSendPacket"));
    WintunSendPacket           = reinterpret_cast<fn_WintunSendPacket>(GetProcAddress(mod, "WintunSendPacket"));
    return WintunCreateAdapter && WintunStartSession && WintunReceivePacket && WintunSendPacket;
}

static int winhttp_generate_204_ping() {
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) NanoRay",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return -2;

    WinHttpSetTimeouts(hSession, 3000, 4000, 4000, 4000);

    HINTERNET hConnect = WinHttpConnect(hSession, L"www.google.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return -2;
    }

    HINTERNET hReq = WinHttpOpenRequest(hConnect, L"GET", L"/generate_204",
                                       nullptr, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       WINHTTP_FLAG_SECURE);
    if (!hReq) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -2;
    }

    if (g_cfg.vless_allow_insecure) {
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                      SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
    }

    ULONGLONG t0 = GetTickCount64();
    BOOL sent = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    int result = -2;
    if (sent && WinHttpReceiveResponse(hReq, nullptr)) {
        DWORD status = 0, sz = sizeof(status);
        if (WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX)) {
            if (status == 204 || status == 200) {
                result = static_cast<int>(GetTickCount64() - t0);
                if (result <= 0) result = 1;
            }
        }
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

static unsigned __stdcall ping_worker_thread(void*) {
    if (g_State.load() == STATE_CONNECTED) {
        int ms = winhttp_generate_204_ping();
        if (ms > 0) {
            g_LastPingMs = ms;
            request_flyout_repaint();
            return 0;
        }
    }

    AppConfig ping_cfg;
    {
        std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
        ping_cfg = g_cfg;
    }

    bool has_proxy = (ping_cfg.chain_type != CHAIN_NONE && !ping_cfg.chain_ip.empty() && ping_cfg.chain_port != 0);
    if (!ping_cfg.vless_valid && !has_proxy) {
        g_LastPingMs = -2;
        request_flyout_repaint();
        return 0;
    }

    if (g_PhysIfIndex == 0) {
        std::string gw;
        if (!find_physical_adapter(g_PhysIfIndex, gw)) GetBestInterface(inet_addr("8.8.8.8"), &g_PhysIfIndex);
    }

    ITransportStream* stream = nullptr;
    if (ping_cfg.vless_valid) {
        stream = dial_vless_transport(false, &ping_cfg);
    } else if (has_proxy) {
        SOCKET s = dial_proxy_to_dest(inet_addr("142.250.180.206"), htons(80), &ping_cfg); // www.google.com
        if (s != INVALID_SOCKET) stream = new TcpStream(s, true);
    }

    if (stream) {
        ULONGLONG t0 = GetTickCount64();
        bool ok = true;
        if (ping_cfg.vless_valid) {
            uint8_t hdr[128];
            int hlen = 0;
            if (ping_cfg.outbound_proto == PROTO_TROJAN) {
                hlen = build_trojan_header_domain(hdr, 0x01, "www.google.com", htons(80), ping_cfg.trojan_hash_hex);
            } else {
                hlen = build_vless_header_domain(hdr, 0x01, "www.google.com", htons(80), ping_cfg.vless_uuid, ping_cfg.vless_flow);
            }
            ok = stream->send_all(hdr, hlen);
        }
        if (ok) {
            const char req[] = "GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n";
            if (stream->send_all(req, sizeof(req) - 1)) {
                if (ping_cfg.vless_valid && ping_cfg.outbound_proto == PROTO_VLESS) {
                    uint8_t v_resp[2];
                    if (stream->recv_exact(v_resp, 2) && v_resp[1] > 0) {
                        uint8_t ad[256]; stream->recv_exact(ad, v_resp[1]);
                    }
                }
                char resp[512]{};
                int r = stream->recv_some(resp, sizeof(resp) - 1);
                if (r > 0 && (std::strstr(resp, " 204 ") || std::strstr(resp, " 200 "))) {
                    g_LastPingMs = static_cast<int>(GetTickCount64() - t0);
                    delete stream;
                    request_flyout_repaint();
                    return 0;
                }
            }
        }
        delete stream;
    }

    int ms = winhttp_generate_204_ping();
    g_LastPingMs = ms;
    request_flyout_repaint();
    return 0;
}

void trigger_async_ping() {
    uintptr_t h = _beginthreadex(nullptr, 65536, ping_worker_thread, nullptr, 0, nullptr);
    if (h) CloseHandle(reinterpret_cast<HANDLE>(h));
}

static HANDLE g_hMasterThread = nullptr;
static std::mutex g_master_thread_mtx;

void stop_tunnel(bool is_failure, const std::string& fail_msg) {
    g_TunnelRun = false;
    log_msg("Stopping tunnel... (is_failure=%d)", is_failure);
    if (g_ListenSock != INVALID_SOCKET) { closesocket(g_ListenSock); g_ListenSock = INVALID_SOCKET; }

    // Clear DNS cache
    {
        std::lock_guard<std::mutex> lk(g_dns_cache_mtx);
        g_dns_cache.clear();
    }

    // Instant native route removal
    native_delete_route(g_TunLuid, g_TunIfIndex, "0.0.0.0", 1, "10.66.66.2");
    native_delete_route(g_TunLuid, g_TunIfIndex, "128.0.0.0", 1, "10.66.66.2");
    native_delete_route(g_TunLuid, g_TunIfIndex, "1.1.1.1", 32, "10.66.66.2");
    native_delete_route(g_TunLuid, g_TunIfIndex, "8.8.8.8", 32, "10.66.66.2");

    NET_LUID zero_luid{};
    std::string v_ip = g_active_cfg.vless_resolved_ip.empty() ? resolve_to_ip_str(g_active_cfg.vless_ip) : g_active_cfg.vless_resolved_ip;
    if (!v_ip.empty()) {
        native_delete_route(zero_luid, g_PhysIfIndex, v_ip.c_str(), 32, g_PhysGateway.c_str());
    }
    std::string c_ip = g_active_cfg.chain_resolved_ip.empty() ? resolve_to_ip_str(g_active_cfg.chain_ip) : g_active_cfg.chain_resolved_ip;
    if (!c_ip.empty()) {
        native_delete_route(zero_luid, g_PhysIfIndex, c_ip.c_str(), 32, g_PhysGateway.c_str());
    }

    {
        std::lock_guard<std::mutex> lk(g_udp_table_mtx);
        for (auto& pair : g_udp_map) {
            if (pair.second) {
                pair.second->alive.store(false);
                if (pair.second->v_stream) pair.second->v_stream->close();
            }
        }
        g_udp_map.clear();
    }

    // Clean up firewall rules and IPv6 routes asynchronously to avoid blocking UI flyout thread
    std::wstring tun_alias = g_TunAlias;
    uintptr_t hClean = _beginthreadex(nullptr, 65536, [](void* arg) -> unsigned {
        std::wstring* pAlias = static_cast<std::wstring*>(arg);
        run_silent_cmd("netsh advfirewall firewall delete rule name=\"NanoRayRelay\"");
        if (pAlias && !pAlias->empty()) {
            char del_cmd[512];
            std::snprintf(del_cmd, sizeof(del_cmd), "netsh interface ipv6 delete route ::/1 \"%ls\"", pAlias->c_str());
            run_silent_cmd(del_cmd);
            std::snprintf(del_cmd, sizeof(del_cmd), "netsh interface ipv6 delete route 8000::/1 \"%ls\"", pAlias->c_str());
            run_silent_cmd(del_cmd);
        }
        delete pAlias;
        return 0;
    }, new std::wstring(tun_alias), 0, nullptr);
    if (hClean) CloseHandle(reinterpret_cast<HANDLE>(hClean));

    // Wait for packet loop / master thread to exit so g_Session is not accessed concurrently
    DWORD cur_tid = GetCurrentThreadId();
    DWORD master_tid = g_master_thread_id.load();
    if (cur_tid != master_tid) {
        HANDLE hMaster = nullptr;
        {
            std::lock_guard<std::mutex> lk(g_master_thread_mtx);
            hMaster = g_hMasterThread;
            g_hMasterThread = nullptr;
        }
        if (hMaster) {
            WaitForSingleObject(hMaster, 1500);
            CloseHandle(hMaster);
        }
    } else {
        std::lock_guard<std::mutex> lk(g_master_thread_mtx);
        if (g_hMasterThread) {
            CloseHandle(g_hMasterThread);
            g_hMasterThread = nullptr;
        }
    }

    {
        std::lock_guard<std::mutex> lock(g_TunTxMutex);
        if (g_Session) { WintunEndSession(g_Session); g_Session = nullptr; }
        if (g_Adapter) { WintunCloseAdapter(g_Adapter); g_Adapter = nullptr; }
    }
    if (is_failure) {
        g_State = STATE_FAILED;
        if (!fail_msg.empty()) set_status_msg(fail_msg);
    } else {
        if (g_State.load() != STATE_FAILED) {
            g_State = STATE_DISCONNECTED;
            set_status_msg("Tunnel stopped & system routes restored");
        }
    }
    g_LastPingMs = PING_IDLE;
    EmptyWorkingSet(GetCurrentProcess());
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
    log_msg("Tunnel stopped cleanly.");
    update_tray_icon();
    request_flyout_repaint();
}

static std::atomic<bool> g_StartingTunnel{ false };

static unsigned __stdcall tunnel_master_thread(void*) {
    g_master_thread_id.store(GetCurrentThreadId());
    struct TunnelMasterGuard {
        ~TunnelMasterGuard() {
            g_StartingTunnel.store(false);
            g_master_thread_id.store(0);
        }
    } master_guard;

    {
        std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
        g_active_cfg = g_cfg;
    }
    g_active_cfg.vless_resolved_ip = resolve_to_ip_str(g_active_cfg.vless_ip);
    g_active_cfg.chain_resolved_ip = resolve_to_ip_str(g_active_cfg.chain_ip);

    bool has_proxy = (g_active_cfg.chain_type != CHAIN_NONE && !g_active_cfg.chain_ip.empty() && g_active_cfg.chain_port != 0);
    if (!g_active_cfg.vless_valid && !has_proxy) {
        stop_tunnel(false);
        set_status_msg("Error: Configure a VLESS server or an Upstream Proxy");
        return 0;
    }
    if (g_active_cfg.chain_type != CHAIN_NONE && (g_active_cfg.chain_ip.empty() || g_active_cfg.chain_port == 0)) {
        if (g_active_cfg.chain_addr_str.empty()) {
            if (g_active_cfg.vless_valid) {
                log_msg("Upstream proxy mode selected but address is empty -> Auto-falling back to Direct.");
                g_active_cfg.chain_type = CHAIN_NONE;
                {
                    std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
                    g_cfg.chain_type = CHAIN_NONE;
                    save_config_ini();
                }
            } else {
                stop_tunnel(false);
                set_status_msg("Error: Upstream proxy address is empty");
                return 0;
            }
        } else {
            log_msg("Cannot start tunnel: Invalid upstream proxy address '%s'", g_active_cfg.chain_addr_str.c_str());
            stop_tunnel(true, "Invalid upstream proxy host:port");
            return 0;
        }
    }
    g_State = STATE_CONNECTING;
    set_status_msg("Detecting physical interface & loading Wintun...");
    update_tray_icon(); request_flyout_repaint();

    if (!g_TunnelRun) { stop_tunnel(false); return 0; }

    g_PhysGateway.clear();
    if (!find_physical_adapter(g_PhysIfIndex, g_PhysGateway)) {
        if (GetBestInterface(inet_addr("8.8.8.8"), &g_PhysIfIndex) != NO_ERROR) {
            stop_tunnel(true, "Error: No active physical internet connection!");
            return 0;
        }
    }
    log_msg("Physical interface: Index=%lu, Gateway=%s", g_PhysIfIndex, g_PhysGateway.c_str());

    if (!g_TunnelRun) { stop_tunnel(false); return 0; }

    if (!load_wintun_dll()) {
        stop_tunnel(true, "Error: wintun.dll missing next to executable!");
        return 0;
    }

    if (!g_TunnelRun) { stop_tunnel(false); return 0; }

    std::memset(g_nat_table, 0, sizeof(g_nat_table));
    GUID guid = { 0xdeadbeef, 0xcafe, 0xbabe, { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 } };
    g_Adapter = WintunCreateAdapter(L"NanoRayTun", L"NanoRay", &guid);
    if (!g_Adapter && WintunOpenAdapter) {
        g_Adapter = WintunOpenAdapter(L"NanoRayTun");
    }
    if (!g_Adapter) {
        log_msg("WintunCreateAdapter failed! Error=%lu", GetLastError());
        stop_tunnel(true, "Error: Run application as Administrator!");
        return 0;
    }

    if (!g_TunnelRun) { stop_tunnel(false); return 0; }

    NET_LUID tun_luid{};
    DWORD tun_if_index = 0;
    wchar_t tun_alias[256]{};
    if (WintunGetAdapterLUID) {
        WintunGetAdapterLUID(g_Adapter, &tun_luid);
        for (int i = 0; i < 40; ++i) {
            if (ConvertInterfaceLuidToIndex(&tun_luid, &tun_if_index) == NO_ERROR && tun_if_index != 0) {
                ConvertInterfaceLuidToAlias(&tun_luid, tun_alias, 256);
                break;
            }
            if (!g_TunnelRun) { stop_tunnel(false); return 0; }
            Sleep(100);
        }
    }
    if (tun_alias[0] == L'\0') wcscpy_s(tun_alias, L"NanoRayTun");
    g_TunLuid = tun_luid;
    g_TunIfIndex = tun_if_index;
    g_TunAlias = tun_alias;
    log_msg("Wintun adapter ready: if_index=%lu, alias=%ls", tun_if_index, tun_alias);

    if (!g_TunnelRun) { stop_tunnel(false); return 0; }

    g_Session = WintunStartSession(g_Adapter, 0x200000);
    if (!g_Session) {
        log_msg("WintunStartSession failed! Error=%lu", GetLastError());
        stop_tunnel(true, "Error: Failed to start Wintun ring buffer!");
        return 0;
    }

    if (!g_TunnelRun) { stop_tunnel(false); return 0; }

    set_status_msg("Configuring virtual adapter & system routes...");
    request_flyout_repaint();

    // 1. Configure IP on TUN adapter via native IP Helper API (< 1ms)
    MIB_UNICASTIPADDRESS_ROW ip_row{};
    InitializeUnicastIpAddressEntry(&ip_row);
    ip_row.InterfaceLuid = g_TunLuid;
    ip_row.Address.Ipv4.sin_family = AF_INET;
    ip_row.Address.Ipv4.sin_addr.s_addr = inet_addr(g_active_cfg.tun_ip_str);
    ip_row.OnLinkPrefixLength = 24;
    ip_row.DadState = IpDadStatePreferred;
    DWORD ip_res = CreateUnicastIpAddressEntry(&ip_row);
    log_msg("CreateUnicastIpAddressEntry returned %lu", ip_res);
    if (ip_res != NO_ERROR && ip_res != ERROR_OBJECT_ALREADY_EXISTS) {
        log_msg("Failed to assign IP 10.66.66.1 to TUN interface: error %lu", ip_res);
        stop_tunnel(true, "Error: Failed to configure TUN IP address");
        return 0;
    }

    if (!g_TunnelRun) { stop_tunnel(false); return 0; }

    // 2. Set interface metric to 1 natively via IP Helper API (< 1ms)
    MIB_IPINTERFACE_ROW if_row{};
    InitializeIpInterfaceEntry(&if_row);
    if_row.Family = AF_INET;
    if_row.InterfaceLuid = g_TunLuid;
    if (GetIpInterfaceEntry(&if_row) == NO_ERROR) {
        if_row.Metric = 1;
        SetIpInterfaceEntry(&if_row);
        log_msg("SetIpInterfaceEntry metric=1 success");
    }

    // 3. Asynchronously ensure DNS, firewall rules, and IPv6 leak prevention routes
    struct AsyncTunArgs { std::wstring alias; };
    AsyncTunArgs* aargs = new AsyncTunArgs{ g_TunAlias };
    uintptr_t hAsync = _beginthreadex(nullptr, 65536, [](void* p) -> unsigned {
        auto* a = static_cast<AsyncTunArgs*>(p);
        char cmd[512];
        std::snprintf(cmd, sizeof(cmd), "netsh interface ip set dns name=\"%ls\" static 1.1.1.1 validate=no", a->alias.c_str());
        run_silent_cmd(cmd);
        run_silent_cmd("netsh advfirewall firewall add rule name=\"NanoRayRelay\" dir=in action=allow localip=10.66.66.1 protocol=TCP localport=10888 profile=any");
        std::snprintf(cmd, sizeof(cmd), "netsh interface ipv6 add route ::/1 \"%ls\" metric=1", a->alias.c_str());
        run_silent_cmd(cmd);
        std::snprintf(cmd, sizeof(cmd), "netsh interface ipv6 add route 8000::/1 \"%ls\" metric=1", a->alias.c_str());
        run_silent_cmd(cmd);
        delete a;
        return 0;
    }, aargs, 0, nullptr);
    if (hAsync) CloseHandle(reinterpret_cast<HANDLE>(hAsync));

    if (!g_TunnelRun) { stop_tunnel(false); return 0; }

    // 4. Start local NAT listener specifically bound to TUN IP
    g_ListenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOL reuse = TRUE;
    setsockopt(g_ListenSock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
    int listen_buf = 262144;
    setsockopt(g_ListenSock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&listen_buf), sizeof(listen_buf));
    sockaddr_in laddr{}; laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = inet_addr(g_active_cfg.tun_ip_str);
    laddr.sin_port = htons(g_active_cfg.relay_port);
    if (bind(g_ListenSock, reinterpret_cast<sockaddr*>(&laddr), sizeof(laddr)) != 0 || listen(g_ListenSock, SOMAXCONN) != 0) {
        log_msg("Failed to bind local NAT listener: WSAError=%d", WSAGetLastError());
        stop_tunnel(true, "Error: Failed to bind local NAT listener");
        return 0;
    }

    if (!g_TunnelRun) { stop_tunnel(false); return 0; }

    uintptr_t hListener = _beginthreadex(nullptr, 65536, tcp_listener_thread, reinterpret_cast<void*>(g_ListenSock), 0, nullptr);
    if (hListener) CloseHandle(reinterpret_cast<HANDLE>(hListener));

    // 5. Direct host route bypass for VLESS endpoint & upstream proxy via native IP Helper API (< 1ms)
    std::string v_ip = g_active_cfg.vless_resolved_ip.empty() ? resolve_to_ip_str(g_active_cfg.vless_ip) : g_active_cfg.vless_resolved_ip;
    if (!g_PhysGateway.empty() && !v_ip.empty()) {
        NET_LUID zero_luid{};
        native_add_route(zero_luid, g_PhysIfIndex, v_ip.c_str(), 32, g_PhysGateway.c_str(), 1);
    }
    std::string c_ip = g_active_cfg.chain_resolved_ip.empty() ? resolve_to_ip_str(g_active_cfg.chain_ip) : g_active_cfg.chain_resolved_ip;
    if (!g_PhysGateway.empty() && g_active_cfg.chain_type != CHAIN_NONE && !c_ip.empty()) {
        NET_LUID zero_luid{};
        native_add_route(zero_luid, g_PhysIfIndex, c_ip.c_str(), 32, g_PhysGateway.c_str(), 1);
    }

    if (!g_TunnelRun) { stop_tunnel(false); return 0; }

    // 6. Fast native default routes into TUN interface (< 1ms)
    native_add_route(g_TunLuid, g_TunIfIndex, "0.0.0.0", 1, "10.66.66.2", 1);
    native_add_route(g_TunLuid, g_TunIfIndex, "128.0.0.0", 1, "10.66.66.2", 1);
    native_add_route(g_TunLuid, g_TunIfIndex, "1.1.1.1", 32, "10.66.66.2", 1);
    native_add_route(g_TunLuid, g_TunIfIndex, "8.8.8.8", 32, "10.66.66.2", 1);

    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);

    if (!g_TunnelRun) { stop_tunnel(false); return 0; }

    g_ConnectTick = GetTickCount64();
    g_State = STATE_CONNECTED;
    if (is_other_vpn_active()) {
        set_status_msg("Connected - NOTE: Disconnect other VPNs (Throne) to route traffic");
    } else {
        if (g_active_cfg.vless_valid) {
            set_status_msg("Connected - Routing all traffic via " + g_active_cfg.vless_remark);
        } else {
            std::string p_type = (g_active_cfg.chain_type == CHAIN_SOCKS5) ? "SOCKS5" : "HTTP";
            set_status_msg("Connected - Routing traffic via Upstream " + p_type + " (" + g_active_cfg.chain_ip + ":" + std::to_string(g_active_cfg.chain_port) + ")");
        }
    }
    log_msg("Tunnel active! Status: %s", get_status_msg().c_str());
    update_tray_icon(); request_flyout_repaint();

    uint32_t tun_ip_net = inet_addr(g_active_cfg.tun_ip_str), tun_peer_net = inet_addr(g_active_cfg.tun_peer_str);
    uint16_t relay_port_net = htons(g_active_cfg.relay_port);
    HANDLE wait_event = WintunGetReadWaitEvent(g_Session);

    while (g_TunnelRun) {
        DWORD pkt_size = 0;
        BYTE* pkt = WintunReceivePacket(g_Session, &pkt_size);
        if (!pkt) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) { WaitForSingleObject(wait_event, 40); continue; }
            break;
        }
        if (pkt_size >= 40 && (pkt[0] >> 4) == 6) {
            // Drop IPv6 traffic routed to TUN to force apps to fall back to IPv4 over proxy
            WintunReleaseReceivePacket(g_Session, pkt);
            continue;
        }
        if (pkt_size >= sizeof(IPv4Header) && (pkt[0] >> 4) == 4) {
            IPv4Header* ip = reinterpret_cast<IPv4Header*>(pkt);
            int ihl = (ip->ihl_ver & 0x0F) * 4;
            static uint32_t pkt_cnt = 0;
            uint32_t c = ++pkt_cnt;
            if (c <= 25 || (c % 200 == 0)) {
                log_msg("Wintun pkt #%u: proto=%u -> %s (len=%lu)", c, ip->protocol, mask_ip(ip->daddr).c_str(), pkt_size);
            }
            if (ip->protocol == IPPROTO_TCP && pkt_size >= static_cast<DWORD>(ihl + sizeof(TCPHeader))) {
                TCPHeader* tcp = reinterpret_cast<TCPHeader*>(pkt + ihl);
                if (ip->saddr == tun_ip_net && ip->daddr == tun_peer_net && tcp->source == relay_port_net) {
                    NatEntry entry = g_nat_table[ntohs(tcp->dest)];
                    if (entry.orig_dst_ip != 0) {
                        uint8_t out_buf[65536]; std::memcpy(out_buf, pkt, pkt_size);
                        IPv4Header* out_ip = reinterpret_cast<IPv4Header*>(out_buf);
                        TCPHeader* out_tcp = reinterpret_cast<TCPHeader*>(out_buf + ihl);
                        out_ip->saddr = entry.orig_dst_ip; out_ip->daddr = tun_ip_net; out_tcp->source = entry.orig_dst_port;
                        update_ipv4_checksum(out_ip); update_l4_checksum(out_ip, out_tcp, &out_tcp->check);
                        tun_send_packet(out_buf, pkt_size);
                    }
                } else if (ip->saddr == tun_ip_net && ip->daddr != tun_ip_net && ip->daddr != tun_peer_net) {
                    uint16_t app_port = ntohs(tcp->source);
                    g_nat_table[app_port].orig_dst_ip = ip->daddr;
                    g_nat_table[app_port].orig_dst_port = tcp->dest;
                    uint8_t out_buf[65536]; std::memcpy(out_buf, pkt, pkt_size);
                    IPv4Header* out_ip = reinterpret_cast<IPv4Header*>(out_buf);
                    TCPHeader* out_tcp = reinterpret_cast<TCPHeader*>(out_buf + ihl);
                    out_ip->saddr = tun_peer_net; out_ip->daddr = tun_ip_net; out_tcp->dest = relay_port_net;
                    update_ipv4_checksum(out_ip); update_l4_checksum(out_ip, out_tcp, &out_tcp->check);
                    tun_send_packet(out_buf, pkt_size);
                }
            } else if (ip->protocol == IPPROTO_UDP && pkt_size >= static_cast<DWORD>(ihl + sizeof(UDPHeader))) {
                UDPHeader* udp = reinterpret_cast<UDPHeader*>(pkt + ihl);
                if (ntohs(udp->dest) == 53) {
                    int ulen = pkt_size - (ihl + sizeof(UDPHeader));
                    if (ulen > 0 && ulen <= 1400) {
                        if (g_active_dns_workers.load() < 16) {
                            g_active_dns_workers.fetch_add(1);
                            DnsJob* job = new DnsJob{ ip->saddr, ip->daddr, udp->source, udp->dest, static_cast<uint16_t>(ulen), {} };
                            std::memcpy(job->payload, pkt + ihl + sizeof(UDPHeader), ulen);
                            uintptr_t hDns = _beginthreadex(nullptr, 65536, dns_hijack_worker, job, 0, nullptr);
                            if (hDns) {
                                CloseHandle(reinterpret_cast<HANDLE>(hDns));
                            } else {
                                delete job;
                                g_active_dns_workers.fetch_sub(1);
                            }
                        }
                    }
                } else if (ip->saddr == tun_ip_net) {
                    int ulen = pkt_size - (ihl + sizeof(UDPHeader));
                    if (ulen > 0 && ulen <= 1460) {
                        handle_udp_packet(udp->source, ip->daddr, udp->dest, pkt + ihl + sizeof(UDPHeader), static_cast<uint16_t>(ulen));
                    }
                }
            }
        }
        WintunReleaseReceivePacket(g_Session, pkt);
    }

    if (g_TunnelRun) {
        log_msg("Wintun packet loop exited unexpectedly (error=%lu). Stopping tunnel to restore routes.", GetLastError());
        stop_tunnel();
    }
    return 0;
}

void start_tunnel_async() {
    if (g_State.load() == STATE_CONNECTED || g_State.load() == STATE_CONNECTING) return;
    bool expected = false;
    if (!g_StartingTunnel.compare_exchange_strong(expected, true)) return;
    g_TunnelRun = true;
    std::lock_guard<std::mutex> lk(g_master_thread_mtx);
    if (g_hMasterThread) {
        CloseHandle(g_hMasterThread);
        g_hMasterThread = nullptr;
    }
    g_hMasterThread = reinterpret_cast<HANDLE>(_beginthreadex(nullptr, 65536, tunnel_master_thread, nullptr, 0, nullptr));
}