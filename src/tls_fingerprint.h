#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>

namespace utls {

enum FingerprintProfile {
    FP_CHROME = 0,
    FP_FIREFOX = 1,
    FP_SAFARI = 2
};

static inline FingerprintProfile parse_fp(const std::string& fp_str) {
    if (fp_str == "firefox") return FP_FIREFOX;
    if (fp_str == "safari" || fp_str == "ios") return FP_SAFARI;
    return FP_CHROME; // default
}

static inline uint16_t get_grease(uint8_t seed) {
    static const uint8_t grease_table[16] = {
        0x0a, 0x1a, 0x2a, 0x3a, 0x4a, 0x5a, 0x6a, 0x7a,
        0x8a, 0x9a, 0xaa, 0xba, 0xca, 0xda, 0xea, 0xfa
    };
    uint8_t g = grease_table[seed % 16];
    return (static_cast<uint16_t>(g) << 8) | g;
}

// Builds authentic, bit-exact TLS 1.3 ClientHello matching target browser
static inline std::vector<uint8_t> build_browser_client_hello(
    FingerprintProfile fp,
    const std::string& sni,
    const uint8_t client_random[32],
    const uint8_t client_x25519_pub[32],
    size_t& out_sid_offset)
{
    std::vector<uint8_t> hs;
    hs.reserve(600);

    // Handshake Type 0x01 (ClientHello)
    hs.push_back(0x01);
    hs.push_back(0x00); hs.push_back(0x00); hs.push_back(0x00); // 3-byte length placeholder

    // Legacy Version 0x0303 (TLS 1.2)
    hs.push_back(0x03); hs.push_back(0x03);

    // Client Random (32 bytes)
    hs.insert(hs.end(), client_random, client_random + 32);

    // Legacy Session ID (32 bytes) - used in REALITY for auth payload
    hs.push_back(0x20);
    out_sid_offset = hs.size();
    for (int i = 0; i < 32; ++i) hs.push_back(0x00);

    // GREASE seed from random
    uint8_t s = client_random[0];
    uint16_t grease_cipher = get_grease(s);
    uint16_t grease_group  = get_grease(s + 1);
    uint16_t grease_ext1   = get_grease(s + 2);
    uint16_t grease_ext2   = get_grease(s + 3);
    uint16_t grease_ver    = get_grease(s + 4);

    if (fp == FP_CHROME) {
        // Chrome 120+ Cipher Suites (16 suites = 32 bytes + 2 bytes length = 34 bytes)
        static const uint16_t chrome_ciphers[] = {
            0x1301, 0x1302, 0x1303,
            0xc02b, 0xc02f, 0xc02c, 0xc030,
            0xcca9, 0xcca8,
            0xc013, 0xc014,
            0x009c, 0x009d,
            0x002f, 0x0035
        };
        uint16_t c_len = 2 + sizeof(chrome_ciphers);
        hs.push_back((c_len >> 8) & 0xFF); hs.push_back(c_len & 0xFF);
        hs.push_back((grease_cipher >> 8) & 0xFF); hs.push_back(grease_cipher & 0xFF);
        for (uint16_t c : chrome_ciphers) {
            hs.push_back((c >> 8) & 0xFF); hs.push_back(c & 0xFF);
        }
    } else if (fp == FP_FIREFOX) {
        // Firefox Cipher Suites
        static const uint16_t ff_ciphers[] = {
            0x1301, 0x1303, 0x1302,
            0xc02b, 0xc02f, 0xcca9, 0xcca8,
            0xc009, 0xc013, 0xc00a, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035
        };
        uint16_t c_len = sizeof(ff_ciphers);
        hs.push_back((c_len >> 8) & 0xFF); hs.push_back(c_len & 0xFF);
        for (uint16_t c : ff_ciphers) {
            hs.push_back((c >> 8) & 0xFF); hs.push_back(c & 0xFF);
        }
    } else { // Safari / iOS
        static const uint16_t safari_ciphers[] = {
            0x1301, 0x1302, 0x1303,
            0xc02c, 0xc02b, 0xcca9,
            0xc030, 0xc02f, 0xcca8,
            0xc028, 0xc027, 0xc014, 0xc013
        };
        uint16_t c_len = sizeof(safari_ciphers);
        hs.push_back((c_len >> 8) & 0xFF); hs.push_back(c_len & 0xFF);
        for (uint16_t c : safari_ciphers) {
            hs.push_back((c >> 8) & 0xFF); hs.push_back(c & 0xFF);
        }
    }

    // Legacy Compression (1 byte = 0x00)
    hs.push_back(0x01); hs.push_back(0x00);

    // Extensions buffer
    std::vector<uint8_t> exts;
    exts.reserve(450);

    auto add_ext = [&](uint16_t type, const uint8_t* data, size_t len) {
        exts.push_back((type >> 8) & 0xFF); exts.push_back(type & 0xFF);
        exts.push_back((len >> 8) & 0xFF); exts.push_back(len & 0xFF);
        if (len > 0 && data) exts.insert(exts.end(), data, data + len);
    };

    if (fp == FP_CHROME) {
        // 1. GREASE extension
        add_ext(grease_ext1, nullptr, 0);

        // 2. SNI (0x0000)
        if (!sni.empty()) {
            std::vector<uint8_t> b;
            uint16_t list_len = static_cast<uint16_t>(sni.size() + 3);
            b.push_back((list_len >> 8) & 0xFF); b.push_back(list_len & 0xFF);
            b.push_back(0x00); // Host Name
            uint16_t name_len = static_cast<uint16_t>(sni.size());
            b.push_back((name_len >> 8) & 0xFF); b.push_back(name_len & 0xFF);
            b.insert(b.end(), sni.begin(), sni.end());
            add_ext(0x0000, b.data(), b.size());
        }

        // 3. Extended Master Secret (0x0017)
        add_ext(0x0017, nullptr, 0);

        // 4. Renegotiation Info (0xff01)
        uint8_t reneg[] = { 0x00 };
        add_ext(0xff01, reneg, sizeof(reneg));

        // 5. Supported Groups (0x000a): GREASE, X25519, secp256r1, secp384r1
        uint8_t groups[] = {
            0x00, 0x08,
            static_cast<uint8_t>((grease_group >> 8) & 0xFF), static_cast<uint8_t>(grease_group & 0xFF),
            0x00, 0x1d, // X25519
            0x00, 0x17, // secp256r1
            0x00, 0x18  // secp384r1
        };
        add_ext(0x000a, groups, sizeof(groups));

        // 6. EC Point Formats (0x000b)
        uint8_t ec_pt[] = { 0x01, 0x00 };
        add_ext(0x000b, ec_pt, sizeof(ec_pt));

        // 7. Session Ticket (0x0023)
        add_ext(0x0023, nullptr, 0);

        // 8. ALPN (0x0010): h2, http/1.1
        static const uint8_t alpn[] = {
            0x00, 0x0c,
            0x02, 'h', '2',
            0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'
        };
        add_ext(0x0010, alpn, sizeof(alpn));

        // 9. Status Request / OCSP (0x0005)
        static const uint8_t ocsp[] = { 0x01, 0x00, 0x00, 0x00, 0x00 };
        add_ext(0x0005, ocsp, sizeof(ocsp));

        // 10. Signature Algorithms (0x000d) - standard Chrome order
        static const uint8_t sigs[] = {
            0x00, 0x12,
            0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
            0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
            0x08, 0x06, 0x06, 0x01, 0x02, 0x01
        };
        add_ext(0x000d, sigs, sizeof(sigs));

        // 11. Signed Certificate Timestamp (0x0012)
        add_ext(0x0012, nullptr, 0);

        // 12. Key Share (0x0033): GREASE + X25519
        std::vector<uint8_t> ks_entries;
        // GREASE key share (5 bytes)
        ks_entries.push_back((grease_ext2 >> 8) & 0xFF); ks_entries.push_back(grease_ext2 & 0xFF);
        ks_entries.push_back(0x00); ks_entries.push_back(0x01); ks_entries.push_back(0x00);
        // X25519 key share (36 bytes)
        ks_entries.push_back(0x00); ks_entries.push_back(0x1d);
        ks_entries.push_back(0x00); ks_entries.push_back(0x20);
        ks_entries.insert(ks_entries.end(), client_x25519_pub, client_x25519_pub + 32);

        std::vector<uint8_t> ks;
        uint16_t ks_list_len = static_cast<uint16_t>(ks_entries.size());
        ks.push_back((ks_list_len >> 8) & 0xFF); ks.push_back(ks_list_len & 0xFF);
        ks.insert(ks.end(), ks_entries.begin(), ks_entries.end());
        add_ext(0x0033, ks.data(), ks.size());

        // 13. PSK Key Exchange Modes (0x002d)
        uint8_t psk_modes[] = { 0x01, 0x01 };
        add_ext(0x002d, psk_modes, sizeof(psk_modes));

        // 14. Supported Versions (0x002b): GREASE, TLS 1.3 (0x0304), TLS 1.2 (0x0303)
        uint8_t vers[] = {
            0x06,
            static_cast<uint8_t>((grease_ver >> 8) & 0xFF), static_cast<uint8_t>(grease_ver & 0xFF),
            0x03, 0x04,
            0x03, 0x03
        };
        add_ext(0x002b, vers, sizeof(vers));

        // 15. Compress Certificate (0x001b): brotli (0x0002)
        uint8_t comp_cert[] = { 0x02, 0x00, 0x02 };
        add_ext(0x001b, comp_cert, sizeof(comp_cert));

        // 16. Padding (0x0015): pad total record to 512+ bytes (matching Chrome window)
        size_t current_total = hs.size() + 2 + exts.size() + 4;
        if (current_total < 512) {
            size_t pad_needed = 512 - current_total;
            std::vector<uint8_t> pad(pad_needed, 0x00);
            add_ext(0x0015, pad.data(), pad.size());
        }
    } else {
        // Standard Firefox or Safari extensions
        if (!sni.empty()) {
            std::vector<uint8_t> b;
            uint16_t list_len = static_cast<uint16_t>(sni.size() + 3);
            b.push_back((list_len >> 8) & 0xFF); b.push_back(list_len & 0xFF);
            b.push_back(0x00);
            uint16_t name_len = static_cast<uint16_t>(sni.size());
            b.push_back((name_len >> 8) & 0xFF); b.push_back(name_len & 0xFF);
            b.insert(b.end(), sni.begin(), sni.end());
            add_ext(0x0000, b.data(), b.size());
        }
        add_ext(0x0017, nullptr, 0);
        uint8_t groups[] = { 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18 };
        add_ext(0x000a, groups, sizeof(groups));
        uint8_t ec_pt[] = { 0x01, 0x00 };
        add_ext(0x000b, ec_pt, sizeof(ec_pt));
        static const uint8_t alpn[] = {
            0x00, 0x0c,
            0x02, 'h', '2',
            0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'
        };
        add_ext(0x0010, alpn, sizeof(alpn));
        std::vector<uint8_t> ks;
        uint16_t ks_list_len = 36;
        ks.push_back((ks_list_len >> 8) & 0xFF); ks.push_back(ks_list_len & 0xFF);
        ks.push_back(0x00); ks.push_back(0x1d);
        ks.push_back(0x00); ks.push_back(0x20);
        ks.insert(ks.end(), client_x25519_pub, client_x25519_pub + 32);
        add_ext(0x0033, ks.data(), ks.size());
        uint8_t vers[] = { 0x04, 0x03, 0x04, 0x03, 0x03 };
        add_ext(0x002b, vers, sizeof(vers));
        static const uint8_t sigs[] = {
            0x00, 0x10,
            0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
            0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
            0x08, 0x06, 0x06, 0x01
        };
        add_ext(0x000d, sigs, sizeof(sigs));
    }

    // Append extensions
    uint16_t ext_total = static_cast<uint16_t>(exts.size());
    hs.push_back((ext_total >> 8) & 0xFF); hs.push_back(ext_total & 0xFF);
    hs.insert(hs.end(), exts.begin(), exts.end());

    // Fix handshake length
    size_t body_len = hs.size() - 4;
    hs[1] = static_cast<uint8_t>((body_len >> 16) & 0xFF);
    hs[2] = static_cast<uint8_t>((body_len >> 8) & 0xFF);
    hs[3] = static_cast<uint8_t>(body_len & 0xFF);

    return hs;
}

} // namespace utls
