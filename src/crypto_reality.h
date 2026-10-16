#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace reality {

// ---------------------------------------------------------------------------
// 1. SHA-256 & HMAC-SHA256 & HKDF-SHA256
// ---------------------------------------------------------------------------
static inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

struct SHA256_CTX {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
};

static void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    uint32_t W[64];
    for (int i = 0; i < 16; ++i) {
        W[i] = (static_cast<uint32_t>(data[i * 4]) << 24) |
               (static_cast<uint32_t>(data[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(data[i * 4 + 2]) << 8) |
               (static_cast<uint32_t>(data[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint32_t s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static inline void sha256_init(SHA256_CTX* ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static inline void sha256_update(SHA256_CTX* ctx, const void* data, size_t len) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(data);
    size_t idx = static_cast<size_t>(ctx->count & 63);
    ctx->count += len;
    while (len > 0) {
        size_t part = 64 - idx;
        if (part > len) part = len;
        std::memcpy(ctx->buf + idx, p, part);
        p += part; len -= part; idx += part;
        if (idx == 64) {
            sha256_transform(ctx->state, ctx->buf);
            idx = 0;
        }
    }
}

static inline void sha256_final(SHA256_CTX* ctx, uint8_t out[32]) {
    uint64_t bits = ctx->count * 8;
    uint8_t pad = 0x80;
    sha256_update(ctx, &pad, 1);
    uint8_t zero = 0;
    while ((ctx->count & 63) != 56) sha256_update(ctx, &zero, 1);
    uint8_t len_bytes[8];
    for (int i = 0; i < 8; ++i) len_bytes[i] = static_cast<uint8_t>((bits >> ((7 - i) * 8)) & 0xFF);
    sha256_update(ctx, len_bytes, 8);
    for (int i = 0; i < 8; ++i) {
        out[i * 4]     = static_cast<uint8_t>((ctx->state[i] >> 24) & 0xFF);
        out[i * 4 + 1] = static_cast<uint8_t>((ctx->state[i] >> 16) & 0xFF);
        out[i * 4 + 2] = static_cast<uint8_t>((ctx->state[i] >> 8) & 0xFF);
        out[i * 4 + 3] = static_cast<uint8_t>(ctx->state[i] & 0xFF);
    }
}

static inline void sha256(const void* data, size_t len, uint8_t out[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

static inline void sha224_init(SHA256_CTX* ctx) {
    ctx->state[0] = 0xc1059ed8; ctx->state[1] = 0x367cd507;
    ctx->state[2] = 0x3070dd17; ctx->state[3] = 0xf70e5939;
    ctx->state[4] = 0xffc00b31; ctx->state[5] = 0x68581511;
    ctx->state[6] = 0x64f98fa7; ctx->state[7] = 0xbefa4fa4;
    ctx->count = 0;
}

static inline void sha224_final(SHA256_CTX* ctx, uint8_t out[28]) {
    uint64_t bits = ctx->count * 8;
    uint8_t pad = 0x80;
    sha256_update(ctx, &pad, 1);
    uint8_t zero = 0;
    while ((ctx->count & 63) != 56) sha256_update(ctx, &zero, 1);
    uint8_t len_bytes[8];
    for (int i = 0; i < 8; ++i) len_bytes[i] = static_cast<uint8_t>((bits >> ((7 - i) * 8)) & 0xFF);
    sha256_update(ctx, len_bytes, 8);
    for (int i = 0; i < 7; ++i) {
        out[i * 4]     = static_cast<uint8_t>((ctx->state[i] >> 24) & 0xFF);
        out[i * 4 + 1] = static_cast<uint8_t>((ctx->state[i] >> 16) & 0xFF);
        out[i * 4 + 2] = static_cast<uint8_t>((ctx->state[i] >> 8) & 0xFF);
        out[i * 4 + 3] = static_cast<uint8_t>(ctx->state[i] & 0xFF);
    }
}

static inline void sha224(const void* data, size_t len, uint8_t out[28]) {
    SHA256_CTX ctx;
    sha224_init(&ctx);
    sha256_update(&ctx, data, len);
    sha224_final(&ctx, out);
}

static inline std::string sha224_hex(const std::string& input) {
    uint8_t d[28];
    sha224(input.data(), input.size(), d);
    char hex[57];
    for (int i = 0; i < 28; ++i) {
        std::sprintf(hex + i * 2, "%02x", d[i]);
    }
    hex[56] = '\0';
    return std::string(hex, 56);
}

static inline void hmac_sha256(const void* key, size_t key_len, const void* data, size_t data_len, uint8_t out[32]) {
    uint8_t k[64]{};
    if (key_len > 64) {
        sha256(key, key_len, k);
    } else {
        std::memcpy(k, key, key_len);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }
    uint8_t inner[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, out);
}

static inline void hkdf_extract(const void* salt, size_t salt_len, const void* ikm, size_t ikm_len, uint8_t prk[32]) {
    static const uint8_t zero_salt[32] = { 0 };
    if (!salt || salt_len == 0) { salt = zero_salt; salt_len = 32; }
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

static inline void hkdf_expand(const uint8_t prk[32], const void* info, size_t info_len, uint8_t* okm, size_t okm_len) {
    uint8_t t[32]{};
    size_t generated = 0;
    uint8_t counter = 1;

    while (generated < okm_len) {
        SHA256_CTX ctx;
        uint8_t k[64]{};
        std::memcpy(k, prk, 32);
        uint8_t ipad[64], opad[64];
        for (int i = 0; i < 64; ++i) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5C; }

        uint8_t inner[32];
        sha256_init(&ctx);
        sha256_update(&ctx, ipad, 64);
        if (counter > 1) sha256_update(&ctx, t, 32);
        if (info && info_len > 0) sha256_update(&ctx, info, info_len);
        sha256_update(&ctx, &counter, 1);
        sha256_final(&ctx, inner);

        sha256_init(&ctx);
        sha256_update(&ctx, opad, 64);
        sha256_update(&ctx, inner, 32);
        sha256_final(&ctx, t);

        size_t chunk = (okm_len - generated < 32) ? (okm_len - generated) : 32;
        std::memcpy(okm + generated, t, chunk);
        generated += chunk;
        counter++;
    }
}

static inline void hkdf(const void* salt, size_t salt_len, const void* ikm, size_t ikm_len,
                        const void* info, size_t info_len, uint8_t* okm, size_t okm_len) {
    uint8_t prk[32];
    hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    hkdf_expand(prk, info, info_len, okm, okm_len);
}

// ---------------------------------------------------------------------------
// 2. Base64 URL / Standard Decoder
// ---------------------------------------------------------------------------
static inline int b64_char_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

static inline std::vector<uint8_t> base64_decode(const std::string& in) {
    std::vector<uint8_t> out;
    int val = 0, valb = -8;
    for (char c : in) {
        if (c == '=' || c == ' ' || c == '\r' || c == '\n') continue;
        int d = b64_char_val(c);
        if (d < 0) continue;
        val = (val << 6) | d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

static inline std::vector<uint8_t> hex_decode(const std::string& in) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < in.size(); i += 2) {
        auto hex_nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = hex_nibble(in[i]), lo = hex_nibble(in[i + 1]);
        if (hi >= 0 && lo >= 0) {
            out.push_back(static_cast<uint8_t>((hi << 4) | lo));
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// 3. Curve25519 (X25519) Public Key Function
// ---------------------------------------------------------------------------
} // namespace reality

extern "C" {
#include "curve25519.c"
}

namespace reality {

static inline void x25519(uint8_t out[32], const uint8_t secret[32], const uint8_t point[32]) {
    curve25519_donna(out, secret, point);
}

static inline void x25519_base(uint8_t out[32], const uint8_t secret[32]) {
    static const uint8_t base[32] = {9};
    curve25519_donna(out, secret, base);
}

// ---------------------------------------------------------------------------
// 4. AES-128-GCM (via Windows CNG / bcrypt.dll)
// ---------------------------------------------------------------------------
static inline bool aes_gcm_encrypt(
    const uint8_t key[16], const uint8_t nonce[12],
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext, uint8_t tag[16]) {

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status < 0) return false;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key, 16, 0);
    if (status < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = 12;
    authInfo.pbAuthData = (PUCHAR)aad;
    authInfo.cbAuthData = (ULONG)aad_len;
    authInfo.pbTag = tag;
    authInfo.cbTag = 16;

    ULONG cbResult = 0;
    status = BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)pt_len, &authInfo, nullptr, 0,
                           ciphertext, (ULONG)pt_len, &cbResult, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return (status >= 0);
}

static inline bool aes_gcm_decrypt(
    const uint8_t key[16], const uint8_t nonce[12],
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t tag[16],
    const uint8_t* aad, size_t aad_len,
    uint8_t* plaintext) {

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status < 0) return false;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key, 16, 0);
    if (status < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = 12;
    authInfo.pbAuthData = (PUCHAR)aad;
    authInfo.cbAuthData = (ULONG)aad_len;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = 16;

    ULONG cbResult = 0;
    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext, (ULONG)ct_len, &authInfo, nullptr, 0,
                           plaintext, (ULONG)ct_len, &cbResult, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return (status >= 0);
}

// ---------------------------------------------------------------------------
// 5. RFC 8446 TLS 1.3 Key Schedule Utilities
// ---------------------------------------------------------------------------
static inline void hkdf_expand_label(
    const uint8_t secret[32],
    const char* label,
    const uint8_t* context, size_t context_len,
    uint8_t* out, size_t out_len)
{
    std::vector<uint8_t> hkdf_label;
    hkdf_label.push_back(static_cast<uint8_t>((out_len >> 8) & 0xFF));
    hkdf_label.push_back(static_cast<uint8_t>(out_len & 0xFF));

    std::string full_label = std::string("tls13 ") + label;
    hkdf_label.push_back(static_cast<uint8_t>(full_label.size()));
    hkdf_label.insert(hkdf_label.end(), full_label.begin(), full_label.end());

    hkdf_label.push_back(static_cast<uint8_t>(context_len));
    if (context && context_len > 0) {
        hkdf_label.insert(hkdf_label.end(), context, context + context_len);
    }

    hkdf_expand(secret, hkdf_label.data(), hkdf_label.size(), out, out_len);
}

static inline void derive_secret(
    const uint8_t secret[32],
    const char* label,
    const uint8_t* transcript_hash,
    uint8_t out[32])
{
    static const uint8_t empty_hash[32] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
    };
    const uint8_t* ctx = transcript_hash ? transcript_hash : empty_hash;
    hkdf_expand_label(secret, label, ctx, 32, out, 32);
}

} // namespace reality

