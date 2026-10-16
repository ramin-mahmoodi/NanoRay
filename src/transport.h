#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <winsock2.h>
#include <windows.h>
#include <security.h>
#include <schnlsp.h>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <cctype>
#include <mutex>
#include "crypto_reality.h"
#include "tls_fingerprint.h"

// Abstract stream for transport protocols (TCP, TLS, WebSocket)
class ITransportStream {
public:
    virtual ~ITransportStream() = default;
    virtual bool send_all(const void* buf, int len) = 0;
    virtual int recv_some(void* buf, int max_len) = 0;
    virtual void close() = 0;

    virtual bool recv_exact(void* buf, int len) {
        uint8_t* p = reinterpret_cast<uint8_t*>(buf);
        int total = 0;
        while (total < len) {
            int n = recv_some(p + total, len - total);
            if (n <= 0) return false;
            total += n;
        }
        return true;
    }

    virtual ITransportStream* unwrap_vision() { return this; }
    virtual void shutdown_send() {}
    virtual void set_rcv_timeout(int /*timeout_ms*/) {}
};

// Plain TCP stream wrapping a standard SOCKET
class TcpStream : public ITransportStream {
private:
    SOCKET m_sock;
    bool   m_own;
public:
    explicit TcpStream(SOCKET s, bool own = true) : m_sock(s), m_own(own) {}
    ~TcpStream() override { close(); }

    bool send_all(const void* buf, int len) override {
        const char* p = reinterpret_cast<const char*>(buf);
        int sent = 0;
        while (sent < len) {
            int n = ::send(m_sock, p + sent, len - sent, 0);
            if (n <= 0) return false;
            sent += n;
        }
        return true;
    }

    int recv_some(void* buf, int max_len) override {
        if (m_sock == INVALID_SOCKET) return -1;
        return ::recv(m_sock, reinterpret_cast<char*>(buf), max_len, 0);
    }

    void close() override {
        if (m_own && m_sock != INVALID_SOCKET) {
            ::closesocket(m_sock);
            m_sock = INVALID_SOCKET;
        }
    }

    void set_rcv_timeout(int timeout_ms) override {
        if (m_sock != INVALID_SOCKET) {
            DWORD tv = static_cast<DWORD>(timeout_ms);
            setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
        }
    }

    void shutdown_send() override {
        if (m_sock != INVALID_SOCKET) {
            ::shutdown(m_sock, SD_SEND);
        }
    }

    SOCKET get_socket() const { return m_sock; }
};

// Native Windows TLS stream using Schannel (secur32.dll)
class SchannelStream : public ITransportStream {
private:
    ITransportStream* m_underlying;
    std::string       m_sni;
    CredHandle        m_hCred{};
    CtxtHandle        m_hCtx{};
    bool              m_cred_valid = false;
    bool              m_ctx_valid  = false;
    SecPkgContext_StreamSizes m_sizes{};

    std::vector<uint8_t> m_enc_buf;
    std::vector<uint8_t> m_dec_queue;
    bool              m_allow_insecure = false;
    std::mutex        m_op_mtx;

public:
    SchannelStream(ITransportStream* underlying, const std::string& sni, bool allow_insecure = false)
        : m_underlying(underlying), m_sni(sni), m_allow_insecure(allow_insecure) {
        std::memset(&m_hCred, 0, sizeof(m_hCred));
        std::memset(&m_hCtx, 0, sizeof(m_hCtx));
        std::memset(&m_sizes, 0, sizeof(m_sizes));
    }

    ~SchannelStream() override {
        close();
        delete m_underlying;
    }

    bool handshake() {
#ifndef SP_PROT_TLS1_3_CLIENT
#define SP_PROT_TLS1_3_CLIENT 0x00002000
#endif
#ifndef SCH_CREDENTIALS_VERSION
#define SCH_CREDENTIALS_VERSION 0x00000005
#endif
        TimeStamp tsExpiry{};
        SECURITY_STATUS status = SEC_E_INTERNAL_ERROR;

        struct NativeSchCredentials {
            DWORD dwVersion = 5; // SCH_CREDENTIALS_VERSION
            DWORD dwCredFormat = 0;
            DWORD cCreds = 0;
            void** paCred = nullptr;
            HCERTSTORE hRootStore = nullptr;
            DWORD cMappers = 0;
            void** aphMappers = nullptr;
            DWORD dwSessionLifespan = 0;
            DWORD dwFlags = 0;
            DWORD cTlsParameters = 0;
            void* pTlsParameters = nullptr;
        } creds;
        creds.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;
        if (m_allow_insecure) {
            creds.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_IGNORE_NO_REVOCATION_CHECK | SCH_CRED_IGNORE_REVOCATION_OFFLINE;
        }

        status = AcquireCredentialsHandleW(
            nullptr, (SEC_WCHAR*)UNISP_NAME_W, SECPKG_CRED_OUTBOUND,
            nullptr, &creds, nullptr, nullptr, &m_hCred, &tsExpiry);

        if (status != SEC_E_OK) {
            SCHANNEL_CRED sc{};
            sc.dwVersion = SCHANNEL_CRED_VERSION;
            sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
            sc.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;
            if (m_allow_insecure) {
                sc.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_IGNORE_NO_REVOCATION_CHECK | SCH_CRED_IGNORE_REVOCATION_OFFLINE;
            }

            status = AcquireCredentialsHandleW(
                nullptr, (SEC_WCHAR*)L"Schannel", SECPKG_CRED_OUTBOUND,
                nullptr, &sc, nullptr, nullptr, &m_hCred, &tsExpiry);
            if (status != SEC_E_OK) return false;
        }
        m_cred_valid = true;

        std::wstring wsni(m_sni.begin(), m_sni.end());
        DWORD reqFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                         ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
        DWORD retFlags = 0;

        SecBuffer outBuf{ 0, SECBUFFER_TOKEN, nullptr };
        SecBufferDesc outDesc{ SECBUFFER_VERSION, 1, &outBuf };

        status = InitializeSecurityContextW(
            &m_hCred, nullptr, (SEC_WCHAR*)wsni.c_str(), reqFlags, 0, 0,
            nullptr, 0, &m_hCtx, &outDesc, &retFlags, &tsExpiry);

        if (status != SEC_I_CONTINUE_NEEDED) return false;
        m_ctx_valid = true;

        if (outBuf.cbBuffer > 0 && outBuf.pvBuffer) {
            bool sent = m_underlying->send_all(outBuf.pvBuffer, outBuf.cbBuffer);
            FreeContextBuffer(outBuf.pvBuffer);
            outBuf.pvBuffer = nullptr;
            if (!sent) return false;
        }

        std::vector<uint8_t> inBuf(32768);
        int inLen = 0;

        while (true) {
            int n = m_underlying->recv_some(inBuf.data() + inLen, (int)inBuf.size() - inLen);
            if (n <= 0) return false;
            inLen += n;

            SecBuffer inBuffers[2];
            inBuffers[0] = { (DWORD)inLen, SECBUFFER_TOKEN, inBuf.data() };
            inBuffers[1] = { 0, SECBUFFER_EMPTY, nullptr };
            SecBufferDesc inDesc{ SECBUFFER_VERSION, 2, inBuffers };

            outBuf = { 0, SECBUFFER_TOKEN, nullptr };
            outDesc = { SECBUFFER_VERSION, 1, &outBuf };

            status = InitializeSecurityContextW(
                &m_hCred, &m_hCtx, (SEC_WCHAR*)wsni.c_str(), reqFlags, 0, 0,
                &inDesc, 0, nullptr, &outDesc, &retFlags, &tsExpiry);

            if (status == SEC_E_INCOMPLETE_MESSAGE) continue;

            if (outBuf.cbBuffer > 0 && outBuf.pvBuffer) {
                bool sent = m_underlying->send_all(outBuf.pvBuffer, outBuf.cbBuffer);
                FreeContextBuffer(outBuf.pvBuffer);
                outBuf.pvBuffer = nullptr;
                if (!sent) return false;
            }

            if (inBuffers[1].BufferType == SECBUFFER_EXTRA) {
                int extra = inBuffers[1].cbBuffer;
                m_enc_buf.assign(inBuf.data() + (inLen - extra), inBuf.data() + inLen);
                inLen = 0;
            } else {
                inLen = 0;
            }

            if (status == SEC_E_OK) {
                QueryContextAttributesW(&m_hCtx, SECPKG_ATTR_STREAM_SIZES, &m_sizes);
                return true;
            }
            if (FAILED(status)) return false;
        }
    }

    bool send_all(const void* buf, int len) override {
        std::lock_guard<std::mutex> lk(m_op_mtx);
        if (!m_ctx_valid || m_sizes.cbMaximumMessage == 0) return false;
        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(buf);
        int remaining = len;

        while (remaining > 0) {
            int chunk = remaining;
            if (chunk > (int)m_sizes.cbMaximumMessage) chunk = (int)m_sizes.cbMaximumMessage;

            std::vector<uint8_t> packet(m_sizes.cbHeader + chunk + m_sizes.cbTrailer);
            std::memcpy(packet.data() + m_sizes.cbHeader, ptr, chunk);

            SecBuffer buffers[4];
            buffers[0] = { m_sizes.cbHeader, SECBUFFER_STREAM_HEADER, packet.data() };
            buffers[1] = { (DWORD)chunk, SECBUFFER_DATA, packet.data() + m_sizes.cbHeader };
            buffers[2] = { m_sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, packet.data() + m_sizes.cbHeader + chunk };
            buffers[3] = { 0, SECBUFFER_EMPTY, nullptr };
            SecBufferDesc desc{ SECBUFFER_VERSION, 4, buffers };

            SECURITY_STATUS status = EncryptMessage(&m_hCtx, 0, &desc, 0);
            if (status != SEC_E_OK) return false;

            DWORD toSend = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
            if (!m_underlying->send_all(packet.data(), toSend)) return false;

            ptr += chunk;
            remaining -= chunk;
        }
        return true;
    }

    int recv_some(void* buf, int max_len) override {
        if (!m_ctx_valid) return -1;

        while (m_dec_queue.empty()) {
            if (m_enc_buf.empty()) {
                uint8_t temp[16384];
                int n = m_underlying->recv_some(temp, sizeof(temp));
                if (n <= 0) return n;
                m_enc_buf.assign(temp, temp + n);
            }

            SecBuffer buffers[4];
            buffers[0] = { (DWORD)m_enc_buf.size(), SECBUFFER_DATA, m_enc_buf.data() };
            buffers[1] = { 0, SECBUFFER_EMPTY, nullptr };
            buffers[2] = { 0, SECBUFFER_EMPTY, nullptr };
            buffers[3] = { 0, SECBUFFER_EMPTY, nullptr };
            SecBufferDesc desc{ SECBUFFER_VERSION, 4, buffers };

            SECURITY_STATUS status = SEC_E_INTERNAL_ERROR;
            {
                std::lock_guard<std::mutex> lk(m_op_mtx);
                if (!m_ctx_valid) return -1;
                status = DecryptMessage(&m_hCtx, &desc, 0, nullptr);
            }
            if (status == SEC_E_INCOMPLETE_MESSAGE) {
                uint8_t temp[16384];
                int n = m_underlying->recv_some(temp, sizeof(temp));
                if (n <= 0) return n;
                m_enc_buf.insert(m_enc_buf.end(), temp, temp + n);
                continue;
            }

            if (status == SEC_I_RENEGOTIATE) {
                for (int i = 0; i < 4; ++i) {
                    if (buffers[i].BufferType == SECBUFFER_DATA && buffers[i].cbBuffer > 0) {
                        uint8_t* p = reinterpret_cast<uint8_t*>(buffers[i].pvBuffer);
                        m_dec_queue.insert(m_dec_queue.end(), p, p + buffers[i].cbBuffer);
                    }
                }
                SecBuffer* extra = nullptr;
                for (int i = 0; i < 4; ++i) {
                    if (buffers[i].BufferType == SECBUFFER_EXTRA) { extra = &buffers[i]; break; }
                }
                if (extra && extra->cbBuffer > 0) {
                    int extra_len = extra->cbBuffer;
                    std::vector<uint8_t> remaining(m_enc_buf.end() - extra_len, m_enc_buf.end());
                    m_enc_buf = std::move(remaining);

                    SecBuffer inBuffers[2];
                    inBuffers[0] = { (DWORD)m_enc_buf.size(), SECBUFFER_TOKEN, m_enc_buf.data() };
                    inBuffers[1] = { 0, SECBUFFER_EMPTY, nullptr };
                    SecBufferDesc inDesc{ SECBUFFER_VERSION, 2, inBuffers };

                    SecBuffer outBuf{ 0, SECBUFFER_TOKEN, nullptr };
                    SecBufferDesc outDesc{ SECBUFFER_VERSION, 1, &outBuf };

                    DWORD reqFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                                     ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
                    DWORD retFlags = 0;
                    TimeStamp tsExpiry{};
                    {
                        std::lock_guard<std::mutex> lk(m_op_mtx);
                        if (m_ctx_valid) {
                            InitializeSecurityContextW(
                                &m_hCred, &m_hCtx, nullptr, reqFlags, 0, 0,
                                &inDesc, 0, nullptr, &outDesc, &retFlags, &tsExpiry);
                        }
                    }
                    if (outBuf.cbBuffer > 0 && outBuf.pvBuffer) {
                        m_underlying->send_all(outBuf.pvBuffer, outBuf.cbBuffer);
                        FreeContextBuffer(outBuf.pvBuffer);
                    }
                    if (inBuffers[1].BufferType == SECBUFFER_EXTRA && inBuffers[1].cbBuffer > 0) {
                        int rem_extra = inBuffers[1].cbBuffer;
                        std::vector<uint8_t> rem(m_enc_buf.end() - rem_extra, m_enc_buf.end());
                        m_enc_buf = std::move(rem);
                    } else {
                        m_enc_buf.clear();
                    }
                } else {
                    m_enc_buf.clear();
                }
                if (!m_dec_queue.empty()) break;
                continue;
            }

            if (status == SEC_E_OK || status == SEC_I_CONTEXT_EXPIRED) {
                for (int i = 0; i < 4; ++i) {
                    if (buffers[i].BufferType == SECBUFFER_DATA && buffers[i].cbBuffer > 0) {
                        uint8_t* p = reinterpret_cast<uint8_t*>(buffers[i].pvBuffer);
                        m_dec_queue.insert(m_dec_queue.end(), p, p + buffers[i].cbBuffer);
                    }
                }

                // Handle remaining encrypted bytes
                SecBuffer* extra = nullptr;
                for (int i = 0; i < 4; ++i) {
                    if (buffers[i].BufferType == SECBUFFER_EXTRA) { extra = &buffers[i]; break; }
                }
                if (extra && extra->cbBuffer > 0) {
                    int extra_len = extra->cbBuffer;
                    std::vector<uint8_t> remaining(m_enc_buf.end() - extra_len, m_enc_buf.end());
                    m_enc_buf = std::move(remaining);
                } else {
                    m_enc_buf.clear();
                }

                if (status == SEC_I_CONTEXT_EXPIRED && m_dec_queue.empty()) return 0;
                break;
            }

            return -1;
        }

        int count = (int)m_dec_queue.size();
        if (count > max_len) count = max_len;
        std::memcpy(buf, m_dec_queue.data(), count);
        m_dec_queue.erase(m_dec_queue.begin(), m_dec_queue.begin() + count);
        return count;
    }

    void close() override {
        if (m_underlying) m_underlying->close();
        std::lock_guard<std::mutex> lk(m_op_mtx);
        if (m_ctx_valid) {
            DeleteSecurityContext(&m_hCtx);
            m_ctx_valid = false;
        }
        if (m_cred_valid) {
            FreeCredentialsHandle(&m_hCred);
            m_cred_valid = false;
        }
    }

    void shutdown_send() override {
        if (m_underlying) m_underlying->shutdown_send();
    }
    void set_rcv_timeout(int timeout_ms) override {
        if (m_underlying) m_underlying->set_rcv_timeout(timeout_ms);
    }
};

// RFC 6455 WebSocket stream wrapping an underlying stream (TCP or TLS)
class WsStream : public ITransportStream {
private:
    ITransportStream*    m_underlying;
    std::string          m_path;
    std::string          m_host;
    std::vector<uint8_t> m_rx_queue;

public:
    WsStream(ITransportStream* underlying, const std::string& path, const std::string& host)
        : m_underlying(underlying), m_path(path), m_host(host) {}

    ~WsStream() override {
        close();
        delete m_underlying;
    }

    bool handshake() {
        // Generate random 16-byte WebSocket Key
        static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        uint8_t nonce[16];
        if (!reality::secure_random(nonce, 16)) return false;
        std::string ws_key;
        int val = 0, valb = -6;
        for (uint8_t c : nonce) {
            val = (val << 8) + c; valb += 8;
            while (valb >= 0) { ws_key.push_back(tbl[(val >> valb) & 0x3F]); valb -= 6; }
        }
        if (valb > -6) ws_key.push_back(tbl[((val << 8) >> (valb + 8)) & 0x3F]);
        while (ws_key.size() % 4) ws_key.push_back('=');

        std::string req =
            "GET " + m_path + " HTTP/1.1\r\n"
            "Host: " + m_host + "\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: " + ws_key + "\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            "\r\n";

        if (!m_underlying->send_all(req.data(), (int)req.size())) return false;

        std::string resp;
        char ch;
        while (resp.size() < 4096) {
            if (!m_underlying->recv_exact(&ch, 1)) return false;
            resp.push_back(ch);
            if (resp.size() >= 4 && resp.substr(resp.size() - 4) == "\r\n\r\n") break;
        }

        return (resp.find(" 101 ") != std::string::npos);
    }

    bool send_all(const void* buf, int len) override {
        const uint8_t* data = reinterpret_cast<const uint8_t*>(buf);
        std::vector<uint8_t> frame;
        frame.reserve(len + 14);

        // FIN=1, Opcode=0x02 (Binary)
        frame.push_back(0x82);

        // Client MUST mask payload (0x80)
        if (len <= 125) {
            frame.push_back(static_cast<uint8_t>(0x80 | len));
        } else if (len <= 65535) {
            frame.push_back(0x80 | 126);
            frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
            frame.push_back(static_cast<uint8_t>(len & 0xFF));
        } else {
            frame.push_back(0x80 | 127);
            for (int i = 7; i >= 0; --i) frame.push_back(static_cast<uint8_t>((static_cast<uint64_t>(len) >> (i * 8)) & 0xFF));
        }

        // 4-byte random masking key
        uint8_t mask[4];
        reality::secure_random(mask, 4);
        for (int i = 0; i < 4; ++i) {
            frame.push_back(mask[i]);
        }

        // Mask and append payload
        size_t head_len = frame.size();
        frame.resize(head_len + len);
        for (int i = 0; i < len; ++i) {
            frame[head_len + i] = data[i] ^ mask[i % 4];
        }

        return m_underlying->send_all(frame.data(), (int)frame.size());
    }

    int recv_some(void* buf, int max_len) override {
        while (m_rx_queue.empty()) {
            uint8_t hdr[2];
            if (!m_underlying->recv_exact(hdr, 2)) return 0;

            uint8_t opcode = hdr[0] & 0x0F;
            bool masked = (hdr[1] & 0x80) != 0;
            uint64_t payload_len = hdr[1] & 0x7F;

            if (payload_len == 126) {
                uint8_t ext[2];
                if (!m_underlying->recv_exact(ext, 2)) return 0;
                payload_len = (ext[0] << 8) | ext[1];
            } else if (payload_len == 127) {
                uint8_t ext[8];
                if (!m_underlying->recv_exact(ext, 8)) return 0;
                payload_len = 0;
                for (int i = 0; i < 8; ++i) payload_len = (payload_len << 8) | ext[i];
            }

            if (payload_len > 16 * 1024 * 1024) return 0; // Defense against server bad_alloc crash

            uint8_t mask[4]{};
            if (masked) {
                if (!m_underlying->recv_exact(mask, 4)) return 0;
            }

            std::vector<uint8_t> payload(payload_len);
            if (payload_len > 0) {
                if (!m_underlying->recv_exact(payload.data(), (int)payload_len)) return 0;
                if (masked) {
                    for (size_t i = 0; i < payload_len; ++i) payload[i] ^= mask[i % 4];
                }
            }

            if (opcode == 0x08) {
                // Connection Close
                return 0;
            } else if (opcode == 0x09) {
                // Ping -> Reply with Pong (0x8A)
                std::vector<uint8_t> pong;
                pong.push_back(0x8A);
                pong.push_back(static_cast<uint8_t>(0x80 | (payload_len & 0x7F)));
                uint8_t pmask[4] = { 1, 2, 3, 4 };
                pong.insert(pong.end(), pmask, pmask + 4);
                for (size_t i = 0; i < payload_len; ++i) pong.push_back(payload[i] ^ pmask[i % 4]);
                m_underlying->send_all(pong.data(), (int)pong.size());
                continue;
            } else if (opcode == 0x0A) {
                // Pong -> Ignore
                continue;
            } else if (opcode == 0x01 || opcode == 0x02 || opcode == 0x00) {
                // Data payload
                m_rx_queue = std::move(payload);
                break;
            }
        }

        int count = (int)m_rx_queue.size();
        if (count > max_len) count = max_len;
        std::memcpy(buf, m_rx_queue.data(), count);
        m_rx_queue.erase(m_rx_queue.begin(), m_rx_queue.begin() + count);
        return count;
    }

    void close() override {
        if (m_underlying) m_underlying->close();
    }

    void shutdown_send() override {
        if (m_underlying) m_underlying->shutdown_send();
    }
    void set_rcv_timeout(int timeout_ms) override {
        if (m_underlying) m_underlying->set_rcv_timeout(timeout_ms);
    }
};

// HTTPUpgrade stream implementing HTTP/1.1 Upgrade without WebSocket frame overhead
class HttpUpgradeStream : public ITransportStream {
private:
    ITransportStream*    m_underlying;
    std::string          m_path;
    std::string          m_host;

public:
    HttpUpgradeStream(ITransportStream* underlying, const std::string& path, const std::string& host)
        : m_underlying(underlying), m_path(path), m_host(host) {}

    ~HttpUpgradeStream() override {
        close();
        delete m_underlying;
    }

    bool handshake() {
        if (!m_underlying) return false;

        static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        uint8_t nonce[16];
        if (!reality::secure_random(nonce, 16)) return false;
        std::string ws_key;
        int val = 0, valb = -6;
        for (uint8_t c : nonce) {
            val = (val << 8) + c; valb += 8;
            while (valb >= 0) { ws_key.push_back(tbl[(val >> valb) & 0x3F]); valb -= 6; }
        }
        if (valb > -6) ws_key.push_back(tbl[((val << 8) >> (valb + 8)) & 0x3F]);
        while (ws_key.size() % 4) ws_key.push_back('=');

        std::string req =
            "GET " + m_path + " HTTP/1.1\r\n"
            "Host: " + m_host + "\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Key: " + ws_key + "\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) NanoRay/1.0\r\n"
            "\r\n";

        if (!m_underlying->send_all(req.data(), (int)req.size())) return false;

        std::string resp;
        char ch;
        while (resp.size() < 4096) {
            if (!m_underlying->recv_exact(&ch, 1)) return false;
            resp.push_back(ch);
            if (resp.size() >= 4 && resp.substr(resp.size() - 4) == "\r\n\r\n") break;
        }

        return (resp.find(" 101 ") != std::string::npos);
    }

    bool send_all(const void* buf, int len) override {
        if (!m_underlying) return false;
        return m_underlying->send_all(buf, len);
    }

    int recv_some(void* buf, int max_len) override {
        if (!m_underlying) return -1;
        return m_underlying->recv_some(buf, max_len);
    }

    void close() override {
        if (m_underlying) m_underlying->close();
    }

    void shutdown_send() override {
        if (m_underlying) m_underlying->shutdown_send();
    }
    void set_rcv_timeout(int timeout_ms) override {
        if (m_underlying) m_underlying->set_rcv_timeout(timeout_ms);
    }
};

// REALITY Stream implementing TLS 1.3 Client camouflage over raw TCP
class RealityStream : public ITransportStream {
private:
    ITransportStream* m_underlying;
    std::string       m_sni;
    std::string       m_pbk;
    std::string       m_sid;
    std::string       m_spx;
    std::string       m_fp;

    uint8_t m_client_write_key[32]{};
    uint8_t m_client_write_iv[12]{};
    uint8_t m_server_write_key[32]{};
    uint8_t m_server_write_iv[12]{};
    size_t  m_traffic_key_len = 16;
    uint64_t m_client_seq = 0;
    uint64_t m_server_seq = 0;

    std::vector<uint8_t> m_dec_queue;

    static void make_tls13_nonce(const uint8_t iv[12], uint64_t seq, uint8_t nonce[12]) {
        std::memcpy(nonce, iv, 12);
        for (int i = 0; i < 8; ++i) {
            nonce[11 - i] ^= static_cast<uint8_t>((seq >> (i * 8)) & 0xFF);
        }
    }

public:
    RealityStream(ITransportStream* underlying, const std::string& sni,
                  const std::string& pbk, const std::string& sid, const std::string& spx = "",
                  const std::string& fp = "chrome")
        : m_underlying(underlying), m_sni(sni), m_pbk(pbk), m_sid(sid), m_spx(spx), m_fp(fp) {}

    ~RealityStream() override {
        close();
        delete m_underlying;
    }

    bool handshake() {
        if (!m_underlying) return false;
        auto server_pub = reality::base64_decode(m_pbk);
        if (server_pub.size() != 32) return false;
        auto short_id = reality::hex_decode(m_sid);

        // 1. Generate client random & ephemeral keys with cryptographically secure PRNG
        uint8_t client_random[32];
        if (!reality::secure_random(client_random, 32)) return false;

        uint8_t client_priv[32], client_pub[32];
        if (!reality::secure_random(client_priv, 32)) return false;
        client_priv[0] &= 248; client_priv[31] &= 127; client_priv[31] |= 64;
        reality::x25519_base(client_pub, client_priv);

        // 2. Derive 32-byte AuthKey (matching Xray REALITY spec)
        uint8_t auth_shared[32];
        reality::x25519(auth_shared, client_priv, server_pub.data());
        uint8_t auth_key[32];
        reality::hkdf(client_random, 20, auth_shared, 32, "REALITY", 7, auth_key, 32);

        // 3. Assemble authentic browser ClientHello via uTLS
        size_t sid_start = 0;
        utls::FingerprintProfile fp_prof = utls::parse_fp(m_fp);
        std::vector<uint8_t> hs = utls::build_browser_client_hello(fp_prof, m_sni, client_random, client_pub, sid_start);

        // 4. Seal SessionId using AES-256-GCM with 32-byte AuthKey
        uint8_t plain_sid[16] = { 0x01, 0x08, 0x00, 0x00 };
        uint32_t now_ts = static_cast<uint32_t>(time(nullptr));
        plain_sid[4] = (now_ts >> 24) & 0xFF;
        plain_sid[5] = (now_ts >> 16) & 0xFF;
        plain_sid[6] = (now_ts >> 8) & 0xFF;
        plain_sid[7] = now_ts & 0xFF;
        for (size_t i = 0; i < 8; ++i) {
            plain_sid[8 + i] = (i < short_id.size()) ? short_id[i] : 0x00;
        }

        uint8_t ct[16]{}, tag[16]{};
        if (!reality::aes_gcm_encrypt(
                auth_key, 32, client_random + 20,
                plain_sid, 16,
                hs.data(), hs.size(),
                ct, tag)) {
            return false;
        }

        std::memcpy(hs.data() + sid_start, ct, 16);
        std::memcpy(hs.data() + sid_start + 16, tag, 16);

        // 5. Send TLS Record Header + Handshake
        std::vector<uint8_t> rec;
        rec.push_back(0x16);
        rec.push_back(0x03); rec.push_back(0x01);
        uint16_t rlen = static_cast<uint16_t>(hs.size());
        rec.push_back((rlen >> 8) & 0xFF); rec.push_back(rlen & 0xFF);
        rec.insert(rec.end(), hs.begin(), hs.end());

        if (!m_underlying->send_all(rec.data(), static_cast<int>(rec.size()))) return false;

        // Transcript starts with ClientHello handshake message
        std::vector<uint8_t> transcript = hs;

        // 6. Receive ServerHello
        // Skip any middlebox 0x14 ChangeCipherSpec if sent
        uint8_t r_hdr[5];
        while (true) {
            if (!m_underlying->recv_exact(r_hdr, 5)) return false;
            if (r_hdr[0] == 0x14) { // ChangeCipherSpec
                uint16_t ccs_len = (r_hdr[3] << 8) | r_hdr[4];
                std::vector<uint8_t> ccs_body(ccs_len);
                if (!m_underlying->recv_exact(ccs_body.data(), ccs_len)) return false;
                continue;
            }
            break;
        }

        if (r_hdr[0] != 0x16) return false; // Must be Handshake
        uint16_t sh_rec_len = (r_hdr[3] << 8) | r_hdr[4];
        std::vector<uint8_t> sh(sh_rec_len);
        if (!m_underlying->recv_exact(sh.data(), sh_rec_len)) return false;

        if (sh.size() < 4 || sh[0] != 0x02) return false; // ServerHello type
        transcript.insert(transcript.end(), sh.begin(), sh.end());

        // Parse ServerHello KeyShare to extract server_eph_pub (32 bytes)
        if (sh.size() < 38) return false;
        size_t p = 38;
        uint8_t sh_sid_len = sh[p++];
        if (sh.size() < p + sh_sid_len + 3) return false;
        p += sh_sid_len;
        uint16_t cipher_suite = (sh[p] << 8) | sh[p + 1];
        if (cipher_suite != 0x1301) {
            // Only TLS_AES_128_GCM_SHA256 (0x1301) is supported by REALITY HKDF-SHA256
            return false;
        }
        size_t traffic_key_len = 16;
        m_traffic_key_len = traffic_key_len;
        p += 2; // cipher suite
        p += 1; // compression method
        if (sh.size() < p + 2) return false;
        uint16_t sh_ext_len = (sh[p] << 8) | sh[p + 1];
        p += 2;
        size_t end_p = p + sh_ext_len;
        if (end_p > sh.size()) return false;

        uint8_t server_eph_pub[32]{};
        bool found_share = false;
        while (p + 4 <= end_p) {
            uint16_t etype = (sh[p] << 8) | sh[p + 1];
            uint16_t elen  = (sh[p + 2] << 8) | sh[p + 3];
            p += 4;
            if (etype == 0x0033 && elen >= 36) { // KeyShare
                uint16_t grp = (sh[p] << 8) | sh[p + 1];
                uint16_t klen = (sh[p + 2] << 8) | sh[p + 3];
                if (grp == 0x001d && klen == 32) {
                    std::memcpy(server_eph_pub, sh.data() + p + 4, 32);
                    found_share = true;
                    break;
                }
            }
            p += elen;
        }
        if (!found_share) return false;

        // 7. TLS 1.3 Key Derivation
        uint8_t tls_shared[32];
        reality::x25519(tls_shared, client_priv, server_eph_pub);

        uint8_t zero32[32] = {0};
        uint8_t early_secret[32];
        reality::hkdf_extract(zero32, 32, zero32, 32, early_secret);

        uint8_t derived1[32];
        reality::derive_secret(early_secret, "derived", nullptr, derived1);

        uint8_t handshake_secret[32];
        reality::hkdf_extract(derived1, 32, tls_shared, 32, handshake_secret);

        uint8_t tr_hash1[32];
        reality::sha256(transcript.data(), transcript.size(), tr_hash1);

        uint8_t client_hs_traffic[32], server_hs_traffic[32];
        reality::derive_secret(handshake_secret, "c hs traffic", tr_hash1, client_hs_traffic);
        reality::derive_secret(handshake_secret, "s hs traffic", tr_hash1, server_hs_traffic);

        uint8_t server_hs_key[32], server_hs_iv[12];
        reality::hkdf_expand_label(server_hs_traffic, "key", nullptr, 0, server_hs_key, traffic_key_len);
        reality::hkdf_expand_label(server_hs_traffic, "iv",  nullptr, 0, server_hs_iv, 12);

        uint8_t client_hs_key[32], client_hs_iv[12];
        reality::hkdf_expand_label(client_hs_traffic, "key", nullptr, 0, client_hs_key, traffic_key_len);
        reality::hkdf_expand_label(client_hs_traffic, "iv",  nullptr, 0, client_hs_iv, 12);

        // 8. Decrypt Server's Encrypted Handshake Records & Authenticate Server
        uint64_t s_hs_seq = 0;
        bool server_finished = false;
        bool saw_cert = false;

        while (!server_finished) {
            uint8_t enc_hdr[5];
            if (!m_underlying->recv_exact(enc_hdr, 5)) return false;
            if (enc_hdr[0] == 0x14) { // ChangeCipherSpec
                uint16_t ccs_len = (enc_hdr[3] << 8) | enc_hdr[4];
                std::vector<uint8_t> ccs_b(ccs_len);
                m_underlying->recv_exact(ccs_b.data(), ccs_len);
                continue;
            }
            if (enc_hdr[0] != 0x17) return false;
            uint16_t enc_len = (enc_hdr[3] << 8) | enc_hdr[4];
            if (enc_len < 17) return false;
            std::vector<uint8_t> enc_buf(enc_len);
            if (!m_underlying->recv_exact(enc_buf.data(), enc_len)) return false;

            size_t ct_len = enc_len - 16;
            const uint8_t* tag_ptr = enc_buf.data() + ct_len;
            std::vector<uint8_t> dec(ct_len);

            uint8_t nonce[12];
            make_tls13_nonce(server_hs_iv, s_hs_seq++, nonce);

            if (!reality::aes_gcm_decrypt(
                    server_hs_key, traffic_key_len, nonce,
                    enc_buf.data(), ct_len,
                    tag_ptr,
                    enc_hdr, 5,
                    dec.data())) {
                return false;
            }

            while (!dec.empty() && dec.back() == 0x00) dec.pop_back();
            if (dec.empty()) return false;
            uint8_t inner_type = dec.back();
            dec.pop_back();

            if (inner_type != 0x16) return false;

            size_t idx = 0;
            while (idx + 4 <= dec.size()) {
                uint8_t msg_type = dec[idx];
                uint32_t msg_len = (dec[idx + 1] << 16) | (dec[idx + 2] << 8) | dec[idx + 3];
                size_t total_msg = 4 + msg_len;
                if (idx + total_msg > dec.size()) break;

                // Server Authentication: Validate leaf certificate HMAC
                if (msg_type == 0x0b) { // Certificate message
                    size_t c_pos = idx + 4;
                    if (c_pos >= idx + total_msg) return false;
                    uint8_t req_ctx_len = dec[c_pos++];
                    c_pos += req_ctx_len;
                    if (c_pos + 6 > idx + total_msg) return false;
                    c_pos += 3; // skip cert_list_len
                    uint32_t cert_len = (dec[c_pos] << 16) | (dec[c_pos + 1] << 8) | dec[c_pos + 2];
                    c_pos += 3;
                    if (c_pos + cert_len > idx + total_msg) return false;
                    const uint8_t* cert_der = dec.data() + c_pos;
                    bool cert_ok = false;
                    for (size_t s = 0; s + 38 < cert_len; ++s) {
                        if (cert_der[s] == 0x2b && cert_der[s + 1] == 0x65 && cert_der[s + 2] == 0x70) {
                            for (size_t k = s + 3; k + 35 < cert_len && k < s + 20; ++k) {
                                if (cert_der[k] == 0x03 && cert_der[k + 1] == 0x21 && cert_der[k + 2] == 0x00) {
                                    const uint8_t* pub = cert_der + k + 3;
                                    if (cert_len >= 67) {
                                        size_t sig_pos = cert_len - 67;
                                        while (sig_pos > 0 && !(cert_der[sig_pos] == 0x03 && cert_der[sig_pos + 1] == 0x41 && cert_der[sig_pos + 2] == 0x00)) {
                                            sig_pos--;
                                        }
                                        if (cert_der[sig_pos] == 0x03 && cert_der[sig_pos + 1] == 0x41 && cert_der[sig_pos + 2] == 0x00) {
                                            const uint8_t* sig = cert_der + sig_pos + 3;
                                            uint8_t hmac_out[64];
                                            if (reality::hmac_sha512(auth_key, 32, pub, 32, hmac_out)) {
                                                if (std::memcmp(hmac_out, sig, 64) == 0) {
                                                    cert_ok = true;
                                                }
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                            break;
                        }
                    }
                    if (!cert_ok) return false;
                    saw_cert = true;
                }

                // Server Authentication: Validate server Finished message
                if (msg_type == 0x14) { // Finished message
                    if (!saw_cert) {
                        // Reject Finished if valid Certificate was not presented first (fail-closed against MITM)
                        return false;
                    }
                    uint8_t tr_hash_fin[32];
                    reality::sha256(transcript.data(), transcript.size(), tr_hash_fin);
                    uint8_t s_fin_key[32];
                    reality::hkdf_expand_label(server_hs_traffic, "finished", nullptr, 0, s_fin_key, 32);
                    uint8_t expected_fin[32];
                    reality::hmac_sha256(s_fin_key, 32, tr_hash_fin, 32, expected_fin);
                    if (msg_len < 32 || std::memcmp(dec.data() + idx + 4, expected_fin, 32) != 0) {
                        return false;
                    }
                    transcript.insert(transcript.end(), dec.begin() + idx, dec.begin() + idx + total_msg);
                    idx += total_msg;
                    server_finished = true;
                    break;
                }

                transcript.insert(transcript.end(), dec.begin() + idx, dec.begin() + idx + total_msg);
                idx += total_msg;
            }
        }

        // 9. Derive Application Traffic Keys
        uint8_t derived2[32];
        reality::derive_secret(handshake_secret, "derived", nullptr, derived2);

        uint8_t master_secret[32];
        reality::hkdf_extract(derived2, 32, zero32, 32, master_secret);

        uint8_t tr_hash2[32];
        reality::sha256(transcript.data(), transcript.size(), tr_hash2);

        uint8_t client_ap_traffic[32], server_ap_traffic[32];
        reality::derive_secret(master_secret, "c ap traffic", tr_hash2, client_ap_traffic);
        reality::derive_secret(master_secret, "s ap traffic", tr_hash2, server_ap_traffic);

        reality::hkdf_expand_label(client_ap_traffic, "key", nullptr, 0, m_client_write_key, traffic_key_len);
        reality::hkdf_expand_label(client_ap_traffic, "iv",  nullptr, 0, m_client_write_iv, 12);
        reality::hkdf_expand_label(server_ap_traffic, "key", nullptr, 0, m_server_write_key, traffic_key_len);
        reality::hkdf_expand_label(server_ap_traffic, "iv",  nullptr, 0, m_server_write_iv, 12);

        // 10. Send Client Finished
        uint8_t fin_key[32];
        reality::hkdf_expand_label(client_hs_traffic, "finished", nullptr, 0, fin_key, 32);

        uint8_t verify_data[32];
        reality::hmac_sha256(fin_key, 32, tr_hash2, 32, verify_data);

        std::vector<uint8_t> cfin;
        cfin.push_back(0x14); // Finished
        cfin.push_back(0x00); cfin.push_back(0x00); cfin.push_back(0x20);
        cfin.insert(cfin.end(), verify_data, verify_data + 32);
        cfin.push_back(0x16); // InnerContentType = Handshake

        std::vector<uint8_t> cfin_ct(cfin.size());
        uint8_t cfin_tag[16];
        uint8_t cfin_nonce[12];
        make_tls13_nonce(client_hs_iv, 0, cfin_nonce);

        uint16_t cfin_rec_len = static_cast<uint16_t>(cfin.size() + 16);
        uint8_t cfin_hdr[5] = { 0x17, 0x03, 0x03, static_cast<uint8_t>((cfin_rec_len >> 8) & 0xFF), static_cast<uint8_t>(cfin_rec_len & 0xFF) };

        if (!reality::aes_gcm_encrypt(
                client_hs_key, traffic_key_len, cfin_nonce,
                cfin.data(), cfin.size(),
                cfin_hdr, 5,
                cfin_ct.data(), cfin_tag)) {
            return false;
        }

        std::vector<uint8_t> cfin_pkt;
        cfin_pkt.insert(cfin_pkt.end(), cfin_hdr, cfin_hdr + 5);
        cfin_pkt.insert(cfin_pkt.end(), cfin_ct.begin(), cfin_ct.end());
        cfin_pkt.insert(cfin_pkt.end(), cfin_tag, cfin_tag + 16);

        if (!m_underlying->send_all(cfin_pkt.data(), static_cast<int>(cfin_pkt.size()))) return false;

        m_client_seq = 0;
        m_server_seq = 0;
        return true;
    }

    bool send_all(const void* buf, int len) override {
        const uint8_t* ptr = static_cast<const uint8_t*>(buf);
        int remaining = len;

        while (remaining > 0) {
            int chunk_sz = (remaining > 16384) ? 16384 : remaining;
            std::vector<uint8_t> pt(ptr, ptr + chunk_sz);
            pt.push_back(0x17); // InnerContentType = ApplicationData

            uint16_t rec_len = static_cast<uint16_t>(pt.size() + 16);
            uint8_t hdr[5] = { 0x17, 0x03, 0x03, static_cast<uint8_t>((rec_len >> 8) & 0xFF), static_cast<uint8_t>(rec_len & 0xFF) };

            uint8_t nonce[12];
            make_tls13_nonce(m_client_write_iv, m_client_seq++, nonce);

            std::vector<uint8_t> ct(pt.size());
            uint8_t tag[16];
            if (!reality::aes_gcm_encrypt(
                    m_client_write_key, m_traffic_key_len, nonce,
                    pt.data(), pt.size(),
                    hdr, 5,
                    ct.data(), tag)) {
                return false;
            }

            std::vector<uint8_t> pkt;
            pkt.insert(pkt.end(), hdr, hdr + 5);
            pkt.insert(pkt.end(), ct.begin(), ct.end());
            pkt.insert(pkt.end(), tag, tag + 16);

            if (!m_underlying->send_all(pkt.data(), static_cast<int>(pkt.size()))) return false;
            ptr += chunk_sz;
            remaining -= chunk_sz;
        }
        return true;
    }

    int recv_some(void* buf, int max_len) override {
        if (!m_dec_queue.empty()) {
            int count = (int)m_dec_queue.size();
            if (count > max_len) count = max_len;
            std::memcpy(buf, m_dec_queue.data(), count);
            m_dec_queue.erase(m_dec_queue.begin(), m_dec_queue.begin() + count);
            return count;
        }

        while (m_dec_queue.empty()) {
            uint8_t hdr[5];
            if (!m_underlying->recv_exact(hdr, 5)) return -1;

            if (hdr[0] == 0x14) { // ChangeCipherSpec
                uint16_t ccs_len = (hdr[3] << 8) | hdr[4];
                std::vector<uint8_t> ccs_b(ccs_len);
                m_underlying->recv_exact(ccs_b.data(), ccs_len);
                continue;
            }

            if (hdr[0] != 0x17) return -1;
            uint16_t rec_len = (hdr[3] << 8) | hdr[4];
            if (rec_len < 17) return -1;

            std::vector<uint8_t> enc(rec_len);
            if (!m_underlying->recv_exact(enc.data(), rec_len)) return -1;

            size_t ct_len = rec_len - 16;
            const uint8_t* tag_ptr = enc.data() + ct_len;
            std::vector<uint8_t> dec(ct_len);

            uint8_t nonce[12];
            make_tls13_nonce(m_server_write_iv, m_server_seq++, nonce);

            if (!reality::aes_gcm_decrypt(
                    m_server_write_key, m_traffic_key_len, nonce,
                    enc.data(), ct_len,
                    tag_ptr,
                    hdr, 5,
                    dec.data())) {
                return -1;
            }

            while (!dec.empty() && dec.back() == 0x00) dec.pop_back();
            if (dec.empty()) continue;
            uint8_t inner_type = dec.back();
            dec.pop_back();

            if (inner_type == 0x17) {
                m_dec_queue = std::move(dec);
                break;
            } else if (inner_type == 0x15) {
                return 0; // EOF
            }
        }

        int count = (int)m_dec_queue.size();
        if (count > max_len) count = max_len;
        std::memcpy(buf, m_dec_queue.data(), count);
        m_dec_queue.erase(m_dec_queue.begin(), m_dec_queue.begin() + count);
        return count;
    }

    void close() override {
        if (m_underlying) m_underlying->close();
    }

    void shutdown_send() override {
        if (m_underlying) m_underlying->shutdown_send();
    }
    void set_rcv_timeout(int timeout_ms) override {
        if (m_underlying) m_underlying->set_rcv_timeout(timeout_ms);
    }
};

// XHTTP / SplitHTTP stream implementing HTTP/1.1 chunked transport
class XhttpStream : public ITransportStream {
private:
    ITransportStream*    m_underlying;
    std::string          m_host;
    std::string          m_path;
    std::string          m_mode;
    int                  m_pad_min;
    int                  m_pad_max;
    std::string          m_session_id;

    bool                 m_header_read        = false;
    bool                 m_is_chunked         = true;
    bool                 m_reading_chunk_data = false;
    bool                 m_skip_crlf          = false;
    size_t               m_chunk_remaining    = 0;
    bool                 m_eof                = false;
    bool                 m_eof_sent           = false;

    std::vector<uint8_t> m_rx_buf;
    std::vector<uint8_t> m_rx_queue;

    static std::string generate_session_id() {
        uint8_t rnd[8];
        reality::secure_random(rnd, sizeof(rnd));
        char buf[17];
        for (int i = 0; i < 8; ++i) {
            std::snprintf(buf + i * 2, 3, "%02x", rnd[i]);
        }
        buf[16] = '\0';
        return std::string(buf);
    }

    static std::string generate_padding(int min_len, int max_len) {
        if (min_len <= 0) min_len = 100;
        if (max_len < min_len) max_len = min_len;
        int len = min_len;
        uint32_t r = 0;
        reality::secure_random(&r, sizeof(r));
        if (max_len > min_len) len += (r % (max_len - min_len + 1));
        static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::string pad;
        pad.reserve(len);
        std::vector<uint8_t> rnd_chars(len);
        reality::secure_random(rnd_chars.data(), len);
        for (int i = 0; i < len; ++i) {
            pad.push_back(chars[rnd_chars[i] % (sizeof(chars) - 1)]);
        }
        return pad;
    }

public:
    XhttpStream(ITransportStream* underlying, const std::string& host, const std::string& path,
                const std::string& mode = "auto", int pad_min = 100, int pad_max = 1000)
        : m_underlying(underlying), m_host(host), m_path(path), m_mode(mode),
          m_pad_min(pad_min), m_pad_max(pad_max) {}

    ~XhttpStream() override {
        close();
        delete m_underlying;
    }

    bool handshake() {
        if (!m_underlying) return false;
        m_session_id = generate_session_id();
        std::string full_path = m_path;
        if (full_path.empty()) full_path = "/";
        if (full_path.back() != '/') full_path.push_back('/');
        full_path += m_session_id;

        std::string padding = generate_padding(m_pad_min, m_pad_max);

        std::string req =
            "POST " + full_path + " HTTP/1.1\r\n"
            "Host: " + m_host + "\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Transfer-Encoding: chunked\r\n"
            "X-Padding: " + padding + "\r\n"
            "Connection: keep-alive\r\n\r\n";

        return m_underlying->send_all(req.data(), static_cast<int>(req.size()));
    }

    bool send_all(const void* buf, int len) override {
        if (!m_underlying) return false;
        if (len <= 0) return true;

        char chunk_hdr[32];
        int hlen = std::snprintf(chunk_hdr, sizeof(chunk_hdr), "%x\r\n", len);

        std::vector<uint8_t> pkt;
        pkt.reserve(hlen + len + 2);
        pkt.insert(pkt.end(), reinterpret_cast<const uint8_t*>(chunk_hdr), reinterpret_cast<const uint8_t*>(chunk_hdr) + hlen);
        pkt.insert(pkt.end(), static_cast<const uint8_t*>(buf), static_cast<const uint8_t*>(buf) + len);
        pkt.push_back('\r');
        pkt.push_back('\n');

        return m_underlying->send_all(pkt.data(), static_cast<int>(pkt.size()));
    }

    int recv_some(void* buf, int max_len) override {
        if (!m_underlying || max_len <= 0) return -1;

        // 1. Return pending data if available
        if (!m_rx_queue.empty()) {
            int take = static_cast<int>(m_rx_queue.size());
            if (take > max_len) take = max_len;
            std::memcpy(buf, m_rx_queue.data(), take);
            m_rx_queue.erase(m_rx_queue.begin(), m_rx_queue.begin() + take);
            return take;
        }

        // 2. Consume HTTP response header on first read
        while (!m_header_read) {
            size_t hdr_end = std::string::npos;
            if (m_rx_buf.size() >= 4) {
                for (size_t i = 0; i + 3 < m_rx_buf.size(); ++i) {
                    if (m_rx_buf[i] == '\r' && m_rx_buf[i+1] == '\n' &&
                        m_rx_buf[i+2] == '\r' && m_rx_buf[i+3] == '\n') {
                        hdr_end = i + 4;
                        break;
                    }
                }
            }

            if (hdr_end != std::string::npos) {
                std::string header_str(reinterpret_cast<char*>(m_rx_buf.data()), hdr_end);
                m_rx_buf.erase(m_rx_buf.begin(), m_rx_buf.begin() + hdr_end);

                if (header_str.find(" 200 ") == std::string::npos &&
                    header_str.find(" 204 ") == std::string::npos) {
                    return -1;
                }

                std::string hdr_lower = header_str;
                for (char& c : hdr_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                m_is_chunked = (hdr_lower.find("transfer-encoding: chunked") != std::string::npos ||
                                hdr_lower.find("transfer-encoding:chunked") != std::string::npos);

                m_header_read = true;
                break;
            }

            uint8_t tmp[2048];
            int n = m_underlying->recv_some(tmp, sizeof(tmp));
            if (n <= 0) return n;
            m_rx_buf.insert(m_rx_buf.end(), tmp, tmp + n);
            if (m_rx_buf.size() > 65536) return -1;
        }

        // 3. Passthrough if not chunk-encoded
        if (!m_is_chunked) {
            if (!m_rx_buf.empty()) {
                int take = static_cast<int>(m_rx_buf.size());
                if (take > max_len) take = max_len;
                std::memcpy(buf, m_rx_buf.data(), take);
                m_rx_buf.erase(m_rx_buf.begin(), m_rx_buf.begin() + take);
                return take;
            }
            return m_underlying->recv_some(buf, max_len);
        }

        // 4. Decode chunk-encoded stream
        while (m_rx_queue.empty() && !m_eof) {
            // 4a. Consume trailing CRLF of previous chunk
            if (m_skip_crlf) {
                while (true) {
                    bool has_lf = false;
                    for (uint8_t b : m_rx_buf) {
                        if (b == '\n') { has_lf = true; break; }
                    }
                    if (has_lf) break;
                    uint8_t tmp[2048];
                    int n = m_underlying->recv_some(tmp, sizeof(tmp));
                    if (n <= 0) return (m_rx_queue.empty() ? n : static_cast<int>(m_rx_queue.size()));
                    m_rx_buf.insert(m_rx_buf.end(), tmp, tmp + n);
                }
                while (!m_rx_buf.empty()) {
                    uint8_t b = m_rx_buf[0];
                    m_rx_buf.erase(m_rx_buf.begin());
                    if (b == '\n') break;
                }
                m_skip_crlf = false;
            }

            // 4b. Parse next chunk header
            if (!m_reading_chunk_data) {
                while (true) {
                    bool has_lf = false;
                    for (uint8_t b : m_rx_buf) {
                        if (b == '\n') { has_lf = true; break; }
                    }
                    if (has_lf) break;
                    uint8_t tmp[2048];
                    int n = m_underlying->recv_some(tmp, sizeof(tmp));
                    if (n <= 0) return (m_rx_queue.empty() ? n : static_cast<int>(m_rx_queue.size()));
                    m_rx_buf.insert(m_rx_buf.end(), tmp, tmp + n);
                }

                std::string line;
                while (!m_rx_buf.empty()) {
                    uint8_t b = m_rx_buf[0];
                    m_rx_buf.erase(m_rx_buf.begin());
                    if (b == '\n') break;
                    if (b != '\r') line.push_back(static_cast<char>(b));
                }

                size_t first = line.find_first_not_of(" \t");
                if (first == std::string::npos) continue;
                size_t last = line.find_last_not_of(" \t");
                line = line.substr(first, last - first + 1);

                size_t semi = line.find(';');
                if (semi != std::string::npos) line = line.substr(0, semi);

                unsigned long chunk_sz = std::strtoul(line.c_str(), nullptr, 16);
                if (chunk_sz == 0) {
                    m_eof = true;
                    break;
                }

                m_chunk_remaining = static_cast<size_t>(chunk_sz);
                m_reading_chunk_data = true;
            }

            // 4c. Read chunk payload
            if (m_reading_chunk_data) {
                if (m_rx_buf.empty()) {
                    uint8_t tmp[4096];
                    int n = m_underlying->recv_some(tmp, sizeof(tmp));
                    if (n <= 0) return (m_rx_queue.empty() ? n : static_cast<int>(m_rx_queue.size()));
                    m_rx_buf.insert(m_rx_buf.end(), tmp, tmp + n);
                }

                size_t take = (m_rx_buf.size() < m_chunk_remaining) ? m_rx_buf.size() : m_chunk_remaining;
                if (take > 0) {
                    m_rx_queue.insert(m_rx_queue.end(), m_rx_buf.begin(), m_rx_buf.begin() + take);
                    m_rx_buf.erase(m_rx_buf.begin(), m_rx_buf.begin() + take);
                    m_chunk_remaining -= take;
                }

                if (m_chunk_remaining == 0) {
                    m_reading_chunk_data = false;
                    m_skip_crlf = true;
                }
            }
        }

        if (!m_rx_queue.empty()) {
            int take = static_cast<int>(m_rx_queue.size());
            if (take > max_len) take = max_len;
            std::memcpy(buf, m_rx_queue.data(), take);
            m_rx_queue.erase(m_rx_queue.begin(), m_rx_queue.begin() + take);
            return take;
        }

        return m_eof ? 0 : -1;
    }

    void close() override {
        if (!m_eof_sent) {
            m_eof_sent = true;
            if (m_underlying) {
                const char term[] = "0\r\n\r\n";
                m_underlying->send_all(term, sizeof(term) - 1);
                m_underlying->close();
            }
        }
    }

    void shutdown_send() override {
        if (!m_eof_sent) {
            m_eof_sent = true;
            if (m_underlying) {
                const char term[] = "0\r\n\r\n";
                m_underlying->send_all(term, sizeof(term) - 1);
                m_underlying->shutdown_send();
            }
        }
    }
    void set_rcv_timeout(int timeout_ms) override {
        if (m_underlying) m_underlying->set_rcv_timeout(timeout_ms);
    }
};

// ---------------------------------------------------------------------------
// VisionStream: XTLS Vision (xtls-rprx-vision) Flow Stream Wrapper
// ---------------------------------------------------------------------------
class VisionStream : public ITransportStream {
private:
    ITransportStream*    m_underlying;
    uint8_t              m_uuid[16]{};
    bool                 m_uplink_padded = false;
    bool                 m_downlink_padding_active = true;
    std::vector<uint8_t> m_rx_buf;
    std::vector<uint8_t> m_rx_queue;

public:
    VisionStream(ITransportStream* underlying, const uint8_t uuid[16])
        : m_underlying(underlying) {
        if (uuid) std::memcpy(m_uuid, uuid, 16);
    }

    ~VisionStream() override {
        close();
        delete m_underlying;
    }

    bool send_all(const void* buf, int len) override {
        if (!m_underlying) return false;
        if (len <= 0) return true;

        if (!m_uplink_padded) {
            // First uplink packet after VLESS header requires Vision framing:
            // [16 bytes UserUUID][1 byte command = 0x01 (CommandPaddingEnd)][2 bytes contentLen][2 bytes paddingLen][payload][paddingLen bytes 0x00]
            m_uplink_padded = true;
            uint16_t content_len = static_cast<uint16_t>(len);

            // Random padding between 128 and 384 bytes
            uint8_t r_pad = 0;
            reality::secure_random(&r_pad, 1);
            uint16_t pad_len = 128 + static_cast<uint16_t>(r_pad);
            if (content_len + pad_len > 16384) {
                pad_len = 32;
            }

            std::vector<uint8_t> frame;
            frame.reserve(16 + 5 + content_len + pad_len);
            // 1. UUID
            frame.insert(frame.end(), m_uuid, m_uuid + 16);
            // 2. Command = 0x01 (CommandPaddingEnd -> switch to direct raw copy afterwards)
            frame.push_back(0x01);
            // 3. contentLen (2 bytes, big-endian)
            frame.push_back(static_cast<uint8_t>((content_len >> 8) & 0xFF));
            frame.push_back(static_cast<uint8_t>(content_len & 0xFF));
            // 4. paddingLen (2 bytes, big-endian)
            frame.push_back(static_cast<uint8_t>((pad_len >> 8) & 0xFF));
            frame.push_back(static_cast<uint8_t>(pad_len & 0xFF));
            // 5. Payload
            const uint8_t* p = static_cast<const uint8_t*>(buf);
            frame.insert(frame.end(), p, p + content_len);
            // 6. Padding
            frame.insert(frame.end(), pad_len, 0x00);

            return m_underlying->send_all(frame.data(), static_cast<int>(frame.size()));
        }

        // Once padding has ended, all subsequent packets are sent raw (direct copy)
        return m_underlying->send_all(buf, len);
    }

    int recv_some(void* buf, int max_len) override {
        if (!m_underlying) return -1;

        // If padding is no longer active and queue is empty, read directly
        if (!m_downlink_padding_active && m_rx_queue.empty()) {
            return m_underlying->recv_some(buf, max_len);
        }

        // If we have unconsumed payload in m_rx_queue, serve it
        if (!m_rx_queue.empty()) {
            int take = static_cast<int>(m_rx_queue.size());
            if (take > max_len) take = max_len;
            std::memcpy(buf, m_rx_queue.data(), take);
            m_rx_queue.erase(m_rx_queue.begin(), m_rx_queue.begin() + take);
            return take;
        }

        // Process downlink stream
        while (m_rx_queue.empty()) {
            uint8_t temp[4096];
            int n = m_underlying->recv_some(temp, sizeof(temp));
            if (n <= 0) return n;
            m_rx_buf.insert(m_rx_buf.end(), temp, temp + n);

            if (m_downlink_padding_active) {
                // Check if buffer starts with UUID
                size_t offset = 0;
                if (m_rx_buf.size() >= 16 && std::memcmp(m_rx_buf.data(), m_uuid, 16) == 0) {
                    offset = 16;
                }

                while (m_rx_buf.size() >= offset + 5) {
                    uint8_t cmd = m_rx_buf[offset];
                    uint16_t content_len = (static_cast<uint16_t>(m_rx_buf[offset + 1]) << 8) | m_rx_buf[offset + 2];
                    uint16_t pad_len = (static_cast<uint16_t>(m_rx_buf[offset + 3]) << 8) | m_rx_buf[offset + 4];
                    size_t block_total = offset + 5 + content_len + pad_len;

                    if (m_rx_buf.size() < block_total) {
                        // Need more data
                        break;
                    }

                    // Extract content
                    if (content_len > 0) {
                        const uint8_t* cdata = m_rx_buf.data() + offset + 5;
                        m_rx_queue.insert(m_rx_queue.end(), cdata, cdata + content_len);
                    }

                    // Remove this block from m_rx_buf
                    m_rx_buf.erase(m_rx_buf.begin(), m_rx_buf.begin() + block_total);
                    offset = 0; // subsequent blocks inside this connection don't repeat UUID

                    if (cmd == 0x01 || cmd == 0x02) { // CommandPaddingEnd or CommandPaddingDirect
                        m_downlink_padding_active = false;
                        // Any remaining bytes in m_rx_buf are raw payload
                        if (!m_rx_buf.empty()) {
                            m_rx_queue.insert(m_rx_queue.end(), m_rx_buf.begin(), m_rx_buf.end());
                            m_rx_buf.clear();
                        }
                        break;
                    }
                }

                // If not Vision framed or padding ended
                if (!m_downlink_padding_active) {
                    break;
                }
            } else {
                // Direct mode
                m_rx_queue.insert(m_rx_queue.end(), m_rx_buf.begin(), m_rx_buf.end());
                m_rx_buf.clear();
                break;
            }
        }

        if (!m_rx_queue.empty()) {
            int take = static_cast<int>(m_rx_queue.size());
            if (take > max_len) take = max_len;
            std::memcpy(buf, m_rx_queue.data(), take);
            m_rx_queue.erase(m_rx_queue.begin(), m_rx_queue.begin() + take);
            return take;
        }

        return 0;
    }

    void close() override {
        if (m_underlying) {
            m_underlying->close();
        }
    }

    ITransportStream* unwrap_vision() override { return m_underlying; }
    void shutdown_send() override {
        if (m_underlying) m_underlying->shutdown_send();
    }
    void set_rcv_timeout(int timeout_ms) override {
        if (m_underlying) m_underlying->set_rcv_timeout(timeout_ms);
    }
};



