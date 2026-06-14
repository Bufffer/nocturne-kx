#pragma once

// TCP/TLS transport adapter for Nocturne-KX (P2.5).
//
// Drop-in sibling of MemoryTransport (transport.hpp). Operates on the same
// `Session`/`Frame` types — Session handles sequencing, ACK/NAK, and retries;
// this class only carries serialized frames over a real socket+TLS pipe.
//
// Design points:
//   - TLS 1.3 only. Older versions explicitly disabled (SSL_OP_NO_TLSv1_2 etc).
//   - Optional mTLS:
//       * Server: TlsConfig::require_client_cert => SSL_VERIFY_PEER |
//         SSL_VERIFY_FAIL_IF_NO_PEER_CERT and CA bundle for client verification.
//       * Client: TlsConfig::ca_pem_path + TlsConfig::sni_hostname enables
//         SNI + hostname verification (SSL_set1_host).
//   - Framing on top of TLS stream: 4-byte big-endian length prefix, then the
//     output of transport::serialize_frame(). The Session's frame format
//     already self-describes its own length, but length-prefixing makes the
//     reader trivial and bounds the per-call allocation.
//   - Synchronous API: send() and receive_blocking() are blocking calls. The
//     caller decides threading. SSL_MODE_AUTO_RETRY is set so partial reads
//     during renegotiation don't surface as WANT_READ to callers.
//
// Out of scope (intentional): async I/O, ALPN, OCSP stapling, session
// resumption, connection pooling, QUIC. The Session retry mechanism above
// this class handles the application-level reliability we need.

#include "transport.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  using nocturne_tls_socket_t = SOCKET;
  #define NOCTURNE_TLS_INVALID_SOCKET INVALID_SOCKET
  #define NOCTURNE_TLS_SOCKET_ERROR   SOCKET_ERROR
  #define nocturne_tls_close          ::closesocket
#else
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <unistd.h>
  using nocturne_tls_socket_t = int;
  #define NOCTURNE_TLS_INVALID_SOCKET (-1)
  #define NOCTURNE_TLS_SOCKET_ERROR   (-1)
  #define nocturne_tls_close          ::close
#endif

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#ifndef _WIN32
#include <csignal>
#endif

namespace nocturne {
namespace transport {
namespace tls {

struct TlsConfig {
    // Server: cert chain + private key (required to listen).
    // Client: optional, only needed for mTLS.
    std::string cert_pem_path;
    std::string key_pem_path;

    // Trust anchor for verifying the peer (PEM bundle).
    // Server: enables client cert verification.
    // Client: validates the server's cert. If empty, client uses OpenSSL's
    // default trust store (only useful for public CAs).
    std::optional<std::string> ca_pem_path;

    // Server-only: refuse the connection if the client presents no cert.
    bool require_client_cert = false;

    // Client-only: hostname for SNI + RFC 6125 hostname verification.
    // If empty, hostname verification is skipped (test-only path).
    std::string sni_hostname;
};

namespace detail {

inline void ensure_winsock_initialized() {
#ifdef _WIN32
    static std::once_flag flag;
    static int rc = 0;
    std::call_once(flag, []() {
        WSADATA wsa{};
        rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    });
    if (rc != 0) {
        throw std::runtime_error("WSAStartup failed: " + std::to_string(rc));
    }
#endif
}

inline void ensure_openssl_initialized() {
    static std::once_flag flag;
    std::call_once(flag, []() {
        // OpenSSL 1.1+ auto-initializes; this is a no-op on modern versions
        // but keeps things explicit and safe on older builds.
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                         OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

#ifndef _WIN32
        // SSL_write / SSL_shutdown write to the underlying socket fd.
        // If the peer has already closed the connection, the kernel sends
        // SIGPIPE which by default terminates the process — bypassing any
        // C++ exception handler. Ignoring SIGPIPE makes SSL_write return
        // SSL_ERROR_SYSCALL (errno=EPIPE) instead, which we already handle
        // as a runtime_error. Windows does not have SIGPIPE.
        ::signal(SIGPIPE, SIG_IGN);
#endif
    });
}

inline std::string openssl_last_error(const std::string& context) {
    unsigned long e = ERR_peek_last_error();
    if (e == 0) return context + ": (no OpenSSL error in queue)";
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    ERR_clear_error();
    return context + ": " + buf;
}

inline nocturne_tls_socket_t tcp_connect(const std::string& host, uint16_t port) {
    ensure_winsock_initialized();

    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(port);
    struct addrinfo* result = nullptr;
    int rc = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (rc != 0 || result == nullptr) {
        throw std::runtime_error("TLS resolve " + host + ":" + port_str +
                                 " failed: " +
                                 std::string(gai_strerror(rc)));
    }

    nocturne_tls_socket_t sock = NOCTURNE_TLS_INVALID_SOCKET;
    for (struct addrinfo* it = result; it != nullptr; it = it->ai_next) {
        sock = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (sock == NOCTURNE_TLS_INVALID_SOCKET) continue;
        if (::connect(sock, it->ai_addr,
#ifdef _WIN32
                      static_cast<int>(it->ai_addrlen)
#else
                      it->ai_addrlen
#endif
                      ) == 0) {
            break;
        }
        nocturne_tls_close(sock);
        sock = NOCTURNE_TLS_INVALID_SOCKET;
    }
    ::freeaddrinfo(result);

    if (sock == NOCTURNE_TLS_INVALID_SOCKET) {
        throw std::runtime_error("TLS TCP connect to " + host + ":" + port_str +
                                 " failed");
    }
    return sock;
}

inline nocturne_tls_socket_t tcp_listen(const std::string& bind_host,
                                       uint16_t port, uint16_t* out_port) {
    ensure_winsock_initialized();

    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    std::string port_str = std::to_string(port);
    struct addrinfo* result = nullptr;
    int rc = ::getaddrinfo(bind_host.empty() ? nullptr : bind_host.c_str(),
                           port_str.c_str(), &hints, &result);
    if (rc != 0 || result == nullptr) {
        throw std::runtime_error("TLS bind resolve failed: " +
                                 std::string(gai_strerror(rc)));
    }

    nocturne_tls_socket_t sock = ::socket(result->ai_family,
                                          result->ai_socktype,
                                          result->ai_protocol);
    if (sock == NOCTURNE_TLS_INVALID_SOCKET) {
        ::freeaddrinfo(result);
        throw std::runtime_error("TLS listen socket() failed");
    }

    int yes = 1;
    ::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&yes), sizeof(yes));

    if (::bind(sock, result->ai_addr,
#ifdef _WIN32
               static_cast<int>(result->ai_addrlen)
#else
               result->ai_addrlen
#endif
               ) != 0) {
        ::freeaddrinfo(result);
        nocturne_tls_close(sock);
        throw std::runtime_error("TLS bind() failed");
    }
    ::freeaddrinfo(result);

    if (::listen(sock, 8) != 0) {
        nocturne_tls_close(sock);
        throw std::runtime_error("TLS listen() failed");
    }

    if (out_port) {
        struct sockaddr_storage ss{};
        socklen_t len = sizeof(ss);
        if (::getsockname(sock, reinterpret_cast<struct sockaddr*>(&ss),
                          &len) == 0) {
            if (ss.ss_family == AF_INET) {
                *out_port = ntohs(reinterpret_cast<sockaddr_in*>(&ss)->sin_port);
            } else if (ss.ss_family == AF_INET6) {
                *out_port = ntohs(reinterpret_cast<sockaddr_in6*>(&ss)->sin6_port);
            }
        }
    }
    return sock;
}

inline void apply_tls13_only(SSL_CTX* ctx) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                                 SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
                                 SSL_OP_NO_TLSv1_2 |
                                 SSL_OP_NO_COMPRESSION |
                                 SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
}

struct CtxDeleter { void operator()(SSL_CTX* p) const { if (p) SSL_CTX_free(p); } };
struct SslDeleter { void operator()(SSL* p) const { if (p) SSL_free(p); } };
using CtxPtr = std::unique_ptr<SSL_CTX, CtxDeleter>;
using SslPtr = std::unique_ptr<SSL, SslDeleter>;

inline CtxPtr make_server_ctx(const TlsConfig& cfg) {
    ensure_openssl_initialized();
    CtxPtr ctx(SSL_CTX_new(TLS_server_method()));
    if (!ctx) throw std::runtime_error(openssl_last_error("SSL_CTX_new server"));
    apply_tls13_only(ctx.get());

    if (cfg.cert_pem_path.empty() || cfg.key_pem_path.empty()) {
        throw std::runtime_error("TLS server requires cert + key PEM paths");
    }
    if (SSL_CTX_use_certificate_chain_file(ctx.get(),
                                           cfg.cert_pem_path.c_str()) != 1) {
        throw std::runtime_error(openssl_last_error("load server cert"));
    }
    if (SSL_CTX_use_PrivateKey_file(ctx.get(), cfg.key_pem_path.c_str(),
                                    SSL_FILETYPE_PEM) != 1) {
        throw std::runtime_error(openssl_last_error("load server key"));
    }
    if (SSL_CTX_check_private_key(ctx.get()) != 1) {
        throw std::runtime_error("TLS server cert/key mismatch");
    }

    if (cfg.require_client_cert) {
        if (!cfg.ca_pem_path) {
            throw std::runtime_error(
                "TLS server: require_client_cert needs ca_pem_path for verification");
        }
        if (SSL_CTX_load_verify_locations(ctx.get(),
                                          cfg.ca_pem_path->c_str(),
                                          nullptr) != 1) {
            throw std::runtime_error(openssl_last_error("load server CA bundle"));
        }
        SSL_CTX_set_verify(ctx.get(),
                           SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           nullptr);
        SSL_CTX_set_verify_depth(ctx.get(), 4);
    } else {
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    }
    return ctx;
}

inline CtxPtr make_client_ctx(const TlsConfig& cfg) {
    ensure_openssl_initialized();
    CtxPtr ctx(SSL_CTX_new(TLS_client_method()));
    if (!ctx) throw std::runtime_error(openssl_last_error("SSL_CTX_new client"));
    apply_tls13_only(ctx.get());

    if (cfg.ca_pem_path) {
        if (SSL_CTX_load_verify_locations(ctx.get(),
                                          cfg.ca_pem_path->c_str(),
                                          nullptr) != 1) {
            throw std::runtime_error(openssl_last_error("load client CA bundle"));
        }
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_verify_depth(ctx.get(), 4);
    } else {
        // No CA configured: skip verification. Useful for tests against
        // self-signed certs; production callers MUST set ca_pem_path.
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    }

    // Optional client cert (mTLS).
    if (!cfg.cert_pem_path.empty()) {
        if (SSL_CTX_use_certificate_chain_file(ctx.get(),
                                               cfg.cert_pem_path.c_str()) != 1) {
            throw std::runtime_error(openssl_last_error("load client cert"));
        }
        if (cfg.key_pem_path.empty()) {
            throw std::runtime_error("TLS client cert provided without key");
        }
        if (SSL_CTX_use_PrivateKey_file(ctx.get(), cfg.key_pem_path.c_str(),
                                        SSL_FILETYPE_PEM) != 1) {
            throw std::runtime_error(openssl_last_error("load client key"));
        }
    }
    return ctx;
}

} // namespace detail

class TcpTlsTransport;

/**
 * @brief Listens on a TCP port and produces TcpTlsTransport instances per
 *        accepted connection. Owns the SSL_CTX shared across accepts.
 */
class TlsAcceptor {
public:
    TlsAcceptor(const std::string& bind_host, uint16_t port,
                const TlsConfig& cfg)
        : ctx_(detail::make_server_ctx(cfg)) {
        // Assign in the body: local_port_ is declared after listen_sock_,
        // so writing it through tcp_listen's out-param during the member
        // initializer list would be clobbered by its `= 0` default.
        listen_sock_ = detail::tcp_listen(bind_host, port, &local_port_);
    }

    ~TlsAcceptor() { close(); }
    TlsAcceptor(const TlsAcceptor&) = delete;
    TlsAcceptor& operator=(const TlsAcceptor&) = delete;

    uint16_t local_port() const { return local_port_; }

    /**
     * @brief Blocking accept + TLS handshake. Returns a transport bound to
     *        @p sess. Throws on accept or handshake failure.
     */
    TcpTlsTransport accept(Session& sess);

    void close() {
        if (listen_sock_ != NOCTURNE_TLS_INVALID_SOCKET) {
            nocturne_tls_close(listen_sock_);
            listen_sock_ = NOCTURNE_TLS_INVALID_SOCKET;
        }
    }

private:
    detail::CtxPtr ctx_;
    nocturne_tls_socket_t listen_sock_ = NOCTURNE_TLS_INVALID_SOCKET;
    uint16_t local_port_ = 0;

    friend class TcpTlsTransport;
};

class TcpTlsTransport {
public:
    /**
     * @brief Client-side: connect to host:port, perform TLS 1.3 handshake.
     */
    TcpTlsTransport(Session& sess,
                    const std::string& host, uint16_t port,
                    const TlsConfig& cfg)
        : sess_(&sess),
          ctx_(detail::make_client_ctx(cfg)),
          sock_(detail::tcp_connect(host, port)) {
        ssl_.reset(SSL_new(ctx_.get()));
        if (!ssl_) throw std::runtime_error(detail::openssl_last_error("SSL_new"));

        if (SSL_set_fd(ssl_.get(), static_cast<int>(sock_)) != 1) {
            throw std::runtime_error(detail::openssl_last_error("SSL_set_fd"));
        }

        if (!cfg.sni_hostname.empty()) {
            // SNI
            SSL_set_tlsext_host_name(ssl_.get(), cfg.sni_hostname.c_str());
            // RFC 6125 hostname verification (only effective if CA configured).
            if (cfg.ca_pem_path) {
                SSL_set1_host(ssl_.get(), cfg.sni_hostname.c_str());
            }
        }

        if (SSL_connect(ssl_.get()) != 1) {
            throw std::runtime_error(detail::openssl_last_error("TLS connect"));
        }
        open_ = true;
    }

    ~TcpTlsTransport() { close(); }

    TcpTlsTransport(const TcpTlsTransport&) = delete;
    TcpTlsTransport& operator=(const TcpTlsTransport&) = delete;
    TcpTlsTransport(TcpTlsTransport&& other) noexcept
        : sess_(other.sess_),
          ctx_(std::move(other.ctx_)),
          ssl_(std::move(other.ssl_)),
          sock_(other.sock_),
          open_(other.open_) {
        other.sock_ = NOCTURNE_TLS_INVALID_SOCKET;
        other.open_ = false;
    }
    TcpTlsTransport& operator=(TcpTlsTransport&& other) noexcept {
        if (this != &other) {
            close();
            sess_ = other.sess_;
            ctx_ = std::move(other.ctx_);
            ssl_ = std::move(other.ssl_);
            sock_ = other.sock_;
            open_ = other.open_;
            other.sock_ = NOCTURNE_TLS_INVALID_SOCKET;
            other.open_ = false;
        }
        return *this;
    }

    bool is_open() const { return open_; }

    /**
     * @brief Serialize @p f, prefix with 4-byte BE length, push over TLS.
     *        Tracks the frame in Session for retry accounting (consistent
     *        with MemoryTransport::send).
     */
    void send(const Frame& f) {
        if (!open_) throw std::runtime_error("TLS send on closed transport");
        auto raw = serialize_frame(f);
        if (raw.size() > 0xFFFFFFFFu) {
            throw std::runtime_error("TLS frame too large for u32 length");
        }

        std::array<uint8_t, 4> hdr{};
        uint32_t n = static_cast<uint32_t>(raw.size());
        hdr[0] = static_cast<uint8_t>((n >> 24) & 0xFF);
        hdr[1] = static_cast<uint8_t>((n >> 16) & 0xFF);
        hdr[2] = static_cast<uint8_t>((n >> 8) & 0xFF);
        hdr[3] = static_cast<uint8_t>(n & 0xFF);

        write_all(hdr.data(), hdr.size());
        write_all(raw.data(), raw.size());
        sess_->track_sent(f, raw);
    }

    /**
     * @brief Block until one full frame is received and parsed. Returns
     *        std::nullopt on clean peer close.
     */
    std::optional<Frame> receive_blocking() {
        if (!open_) return std::nullopt;

        std::array<uint8_t, 4> hdr{};
        if (!read_all(hdr.data(), hdr.size())) return std::nullopt;

        uint32_t len = (static_cast<uint32_t>(hdr[0]) << 24) |
                       (static_cast<uint32_t>(hdr[1]) << 16) |
                       (static_cast<uint32_t>(hdr[2]) << 8) |
                       static_cast<uint32_t>(hdr[3]);
        // Cap frame size to prevent a malicious peer from forcing a huge
        // allocation. 16 MiB is well above any expected Nocturne frame.
        if (len > (16u * 1024u * 1024u)) {
            throw std::runtime_error("TLS frame length exceeds 16 MiB cap");
        }

        Bytes raw(len);
        if (len > 0 && !read_all(raw.data(), raw.size())) {
            throw std::runtime_error("TLS truncated read mid-frame");
        }
        return parse_frame(raw);
    }

    void close() {
        if (open_ && ssl_) {
            // Best effort: ignore errors during shutdown.
            SSL_shutdown(ssl_.get());
        }
        ssl_.reset();
        ctx_.reset();
        if (sock_ != NOCTURNE_TLS_INVALID_SOCKET) {
            nocturne_tls_close(sock_);
            sock_ = NOCTURNE_TLS_INVALID_SOCKET;
        }
        open_ = false;
    }

private:
    // Server-side ctor used by TlsAcceptor::accept.
    TcpTlsTransport(Session& sess,
                    SSL_CTX* shared_ctx, // not owned; aliased
                    detail::SslPtr ssl,
                    nocturne_tls_socket_t sock)
        : sess_(&sess),
          ctx_(),                   // server ctx is owned by the acceptor
          ssl_(std::move(ssl)),
          sock_(sock),
          open_(true) {
        (void)shared_ctx;
    }

    friend class TlsAcceptor;

    void write_all(const uint8_t* buf, size_t len) {
        size_t off = 0;
        while (off < len) {
            int n = SSL_write(ssl_.get(), buf + off,
                              static_cast<int>(len - off));
            if (n <= 0) {
                throw std::runtime_error(
                    detail::openssl_last_error("TLS SSL_write"));
            }
            off += static_cast<size_t>(n);
        }
    }

    bool read_all(uint8_t* buf, size_t len) {
        size_t off = 0;
        while (off < len) {
            int n = SSL_read(ssl_.get(), buf + off,
                             static_cast<int>(len - off));
            if (n == 0) {
                // Clean close (close_notify). At off=0 this is a graceful EOF
                // between frames; mid-frame it means the peer truncated us.
                if (off == 0) return false;
                throw std::runtime_error("TLS truncated mid-frame");
            }
            if (n < 0) {
                throw std::runtime_error(
                    detail::openssl_last_error("TLS SSL_read"));
            }
            off += static_cast<size_t>(n);
        }
        return true;
    }

    Session* sess_ = nullptr;
    detail::CtxPtr ctx_;       // client owns its ctx; server side is null
    detail::SslPtr ssl_;
    nocturne_tls_socket_t sock_ = NOCTURNE_TLS_INVALID_SOCKET;
    bool open_ = false;
};

inline TcpTlsTransport TlsAcceptor::accept(Session& sess) {
    struct sockaddr_storage peer{};
    socklen_t plen = sizeof(peer);
    nocturne_tls_socket_t client = ::accept(
        listen_sock_, reinterpret_cast<struct sockaddr*>(&peer), &plen);
    if (client == NOCTURNE_TLS_INVALID_SOCKET) {
        throw std::runtime_error("TLS accept() failed");
    }

    detail::SslPtr ssl(SSL_new(ctx_.get()));
    if (!ssl) {
        nocturne_tls_close(client);
        throw std::runtime_error(detail::openssl_last_error("SSL_new server"));
    }
    if (SSL_set_fd(ssl.get(), static_cast<int>(client)) != 1) {
        nocturne_tls_close(client);
        throw std::runtime_error(detail::openssl_last_error("SSL_set_fd server"));
    }
    if (SSL_accept(ssl.get()) != 1) {
        nocturne_tls_close(client);
        throw std::runtime_error(detail::openssl_last_error("TLS handshake"));
    }
    return TcpTlsTransport(sess, ctx_.get(), std::move(ssl), client);
}

} // namespace tls
} // namespace transport
} // namespace nocturne
