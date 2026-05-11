#ifndef NOCTURNE_SECURITY_SIEM_CONNECTOR_HPP
#define NOCTURNE_SECURITY_SIEM_CONNECTOR_HPP

#include "audit_logger.hpp"
#include <sstream>
#include <iomanip>
#include <ctime>
#include <stdexcept>
#include <mutex>
#include <cstring>
#include <cstdint>
#include <string>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  using nocturne_socket_t = SOCKET;
  #define NOCTURNE_INVALID_SOCKET INVALID_SOCKET
  #define NOCTURNE_SOCKET_ERROR   SOCKET_ERROR
  #define nocturne_close_socket   ::closesocket
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <errno.h>
  using nocturne_socket_t = int;
  #define NOCTURNE_INVALID_SOCKET (-1)
  #define NOCTURNE_SOCKET_ERROR   (-1)
  #define nocturne_close_socket   ::close
#endif

#ifdef NOCTURNE_ENABLE_TLS_TRANSPORT
  #include <openssl/ssl.h>
  #include <openssl/err.h>
  #include <memory>
#endif

namespace nocturne {
namespace security {

/**
 * @brief Syslog Facility (RFC 5424)
 */
enum class SyslogFacility {
    KERN = 0,       ///< Kernel messages
    USER = 1,       ///< User-level messages
    MAIL = 2,       ///< Mail system
    DAEMON = 3,     ///< System daemons
    AUTH = 4,       ///< Security/authorization
    SYSLOG = 5,     ///< Internal syslog
    LPR = 6,        ///< Line printer
    NEWS = 7,       ///< Network news
    UUCP = 8,       ///< UUCP subsystem
    CRON = 9,       ///< Cron daemon
    AUTHPRIV = 10,  ///< Security/authorization (private)
    FTP = 11,       ///< FTP daemon
    LOCAL0 = 16,    ///< Local use 0
    LOCAL1 = 17,    ///< Local use 1
    LOCAL2 = 18,    ///< Local use 2
    LOCAL3 = 19,    ///< Local use 3
    LOCAL4 = 20,    ///< Local use 4
    LOCAL5 = 21,    ///< Local use 5
    LOCAL6 = 22,    ///< Local use 6
    LOCAL7 = 23     ///< Local use 7
};

/**
 * @brief SIEM Connector for various SIEM platforms
 */
class SIEMConnector {
private:
    SIEMConfig config_;

    /**
     * @brief Map audit severity to syslog priority
     */
    int audit_to_syslog_priority(AuditSeverity sev) const {
        switch (sev) {
            case AuditSeverity::EMERGENCY: return 0;
            case AuditSeverity::ALERT: return 1;
            case AuditSeverity::CRITICAL: return 2;
            case AuditSeverity::ERROR: return 3;
            case AuditSeverity::WARNING: return 4;
            case AuditSeverity::NOTICE: return 5;
            case AuditSeverity::INFO: return 6;
            case AuditSeverity::DEBUG: return 7;
            case AuditSeverity::SECURITY: return 1; // Map to ALERT
            default: return 6;
        }
    }

    /**
     * @brief Get syslog facility code
     */
    int get_facility_code() const {
        // Default to LOCAL0 (security applications)
        return static_cast<int>(SyslogFacility::LOCAL0);
    }

    /**
     * @brief Format record as RFC 5424 syslog message
     */
    std::string to_syslog_rfc5424(const AuditRecord& record) const {
        std::ostringstream msg;

        // Priority = (Facility * 8) + Severity
        int facility = get_facility_code();
        int priority_value = audit_to_syslog_priority(record.severity);
        int pri = (facility * 8) + priority_value;

        msg << "<" << pri << ">1 "; // Priority + Version

        // Timestamp (ISO 8601)
        auto time_t = std::chrono::system_clock::to_time_t(record.timestamp);
        std::tm tm_buf;
#ifdef _WIN32
        gmtime_s(&tm_buf, &time_t);
#else
        gmtime_r(&time_t, &tm_buf);
#endif
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            record.timestamp.time_since_epoch()).count() % 1000;

        msg << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S");
        msg << "." << std::setfill('0') << std::setw(3) << ms << "Z ";

        // Hostname (use "nocturne-kx" as default)
        msg << config_.application_name << " ";

        // App name
        msg << config_.application_name << " ";

        // Process ID (use sequence number)
        msg << record.sequence_number << " ";

        // Message ID
        msg << record.category << ":" << record.action << " ";

        // Structured data
        msg << "[nocturne@0";
        msg << " cat=\"" << syslog_escape(record.category) << "\"";
        msg << " act=\"" << syslog_escape(record.action) << "\"";
        msg << " sub=\"" << syslog_escape(record.subject) << "\"";
        msg << " obj=\"" << syslog_escape(record.object) << "\"";
        msg << " res=\"" << syslog_escape(record.result) << "\"";
        msg << " seq=\"" << record.sequence_number << "\"";

        if (record.error_code) {
            msg << " err=\"" << syslog_escape(*record.error_code) << "\"";
        }
        if (record.source_ip) {
            msg << " src=\"" << syslog_escape(*record.source_ip) << "\"";
        }

        msg << "] ";

        // Message
        msg << syslog_escape(record.message);

        return msg.str();
    }

    /**
     * @brief Format record as CEF (Common Event Format)
     * Used by ArcSight, Splunk, QRadar
     */
    std::string to_cef(const AuditRecord& record) const {
        std::ostringstream msg;

        // CEF Header: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        msg << "CEF:0|";
        msg << "Anthropic|";                          // Vendor
        msg << "Nocturne-KX|";                        // Product
        msg << "3.0.0|";                              // Version
        msg << record.category << ":" << record.action << "|"; // Signature ID
        msg << record.category << " " << record.action << "|"; // Name

        // CEF Severity (0-10 scale)
        int cef_severity = std::min(10, static_cast<int>(record.severity));
        msg << cef_severity << "|";

        // Extensions (key=value pairs)
        std::vector<std::string> extensions;

        extensions.push_back("act=" + cef_escape(record.action));
        extensions.push_back("cat=" + cef_escape(record.category));
        extensions.push_back("suser=" + cef_escape(record.subject));
        extensions.push_back("duser=" + cef_escape(record.object));
        extensions.push_back("outcome=" + cef_escape(record.result));
        extensions.push_back("msg=" + cef_escape(record.message));

        if (record.error_code) {
            extensions.push_back("reason=" + cef_escape(*record.error_code));
        }
        if (record.source_ip) {
            extensions.push_back("src=" + cef_escape(*record.source_ip));
        }
        if (record.duration_microseconds) {
            extensions.push_back("rt=" + std::to_string(*record.duration_microseconds));
        }
        if (record.bytes_processed) {
            extensions.push_back("in=" + std::to_string(*record.bytes_processed));
        }

        // Custom extensions
        extensions.push_back("cs1Label=SequenceNumber");
        extensions.push_back("cs1=" + std::to_string(record.sequence_number));

        extensions.push_back("cs2Label=Hash");
        extensions.push_back("cs2=" + hex_encode(record.current_hash.data(), 32));

        // Join extensions
        bool first = true;
        for (const auto& ext : extensions) {
            if (!first) msg << " ";
            msg << ext;
            first = false;
        }

        return msg.str();
    }

    /**
     * @brief Format record as LEEF (Log Event Extended Format)
     * Used by IBM QRadar
     */
    std::string to_leef(const AuditRecord& record) const {
        std::ostringstream msg;

        // LEEF Header: LEEF:Version|Vendor|Product|Version|EventID|
        msg << "LEEF:2.0|";
        msg << "Anthropic|";
        msg << "Nocturne-KX|";
        msg << "3.0.0|";
        msg << record.category << ":" << record.action << "|";

        // Attributes (tab-separated key=value pairs)
        std::vector<std::string> attrs;

        attrs.push_back("devTime=" + format_leef_time(record.timestamp));
        attrs.push_back("cat=" + leef_escape(record.category));
        attrs.push_back("action=" + leef_escape(record.action));
        attrs.push_back("usrName=" + leef_escape(record.subject));
        attrs.push_back("resource=" + leef_escape(record.object));
        attrs.push_back("result=" + leef_escape(record.result));
        attrs.push_back("msg=" + leef_escape(record.message));
        attrs.push_back("sev=" + std::to_string(static_cast<int>(record.severity)));
        attrs.push_back("seq=" + std::to_string(record.sequence_number));

        if (record.error_code) {
            attrs.push_back("reason=" + leef_escape(*record.error_code));
        }
        if (record.source_ip) {
            attrs.push_back("srcIP=" + leef_escape(*record.source_ip));
        }

        // Join with tabs
        for (size_t i = 0; i < attrs.size(); ++i) {
            if (i > 0) msg << "\t";
            msg << attrs[i];
        }

        return msg.str();
    }

    /**
     * @brief Format record for Splunk HEC (HTTP Event Collector)
     */
    std::string to_splunk_hec(const AuditRecord& record) const {
        std::ostringstream json;

        json << "{";
        json << "\"time\":" << std::chrono::duration_cast<std::chrono::seconds>(
            record.timestamp.time_since_epoch()).count() << ",";
        json << "\"host\":\"" << config_.application_name << "\",";
        json << "\"source\":\"nocturne-kx\",";
        json << "\"sourcetype\":\"nocturne:audit\",";
        json << "\"event\":{";
        json << "\"seq\":" << record.sequence_number << ",";
        json << "\"severity\":\"" << severity_to_string(record.severity) << "\",";
        json << "\"category\":\"" << json_escape(record.category) << "\",";
        json << "\"action\":\"" << json_escape(record.action) << "\",";
        json << "\"subject\":\"" << json_escape(record.subject) << "\",";
        json << "\"object\":\"" << json_escape(record.object) << "\",";
        json << "\"result\":\"" << json_escape(record.result) << "\",";
        json << "\"message\":\"" << json_escape(record.message) << "\"";

        if (record.error_code) {
            json << ",\"error_code\":\"" << json_escape(*record.error_code) << "\"";
        }
        if (record.source_ip) {
            json << ",\"source_ip\":\"" << json_escape(*record.source_ip) << "\"";
        }

        json << "}";
        json << "}";

        return json.str();
    }

    /**
     * @brief Escape string for syslog
     */
    std::string syslog_escape(const std::string& s) const {
        std::ostringstream escaped;
        for (char c : s) {
            if (c == '"' || c == '\\' || c == ']') {
                escaped << '\\';
            }
            escaped << c;
        }
        return escaped.str();
    }

    /**
     * @brief Escape string for CEF
     */
    std::string cef_escape(const std::string& s) const {
        std::ostringstream escaped;
        for (char c : s) {
            if (c == '\\' || c == '=' || c == '\n' || c == '\r') {
                escaped << '\\';
            }
            escaped << c;
        }
        return escaped.str();
    }

    /**
     * @brief Escape string for LEEF
     */
    std::string leef_escape(const std::string& s) const {
        std::ostringstream escaped;
        for (char c : s) {
            if (c == '\\' || c == '\t' || c == '\n' || c == '\r') {
                escaped << '\\';
            }
            escaped << c;
        }
        return escaped.str();
    }

    /**
     * @brief JSON escape
     */
    std::string json_escape(const std::string& s) const {
        std::ostringstream escaped;
        for (char c : s) {
            switch (c) {
                case '"': escaped << "\\\""; break;
                case '\\': escaped << "\\\\"; break;
                case '\b': escaped << "\\b"; break;
                case '\f': escaped << "\\f"; break;
                case '\n': escaped << "\\n"; break;
                case '\r': escaped << "\\r"; break;
                case '\t': escaped << "\\t"; break;
                default: escaped << c;
            }
        }
        return escaped.str();
    }

    /**
     * @brief Hex encode
     */
    std::string hex_encode(const uint8_t* data, size_t len) const {
        static const char* hex_chars = "0123456789abcdef";
        std::string hex;
        hex.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) {
            hex.push_back(hex_chars[(data[i] >> 4) & 0x0F]);
            hex.push_back(hex_chars[data[i] & 0x0F]);
        }
        return hex;
    }

    /**
     * @brief Format timestamp for LEEF
     */
    std::string format_leef_time(std::chrono::system_clock::time_point tp) const {
        auto time_t = std::chrono::system_clock::to_time_t(tp);
        std::tm tm_buf;
#ifdef _WIN32
        gmtime_s(&tm_buf, &time_t);
#else
        gmtime_r(&time_t, &tm_buf);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    /**
     * @brief Severity to string
     */
    const char* severity_to_string(AuditSeverity sev) const {
        switch (sev) {
            case AuditSeverity::DEBUG: return "DEBUG";
            case AuditSeverity::INFO: return "INFO";
            case AuditSeverity::NOTICE: return "NOTICE";
            case AuditSeverity::WARNING: return "WARNING";
            case AuditSeverity::ERROR: return "ERROR";
            case AuditSeverity::CRITICAL: return "CRITICAL";
            case AuditSeverity::ALERT: return "ALERT";
            case AuditSeverity::EMERGENCY: return "EMERGENCY";
            case AuditSeverity::SECURITY: return "SECURITY";
            default: return "UNKNOWN";
        }
    }

    // ========================================================================
    // Network transport (P2.6)
    // ========================================================================

    static void ensure_winsock_initialized() {
#ifdef _WIN32
        static std::once_flag init_flag;
        static int init_result = 0;
        std::call_once(init_flag, []() {
            WSADATA wsa{};
            init_result = WSAStartup(MAKEWORD(2, 2), &wsa);
        });
        if (init_result != 0) {
            throw std::runtime_error("WSAStartup failed: " + std::to_string(init_result));
        }
#endif
    }

    /**
     * @brief Resolve host+port; returns getaddrinfo result chain (must be freed).
     *        Throws on failure with a host:port-tagged message.
     */
    static struct addrinfo* resolve(const std::string& host,
                                    uint16_t port,
                                    int socktype) {
        struct addrinfo hints{};
        hints.ai_family = AF_UNSPEC;        // v4 or v6
        hints.ai_socktype = socktype;
        hints.ai_protocol = (socktype == SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP;

        std::string port_str = std::to_string(port);
        struct addrinfo* result = nullptr;
        int rc = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
        if (rc != 0 || result == nullptr) {
            const char* msg = gai_strerror(rc);
            throw std::runtime_error(std::string("SIEM resolve ") + host + ":" +
                                     port_str + " failed: " + (msg ? msg : "unknown"));
        }
        return result;
    }

    /**
     * @brief Send a UDP datagram to host:port. Throws on socket/sendto failure.
     */
    static void udp_send_to(const std::string& host,
                            uint16_t port,
                            const std::string& payload) {
        ensure_winsock_initialized();
        struct addrinfo* ai = resolve(host, port, SOCK_DGRAM);

        nocturne_socket_t sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock == NOCTURNE_INVALID_SOCKET) {
            ::freeaddrinfo(ai);
            throw std::runtime_error("SIEM UDP socket() failed");
        }

        // RFC 5424 hard cap is 8192 bytes for UDP transport with TLS, and
        // implementations MUST accept ≥480. Anything larger risks fragmentation
        // and silent SIEM-side drops, so refuse rather than truncate.
        if (payload.size() > 8192) {
            nocturne_close_socket(sock);
            ::freeaddrinfo(ai);
            throw std::runtime_error("SIEM UDP payload exceeds 8192 bytes");
        }

#ifdef _WIN32
        int sent = ::sendto(sock, payload.data(), static_cast<int>(payload.size()),
                            0, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
#else
        ssize_t sent = ::sendto(sock, payload.data(), payload.size(),
                                0, ai->ai_addr, ai->ai_addrlen);
#endif
        nocturne_close_socket(sock);
        ::freeaddrinfo(ai);

        if (sent == NOCTURNE_SOCKET_ERROR ||
            static_cast<size_t>(sent) != payload.size()) {
            throw std::runtime_error("SIEM UDP sendto() failed or truncated");
        }
    }

    /**
     * @brief Send a TCP message to host:port using RFC 6587 octet-counting
     *        framing (`<len> <msg>`). Single-shot connect/send/close — keep-alive
     *        and retries are explicitly out of scope here; the caller (audit
     *        logger) reports failures via `on_error_`.
     */
    static void tcp_send_to(const std::string& host,
                            uint16_t port,
                            const std::string& payload,
                            bool octet_counting_frame) {
        ensure_winsock_initialized();
        struct addrinfo* ai = resolve(host, port, SOCK_STREAM);

        nocturne_socket_t sock = NOCTURNE_INVALID_SOCKET;
        struct addrinfo* it = ai;
        for (; it != nullptr; it = it->ai_next) {
            sock = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
            if (sock == NOCTURNE_INVALID_SOCKET) continue;
            if (::connect(sock, it->ai_addr,
#ifdef _WIN32
                          static_cast<int>(it->ai_addrlen)
#else
                          it->ai_addrlen
#endif
                          ) == 0) {
                break;
            }
            nocturne_close_socket(sock);
            sock = NOCTURNE_INVALID_SOCKET;
        }
        ::freeaddrinfo(ai);

        if (sock == NOCTURNE_INVALID_SOCKET) {
            throw std::runtime_error("SIEM TCP connect to " + host + ":" +
                                     std::to_string(port) + " failed");
        }

        std::string framed;
        if (octet_counting_frame) {
            // RFC 6587 §3.4.1: MSG-LEN SP SYSLOG-MSG
            framed.reserve(payload.size() + 16);
            framed += std::to_string(payload.size());
            framed += ' ';
            framed += payload;
        } else {
            // Non-transparent framing (RFC 6587 §3.4.2): trailing LF
            framed.reserve(payload.size() + 1);
            framed += payload;
            framed += '\n';
        }

        const char* buf = framed.data();
        size_t remaining = framed.size();
        while (remaining > 0) {
#ifdef _WIN32
            int chunk = ::send(sock, buf, static_cast<int>(remaining), 0);
#else
            ssize_t chunk = ::send(sock, buf, remaining, MSG_NOSIGNAL);
#endif
            if (chunk == NOCTURNE_SOCKET_ERROR || chunk == 0) {
                nocturne_close_socket(sock);
                throw std::runtime_error("SIEM TCP send() failed");
            }
            buf += chunk;
            remaining -= static_cast<size_t>(chunk);
        }

        nocturne_close_socket(sock);
    }

#ifdef NOCTURNE_ENABLE_TLS_TRANSPORT
    /**
     * @brief Send a syslog payload over TLS 1.3 (RFC 5425).
     *
     * Mirrors the connection setup style of src/tcp_tls_transport.hpp:
     * TLS 1.3 only, no compression, peer verification when a CA bundle
     * is supplied, optional mTLS via client cert+key. Framing matches
     * tcp_send_to's octet-counting choice — RFC 5425 explicitly mandates
     * octet-counting framing for syslog-over-TLS, so callers should
     * pass octet_counting_frame=true.
     */
    static void tls_send_to(const std::string& host,
                            uint16_t port,
                            const std::string& payload,
                            const std::optional<std::string>& ca_cert_path,
                            const std::optional<std::string>& client_cert_path,
                            const std::optional<std::string>& client_key_path,
                            bool octet_counting_frame) {
        ensure_winsock_initialized();

        // SSL_library_init / OPENSSL_init_ssl is a no-op after OpenSSL 1.1
        // is initialized on first use; relying on that here.
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(
            SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
        if (!ctx) {
            throw std::runtime_error("SIEM TLS: SSL_CTX_new failed");
        }
        // TLS 1.3 only — same posture as src/tcp_tls_transport.hpp.
        SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);
        SSL_CTX_set_options(ctx.get(),
                            SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                            SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
                            SSL_OP_NO_TLSv1_2 | SSL_OP_NO_COMPRESSION);
        SSL_CTX_set_mode(ctx.get(), SSL_MODE_AUTO_RETRY);

        if (ca_cert_path) {
            if (SSL_CTX_load_verify_locations(ctx.get(),
                                              ca_cert_path->c_str(),
                                              nullptr) != 1) {
                throw std::runtime_error(
                    "SIEM TLS: failed to load CA bundle from " + *ca_cert_path);
            }
            SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
        } else {
            // No CA → accept any cert. SIEM operators that need peer
            // verification must populate ca_cert_path in SIEMConfig.
            SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
        }

        if (client_cert_path && client_key_path) {
            if (SSL_CTX_use_certificate_file(ctx.get(),
                                             client_cert_path->c_str(),
                                             SSL_FILETYPE_PEM) != 1) {
                throw std::runtime_error(
                    "SIEM TLS: failed to load client cert " + *client_cert_path);
            }
            if (SSL_CTX_use_PrivateKey_file(ctx.get(),
                                            client_key_path->c_str(),
                                            SSL_FILETYPE_PEM) != 1) {
                throw std::runtime_error(
                    "SIEM TLS: failed to load client key " + *client_key_path);
            }
            if (SSL_CTX_check_private_key(ctx.get()) != 1) {
                throw std::runtime_error(
                    "SIEM TLS: client cert and key mismatch");
            }
        }

        struct addrinfo* ai = resolve(host, port, SOCK_STREAM);

        nocturne_socket_t sock = NOCTURNE_INVALID_SOCKET;
        for (auto* it = ai; it != nullptr; it = it->ai_next) {
            sock = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
            if (sock == NOCTURNE_INVALID_SOCKET) continue;
            if (::connect(sock, it->ai_addr,
#ifdef _WIN32
                          static_cast<int>(it->ai_addrlen)
#else
                          it->ai_addrlen
#endif
                          ) == 0) {
                break;
            }
            nocturne_close_socket(sock);
            sock = NOCTURNE_INVALID_SOCKET;
        }
        ::freeaddrinfo(ai);

        if (sock == NOCTURNE_INVALID_SOCKET) {
            throw std::runtime_error("SIEM TLS connect to " + host + ":" +
                                     std::to_string(port) + " failed");
        }

        std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx.get()), SSL_free);
        if (!ssl) {
            nocturne_close_socket(sock);
            throw std::runtime_error("SIEM TLS: SSL_new failed");
        }

        // SNI + hostname verification (only when CA is provided — without
        // a CA, hostname checks would be misleading).
        SSL_set_tlsext_host_name(ssl.get(), host.c_str());
        if (ca_cert_path) {
            if (SSL_set1_host(ssl.get(), host.c_str()) != 1) {
                nocturne_close_socket(sock);
                throw std::runtime_error("SIEM TLS: SSL_set1_host failed");
            }
        }

        SSL_set_fd(ssl.get(), static_cast<int>(sock));
        if (SSL_connect(ssl.get()) != 1) {
            unsigned long err = ERR_get_error();
            char buf[256] = {0};
            ERR_error_string_n(err, buf, sizeof(buf));
            nocturne_close_socket(sock);
            throw std::runtime_error(std::string("SIEM TLS handshake failed: ") + buf);
        }

        std::string framed;
        if (octet_counting_frame) {
            framed.reserve(payload.size() + 16);
            framed += std::to_string(payload.size());
            framed += ' ';
            framed += payload;
        } else {
            framed.reserve(payload.size() + 1);
            framed += payload;
            framed += '\n';
        }

        const char* buf = framed.data();
        size_t remaining = framed.size();
        while (remaining > 0) {
            int chunk = SSL_write(ssl.get(), buf, static_cast<int>(remaining));
            if (chunk <= 0) {
                int err = SSL_get_error(ssl.get(), chunk);
                SSL_shutdown(ssl.get());
                nocturne_close_socket(sock);
                throw std::runtime_error(
                    "SIEM TLS SSL_write failed (err=" + std::to_string(err) + ")");
            }
            buf += chunk;
            remaining -= static_cast<size_t>(chunk);
        }

        SSL_shutdown(ssl.get());
        nocturne_close_socket(sock);
    }
#endif // NOCTURNE_ENABLE_TLS_TRANSPORT

public:
    explicit SIEMConnector(const SIEMConfig& config) : config_(config) {}

    /**
     * @brief Send record to SIEM (synchronous; AuditLogger wraps this in
     *        try/catch and routes failures through on_error_).
     *
     * Transports (P2.6):
     *   SYSLOG_UDP, CEF, LEEF → UDP datagram, RFC 5424 / CEF / LEEF body
     *   SYSLOG_TCP            → TCP, RFC 6587 octet-counting
     *
     * Not yet wired (require optional deps; deferred to P2.5/P3):
     *   SYSLOG_TLS    → needs OpenSSL (planned alongside TcpTlsTransport)
     *   SPLUNK_HEC    → needs libcurl HTTPS POST
     *   ELASTICSEARCH → needs libcurl HTTPS POST
     *   KAFKA         → needs librdkafka
     *   CUSTOM        → needs libcurl
     */
    void send(const AuditRecord& record) {
        if (config_.type == SIEMType::NONE) return;
        if (config_.host.empty()) {
            throw std::runtime_error("SIEM host not configured");
        }

        std::string formatted;

        switch (config_.type) {
            case SIEMType::SYSLOG_UDP:
            case SIEMType::SYSLOG_TCP:
            case SIEMType::SYSLOG_TLS:
                formatted = to_syslog_rfc5424(record);
                break;

            case SIEMType::CEF:
                formatted = to_cef(record);
                break;

            case SIEMType::LEEF:
                formatted = to_leef(record);
                break;

            case SIEMType::SPLUNK_HEC:
                formatted = to_splunk_hec(record);
                break;

            default:
                throw std::runtime_error(
                    "SIEM transport not yet wired in this build");
        }

        switch (config_.type) {
            case SIEMType::SYSLOG_UDP:
            case SIEMType::CEF:
            case SIEMType::LEEF:
                // CEF / LEEF are typically transported over syslog UDP. The
                // formatted body itself is fully parseable by ArcSight/QRadar.
                udp_send_to(config_.host, config_.port, formatted);
                return;

            case SIEMType::SYSLOG_TCP:
                tcp_send_to(config_.host, config_.port, formatted,
                            /*octet_counting_frame=*/true);
                return;

            case SIEMType::SYSLOG_TLS:
#ifdef NOCTURNE_ENABLE_TLS_TRANSPORT
                tls_send_to(config_.host, config_.port, formatted,
                            config_.ca_cert_path,
                            config_.client_cert_path,
                            config_.client_key_path,
                            /*octet_counting_frame=*/true);
                return;
#else
                throw std::runtime_error(
                    "SIEM SYSLOG_TLS requires the build to be compiled with "
                    "ENABLE_TLS_TRANSPORT=ON (OpenSSL not linked)");
#endif

            case SIEMType::SPLUNK_HEC:
                throw std::runtime_error(
                    "SIEM SPLUNK_HEC not yet wired (libcurl pending)");

            case SIEMType::ELASTICSEARCH:
                throw std::runtime_error(
                    "SIEM ELASTICSEARCH not yet wired (libcurl pending)");

            case SIEMType::KAFKA:
                throw std::runtime_error(
                    "SIEM KAFKA not yet wired (librdkafka pending)");

            case SIEMType::CUSTOM:
                throw std::runtime_error(
                    "SIEM CUSTOM webhook not yet wired (libcurl pending)");

            default:
                throw std::runtime_error("SIEM transport unknown");
        }
    }

    /**
     * @brief Format record for specific SIEM type
     */
    std::string format(const AuditRecord& record, SIEMType type) const {
        switch (type) {
            case SIEMType::SYSLOG_UDP:
            case SIEMType::SYSLOG_TCP:
            case SIEMType::SYSLOG_TLS:
                return to_syslog_rfc5424(record);

            case SIEMType::CEF:
                return to_cef(record);

            case SIEMType::LEEF:
                return to_leef(record);

            case SIEMType::SPLUNK_HEC:
                return to_splunk_hec(record);

            default:
                return "";
        }
    }
};

} // namespace security
} // namespace nocturne

#endif // NOCTURNE_SECURITY_SIEM_CONNECTOR_HPP
