// SIEM connector network transport tests (P2.6).
//
// Verifies that SIEMConnector::send() actually pushes bytes over the wire for
// the transports we wired up: SYSLOG_UDP, SYSLOG_TCP (RFC 6587 octet-counting),
// CEF, LEEF, and (when NOCTURNE_ENABLE_TLS_TRANSPORT is defined at build time)
// SYSLOG_TLS. Stubbed transports (SPLUNK_HEC / ELASTICSEARCH / KAFKA / CUSTOM)
// are exercised separately to confirm they throw the expected "not yet wired"
// error so the AuditLogger error callback path stays sane.
//
// POSIX-only: CI runs on Ubuntu, and the user's local box is Windows-without-
// libsodium, so guarding with #ifdef _WIN32 is enough to keep the build green.

#include <catch2/catch_test_macros.hpp>

#include "security/siem_connector.hpp"

#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using nocturne::security::AuditRecord;
using nocturne::security::AuditSeverity;
using nocturne::security::SIEMConfig;
using nocturne::security::SIEMConnector;
using nocturne::security::SIEMType;

namespace {

AuditRecord make_record(const std::string& msg) {
    AuditRecord r;
    r.sequence_number = 42;
    r.timestamp = std::chrono::system_clock::now();
    r.severity = AuditSeverity::WARNING;
    r.category = "CRYPTO";
    r.action = "DECRYPT";
    r.subject = "alice";
    r.object = "session-1";
    r.result = "SUCCESS";
    r.message = msg;
    return r;
}

#ifndef _WIN32
// Open a UDP socket bound to 127.0.0.1:0 and return (fd, port).
struct UdpListener {
    int fd = -1;
    uint16_t port = 0;

    UdpListener() {
        fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        REQUIRE(fd >= 0);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        REQUIRE(::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

        sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        REQUIRE(::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &len) == 0);
        port = ntohs(bound.sin_port);

        // 2-second receive timeout — if send() silently fails, we don't hang CI.
        timeval tv{2, 0};
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    ~UdpListener() { if (fd >= 0) ::close(fd); }
    UdpListener(const UdpListener&) = delete;
    UdpListener& operator=(const UdpListener&) = delete;

    std::string recv_one() {
        char buf[8192];
        ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0, nullptr, nullptr);
        if (n <= 0) return {};
        return std::string(buf, static_cast<size_t>(n));
    }
};

struct TcpListener {
    int fd = -1;
    uint16_t port = 0;

    TcpListener() {
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        REQUIRE(fd >= 0);

        int yes = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        REQUIRE(::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
        REQUIRE(::listen(fd, 1) == 0);

        sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        REQUIRE(::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &len) == 0);
        port = ntohs(bound.sin_port);
    }
    ~TcpListener() { if (fd >= 0) ::close(fd); }
    TcpListener(const TcpListener&) = delete;
    TcpListener& operator=(const TcpListener&) = delete;

    // Accept exactly one connection, drain to EOF, return all bytes.
    std::string accept_and_drain() {
        timeval tv{2, 0};
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int client = ::accept(fd, nullptr, nullptr);
        if (client < 0) return {};

        ::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        std::string out;
        char buf[4096];
        while (true) {
            ssize_t n = ::recv(client, buf, sizeof(buf), 0);
            if (n <= 0) break;
            out.append(buf, static_cast<size_t>(n));
        }
        ::close(client);
        return out;
    }
};
#endif // !_WIN32

} // namespace

#ifndef _WIN32

TEST_CASE("SIEMConnector sends RFC 5424 syslog over UDP", "[siem][network]") {
    UdpListener listener;

    SIEMConfig cfg;
    cfg.type = SIEMType::SYSLOG_UDP;
    cfg.host = "127.0.0.1";
    cfg.port = listener.port;
    cfg.application_name = "nocturne-test";

    SIEMConnector conn(cfg);
    auto rec = make_record("hello-udp-syslog");
    REQUIRE_NOTHROW(conn.send(rec));

    std::string payload = listener.recv_one();
    REQUIRE_FALSE(payload.empty());
    // RFC 5424 prefix: "<PRI>1 ..."
    REQUIRE(payload[0] == '<');
    REQUIRE(payload.find(">1 ") != std::string::npos);
    REQUIRE(payload.find("nocturne-test") != std::string::npos);
    REQUIRE(payload.find("hello-udp-syslog") != std::string::npos);
    REQUIRE(payload.find("CRYPTO:DECRYPT") != std::string::npos);
}

TEST_CASE("SIEMConnector sends CEF over UDP", "[siem][network]") {
    UdpListener listener;

    SIEMConfig cfg;
    cfg.type = SIEMType::CEF;
    cfg.host = "127.0.0.1";
    cfg.port = listener.port;

    SIEMConnector conn(cfg);
    auto rec = make_record("cef-event-body");
    REQUIRE_NOTHROW(conn.send(rec));

    std::string payload = listener.recv_one();
    REQUIRE_FALSE(payload.empty());
    REQUIRE(payload.rfind("CEF:0|", 0) == 0);
    REQUIRE(payload.find("Nocturne-KX") != std::string::npos);
    REQUIRE(payload.find("cef-event-body") != std::string::npos);
}

TEST_CASE("SIEMConnector sends LEEF over UDP", "[siem][network]") {
    UdpListener listener;

    SIEMConfig cfg;
    cfg.type = SIEMType::LEEF;
    cfg.host = "127.0.0.1";
    cfg.port = listener.port;

    SIEMConnector conn(cfg);
    auto rec = make_record("leef-event-body");
    REQUIRE_NOTHROW(conn.send(rec));

    std::string payload = listener.recv_one();
    REQUIRE_FALSE(payload.empty());
    REQUIRE(payload.rfind("LEEF:2.0|", 0) == 0);
    REQUIRE(payload.find("leef-event-body") != std::string::npos);
}

TEST_CASE("SIEMConnector sends RFC 5424 syslog over TCP with octet-counting framing",
          "[siem][network]") {
    TcpListener listener;

    SIEMConfig cfg;
    cfg.type = SIEMType::SYSLOG_TCP;
    cfg.host = "127.0.0.1";
    cfg.port = listener.port;
    cfg.application_name = "nocturne-test";

    std::string received;
    std::thread server([&] { received = listener.accept_and_drain(); });

    // Tiny pause so accept() is parked before connect() races in.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    SIEMConnector conn(cfg);
    auto rec = make_record("hello-tcp-syslog");
    REQUIRE_NOTHROW(conn.send(rec));

    server.join();

    REQUIRE_FALSE(received.empty());

    // RFC 6587 §3.4.1: MSG-LEN SP SYSLOG-MSG.
    auto sp = received.find(' ');
    REQUIRE(sp != std::string::npos);
    auto len_str = received.substr(0, sp);
    auto msg = received.substr(sp + 1);
    REQUIRE_FALSE(len_str.empty());
    for (char c : len_str) REQUIRE(std::isdigit(static_cast<unsigned char>(c)));
    REQUIRE(std::stoul(len_str) == msg.size());

    REQUIRE(msg[0] == '<');
    REQUIRE(msg.find("hello-tcp-syslog") != std::string::npos);
    REQUIRE(msg.find("nocturne-test") != std::string::npos);
}

#endif // !_WIN32

TEST_CASE("SIEMConnector throws on unwired transports", "[siem][network]") {
    auto rec = make_record("body");

    auto try_type = [&](SIEMType type) {
        SIEMConfig cfg;
        cfg.type = type;
        cfg.host = "127.0.0.1";
        cfg.port = 1; // never reached — should throw before/at connect
        SIEMConnector conn(cfg);
        REQUIRE_THROWS_AS(conn.send(rec), std::runtime_error);
    };

    // SYSLOG_TLS is "wired" when ENABLE_TLS_TRANSPORT is on, but the
    // exception still fires — port 1 is unbound so the TLS dial fails
    // with "TLS connect ... failed" instead of the stub's "not wired"
    // message. Either flavor is std::runtime_error.
    try_type(SIEMType::SYSLOG_TLS);

    try_type(SIEMType::SPLUNK_HEC);
    try_type(SIEMType::ELASTICSEARCH);
    try_type(SIEMType::KAFKA);
    try_type(SIEMType::CUSTOM);
}

#ifdef NOCTURNE_ENABLE_TLS_TRANSPORT
// When OpenSSL is in the build, SYSLOG_TLS is no longer a stub. We don't
// stand up a self-signed acceptor here (the dedicated tcp-tls-transport-
// test target already covers full TLS 1.3 loopback); just confirm the
// error path is the TLS dial path, not the "not yet wired" stub —
// otherwise a build that silently lost the OpenSSL link would regress
// to stub behavior without any test catching it.
TEST_CASE("SIEMConnector SYSLOG_TLS reaches the TLS code path", "[siem][tls]") {
    SIEMConfig cfg;
    cfg.type = SIEMType::SYSLOG_TLS;
    cfg.host = "127.0.0.1";
    cfg.port = 1;  // unreachable — connect must fail
    SIEMConnector conn(cfg);
    auto rec = make_record("tls-probe");
    try {
        conn.send(rec);
        FAIL("expected SYSLOG_TLS send to throw on port 1");
    } catch (const std::runtime_error& e) {
        std::string what = e.what();
        // Either "SIEM TLS connect to 127.0.0.1:1 failed" (couldn't
        // dial) or a handshake error. Both prove we left the stub.
        REQUIRE(what.find("not yet wired") == std::string::npos);
        REQUIRE(what.find("TLS") != std::string::npos);
    }
}
#endif // NOCTURNE_ENABLE_TLS_TRANSPORT

TEST_CASE("SIEMConnector NONE is a silent no-op", "[siem][network]") {
    SIEMConfig cfg;
    cfg.type = SIEMType::NONE;

    SIEMConnector conn(cfg);
    auto rec = make_record("ignored");
    REQUIRE_NOTHROW(conn.send(rec));
}

TEST_CASE("SIEMConnector throws when host is missing", "[siem][network]") {
    SIEMConfig cfg;
    cfg.type = SIEMType::SYSLOG_UDP;
    cfg.host = ""; // empty
    cfg.port = 514;

    SIEMConnector conn(cfg);
    auto rec = make_record("ignored");
    REQUIRE_THROWS_AS(conn.send(rec), std::runtime_error);
}

TEST_CASE("SIEMConnector format() returns body without sending", "[siem][format]") {
    SIEMConfig cfg;
    cfg.type = SIEMType::CEF;
    cfg.host = "127.0.0.1";
    cfg.port = 514;

    SIEMConnector conn(cfg);
    auto rec = make_record("dry-run");

    auto cef = conn.format(rec, SIEMType::CEF);
    REQUIRE(cef.rfind("CEF:0|", 0) == 0);

    auto syslog = conn.format(rec, SIEMType::SYSLOG_UDP);
    REQUIRE(syslog[0] == '<');
}
