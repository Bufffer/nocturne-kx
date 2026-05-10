// TCP/TLS transport adapter loopback tests (P2.5).
//
// In-process roundtrip: a server thread accepts on 127.0.0.1, client connects,
// frames travel through the actual TLS pipe, parse_frame round-trips them.
// Self-signed Ed25519 X.509 cert is generated on the fly with the OpenSSL EVP
// API and written to a tempdir for SSL_CTX_use_certificate_chain_file().
//
// Tests:
//   1. Plain TLS 1.3 — no client cert, client skips peer verification.
//   2. mTLS — server requires client cert; same self-signed pair acts as
//      both server cert and client cert (OK for a loopback test).
//   3. Bad cert path is rejected up front.
//
// POSIX-only at compile time (matches MemoryTransport's CI surface).

#include <catch2/catch_test_macros.hpp>

#include "tcp_tls_transport.hpp"
#include "transport.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <future>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

using nocturne::transport::Bytes;
using nocturne::transport::DataPayload;
using nocturne::transport::FeatureSet;
using nocturne::transport::Frame;
using nocturne::transport::FrameType;
using nocturne::transport::Session;
using nocturne::transport::tls::TcpTlsTransport;
using nocturne::transport::tls::TlsAcceptor;
using nocturne::transport::tls::TlsConfig;

namespace {

// Generate an Ed25519 self-signed cert (CN=localhost) and write cert + key
// to the given file paths in PEM. Throws on any OpenSSL failure — we do not
// expect this to fail on Ubuntu CI.
void generate_self_signed_pem(const std::string& cert_path,
                              const std::string& key_path) {
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    REQUIRE(kctx != nullptr);
    REQUIRE(EVP_PKEY_keygen_init(kctx) == 1);
    EVP_PKEY* pkey = nullptr;
    REQUIRE(EVP_PKEY_keygen(kctx, &pkey) == 1);
    EVP_PKEY_CTX_free(kctx);
    REQUIRE(pkey != nullptr);

    X509* x = X509_new();
    REQUIRE(x != nullptr);
    REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(x), 1) == 1);
    REQUIRE(X509_gmtime_adj(X509_getm_notBefore(x), 0) != nullptr);
    REQUIRE(X509_gmtime_adj(X509_getm_notAfter(x), 60 * 60 * 24) != nullptr);
    REQUIRE(X509_set_pubkey(x, pkey) == 1);

    X509_NAME* name = X509_get_subject_name(x);
    REQUIRE(X509_NAME_add_entry_by_txt(
                name, "CN", MBSTRING_ASC,
                reinterpret_cast<const unsigned char*>("localhost"),
                -1, -1, 0) == 1);
    REQUIRE(X509_set_issuer_name(x, name) == 1);

    // Ed25519 self-sign requires nullptr digest.
    REQUIRE(X509_sign(x, pkey, nullptr) > 0);

    {
        FILE* f = std::fopen(key_path.c_str(), "wb");
        REQUIRE(f != nullptr);
        REQUIRE(PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0,
                                     nullptr, nullptr) == 1);
        std::fclose(f);
    }
    {
        FILE* f = std::fopen(cert_path.c_str(), "wb");
        REQUIRE(f != nullptr);
        REQUIRE(PEM_write_X509(f, x) == 1);
        std::fclose(f);
    }

    X509_free(x);
    EVP_PKEY_free(pkey);
}

struct EphemeralCert {
    std::filesystem::path dir;
    std::string cert;
    std::string key;

    EphemeralCert() {
        auto ns = std::chrono::steady_clock::now().time_since_epoch().count();
        dir = std::filesystem::temp_directory_path() /
              ("nocturne-tls-test-" +
               std::to_string(reinterpret_cast<uintptr_t>(this)) + "-" +
               std::to_string(static_cast<uint64_t>(ns)));
        std::filesystem::create_directories(dir);
        cert = (dir / "cert.pem").string();
        key  = (dir / "key.pem").string();
        generate_self_signed_pem(cert, key);
    }
    ~EphemeralCert() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

} // namespace

TEST_CASE("TcpTlsTransport plain TLS 1.3 loopback delivers a frame",
          "[transport][tls]") {
    EphemeralCert ec;

    TlsConfig server_cfg;
    server_cfg.cert_pem_path = ec.cert;
    server_cfg.key_pem_path  = ec.key;

    TlsAcceptor acceptor("127.0.0.1", 0, server_cfg);
    uint16_t port = acceptor.local_port();
    REQUIRE(port != 0);

    Session server_sess(/*id=*/1, FeatureSet{});
    Session client_sess(/*id=*/2, FeatureSet{});

    Bytes received_aad, received_ct;
    auto server_future = std::async(std::launch::async, [&] {
        TcpTlsTransport srv = acceptor.accept(server_sess);
        auto f = srv.receive_blocking();
        REQUIRE(f.has_value());
        REQUIRE(static_cast<FrameType>(f->header.type) == FrameType::DATA);
        received_aad = f->data->aad;
        received_ct  = f->data->ciphertext;
    });

    TlsConfig client_cfg;
    // No CA configured ⇒ client skips server verification (test only).
    TcpTlsTransport client(client_sess, "127.0.0.1", port, client_cfg);

    Bytes aad = {0xDE, 0xAD};
    Bytes ct  = {0xBE, 0xEF, 0xCA, 0xFE};
    client.send(client_sess.make_data(aad, ct));

    auto status = server_future.wait_for(std::chrono::seconds(10));
    REQUIRE(status == std::future_status::ready);
    server_future.get(); // surfaces any exception or REQUIRE failure

    REQUIRE(received_aad == aad);
    REQUIRE(received_ct == ct);
}

TEST_CASE("TcpTlsTransport mTLS: server requires client cert", "[transport][tls]") {
    EphemeralCert ec; // shared self-signed acts as both server cert and CA

    TlsConfig server_cfg;
    server_cfg.cert_pem_path = ec.cert;
    server_cfg.key_pem_path  = ec.key;
    server_cfg.ca_pem_path   = ec.cert; // trust this self-signed as CA
    server_cfg.require_client_cert = true;

    TlsAcceptor acceptor("127.0.0.1", 0, server_cfg);
    uint16_t port = acceptor.local_port();

    Session server_sess(1, FeatureSet{});
    Session client_sess(2, FeatureSet{});

    auto server_future = std::async(std::launch::async, [&] {
        TcpTlsTransport srv = acceptor.accept(server_sess);
        auto f = srv.receive_blocking();
        REQUIRE(f.has_value());
        REQUIRE(static_cast<FrameType>(f->header.type) == FrameType::DATA);
    });

    TlsConfig client_cfg;
    client_cfg.cert_pem_path = ec.cert; // present client cert (mTLS)
    client_cfg.key_pem_path  = ec.key;
    // No ca_pem_path on client side: skip server verification (test only).

    TcpTlsTransport client(client_sess, "127.0.0.1", port, client_cfg);
    client.send(client_sess.make_data({0x01}, {0x02, 0x03}));

    auto status = server_future.wait_for(std::chrono::seconds(10));
    REQUIRE(status == std::future_status::ready);
    server_future.get(); // surfaces any exception or REQUIRE failure
}

TEST_CASE("TcpTlsTransport rejects missing cert files", "[transport][tls]") {
    TlsConfig bad_cfg;
    bad_cfg.cert_pem_path = "/nonexistent/cert.pem";
    bad_cfg.key_pem_path  = "/nonexistent/key.pem";

    REQUIRE_THROWS_AS(TlsAcceptor("127.0.0.1", 0, bad_cfg),
                      std::runtime_error);
}

TEST_CASE("TcpTlsTransport receive_blocking returns nullopt on clean close",
          "[transport][tls]") {
    EphemeralCert ec;

    TlsConfig server_cfg;
    server_cfg.cert_pem_path = ec.cert;
    server_cfg.key_pem_path  = ec.key;

    TlsAcceptor acceptor("127.0.0.1", 0, server_cfg);
    uint16_t port = acceptor.local_port();

    Session server_sess(1, FeatureSet{});
    Session client_sess(2, FeatureSet{});

    auto server_future = std::async(std::launch::async, [&] {
        TcpTlsTransport srv = acceptor.accept(server_sess);
        auto f = srv.receive_blocking(); // peer closes without sending
        REQUIRE_FALSE(f.has_value());
    });

    {
        TlsConfig client_cfg;
        TcpTlsTransport client(client_sess, "127.0.0.1", port, client_cfg);
        // explicit close on scope exit triggers SSL_shutdown
    }

    auto status = server_future.wait_for(std::chrono::seconds(10));
    REQUIRE(status == std::future_status::ready);
    server_future.get(); // surfaces any exception or REQUIRE failure
}
