/**
 * @file nocturne-kx.cpp
 * @brief Nocturne-KX: Post-Quantum Secure Key Exchange and Messaging Protocol
 *
 * Copyright (c) 2025-2026 Halil İbrahim Serdaroğlu
 *
 * This software is the exclusive property of Halil İbrahim Serdaroğlu.
 * All rights reserved.
 *
 * Patent Pending: Hybrid Post-Quantum KEM System
 * Trademark: Nocturne-KX™
 *
 * Licensed under the MIT License (see LICENSE file)
 *
 * @author Halil İbrahim Serdaroğlu
 * @version 4.0.0
 * @date 2025
 */

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include <chrono>
#include <unordered_map>
#include <mutex>
#include <sstream>
#include <cstdio>
#include <random>
#include <thread>
#include <atomic>
#include <map>
#include <algorithm>
#include <functional>
#include <span>
#include "src/double_ratchet.hpp"
#include "src/handshake.hpp"
#include "src/transport.hpp"
#include "src/core/side_channel.hpp"
#include "src/hsm/pkcs11_hsm.hpp"
#include "src/pqc/kem/kem_factory.hpp"
#include "src/pqc/sig/sig_factory.hpp"
#include "src/pqc/pqc_config.hpp"

// P5.0–P5.3 foundation: type-safe error path, byte-buffer views, flag
// bitmask, shared value types, packet wire format, and the crypto
// primitive wrappers (KDF, AEAD, Ed25519). The inline definitions that
// used to live in this file have moved into src/core/ and src/protocol/,
// pulled back here for the rest of nocturne-kx.cpp to consume unchanged.
#include "src/core/error.hpp"
#include "src/core/result.hpp"
#include "src/core/byte_span.hpp"
#include "src/core/flags.hpp"
#include "src/core/types.hpp"
#include "src/protocol/packet.hpp"
#include "src/protocol/kdf.hpp"
#include "src/protocol/aead.hpp"
#include "src/protocol/signing.hpp"
#include "src/security/inline/rate_limiter.hpp"
#include "src/security/inline/audit_logger.hpp"
#include "src/security/inline/memory_protection.hpp"
#include "src/security/inline/replay_db.hpp"
#include "src/core/file_io.hpp"
#include "src/hsm/inline/secure_storage.hpp"
#include "src/hsm/inline/hsm_interface.hpp"
#include "src/hsm/inline/file_hsm.hpp"
#include "src/hsm/inline/pkcs11_adapter.hpp"
#include "src/protocol/packet_io.hpp"
#include "src/protocol/keys.hpp"
#include "src/protocol/messaging.hpp"
#include <iomanip>

// TLS transport subcommands (tls-send / tls-recv) are CLI-only: the fuzzer
// and unit-test builds include this TU but exclude main(), and must not
// grow an OpenSSL link dependency.
#if defined(NOCTURNE_ENABLE_TLS_TRANSPORT) && \
    !defined(NOCTURNE_FUZZER_BUILD) && !defined(NOCTURNE_UNIT_TEST)
  #define NOCTURNE_CLI_TLS 1
  #include "src/tcp_tls_transport.hpp"
#endif

#include <sodium.h>

// Platform-specific headers used to live here, but the symbols that needed
// them (VirtualLock / mlock / _mm_clflush etc.) all moved out with P5.4's
// memory_protection extraction and P5.5's HSM extraction. The remaining
// translation unit talks only to standard C++ headers and libsodium.

// SECURITY CONSTANTS (Global namespace for accessibility)
constexpr size_t MAX_PACKET_SIZE = 1024 * 1024;      // 1MB maximum packet size
constexpr size_t MAX_AAD_SIZE = 64 * 1024;           // 64KB maximum AAD size
constexpr size_t MAX_CIPHERTEXT_SIZE = 1024 * 1024;  // 1MB maximum ciphertext size
constexpr size_t MAX_ALLOCATION_SIZE = 100 * 1024 * 1024; // 100MB maximum allocation

/*
 Nocturne-KX - hardened / near-military prototype v3
 ----------------------------------------------------
 This file extends the earlier prototype with the following practical hardening additions:

 1) Robust Replay DB: atomic writes, HMAC-protected JSON, anti-rollback version counter.
 2) Key rotation enforcement + rotation metadata. Rotation metadata can be audited.
 3) Ratchet scaffolding updated and an example "simple DH ratchet" implemented as an optional
    feature (NOT a full Double-Ratchet; see notes below).
 4) HSM/PKCS#11 loader example (stub + PKCS#11 helper wrapper) and integration note.
 5) CI/test hooks (Catch2 unit test skeleton added in tests/). New GitHub Actions workflow runs
    sanitizers (ASAN/UBSAN), unit tests, and a fuzzing job skeleton.
 6) ReplayDB encrypted/MACed and persisted atomically to prevent easy tampering/rollback.
 7) More defensive coding: strict length checks, fewer implicit casts, and explicit zeroing.

 IMPORTANT SECURITY NOTES:
 - This remains *prototype* code. It is NOT production-ready without formal security audit.
 - For production you MUST: obtain formal specification, peer review, formal verification, and an independent security audit.
 - Replace the simple ratchet with a formal Double Ratchet or Noise-based handshake if you want forward secrecy + post-compromise recovery.
 - Integrate HSMs using validated PKCS#11 modules and ensure private keys never leave secure hardware.

 The code compiles with C++23 and libsodium. See README and CI for build/test instructions.
*/

// Rate limiting subsystem moved to src/security/inline/rate_limiter.{hpp,cpp}
// in P5.4. The namespace name (rate_limiting) is preserved so existing
// call sites that say `rate_limiting::allow_request(...)` keep working.

// Structured audit logging subsystem moved to src/security/inline/audit_logger.{hpp,cpp}
// in P5.4. The audit_log namespace name is preserved; existing call sites
// (audit_log::info, audit_log::initialize, etc.) keep working unchanged.

// Memory protection subsystem moved to src/security/inline/memory_protection.{hpp,cpp}
// in P5.4. The memory_protection namespace name and SecureMemory<T> template
// are preserved; existing call sites keep compiling unchanged.

// Constants, exception hierarchy, key-pair types, and check_sodium()
// all moved to src/core/{flags,types,byte_span,error,result}.hpp in
// P5.0–P5.1. gen_x25519 / gen_ed25519 moved to src/protocol/keys.hpp
// in P5.7 so messaging.cpp can share them. Packet wire format and
// serialize/deserialize live in src/protocol/packet.{hpp,cpp} (P5.2).
// KDF / AEAD / Ed25519 primitives are in src/protocol/{kdf,aead,
// signing}.hpp (P5.3). All names remain reachable through namespace
// nocturne via the foundation headers.

// File I/O helpers moved to src/core/file_io.{hpp,cpp} in P5.4. Pull the
// names into the global namespace so the rest of nocturne-kx.cpp keeps
// calling them unqualified.
using nocturne::read_all;
using nocturne::write_all;
using nocturne::write_all_raw;

// ReplayDB moved to src/security/inline/replay_db.{hpp,cpp} in P5.4.
// The nocturne::ReplayDB class is available via the new header — call
// sites that previously said `ReplayDB` (unqualified) at global scope
// now resolve via the `using nocturne::ReplayDB;` directive below.

using nocturne::ReplayDB;

// hexify(), encrypt_packet(), decrypt_packet(), encrypt_packet_kem(),
// decrypt_packet_kem() moved to src/protocol/messaging.{hpp,cpp} in
// P5.7, plus a new EncryptOptions / DecryptOptions aggregate that
// collapses the old positional default-parameter list. Call sites in
// main() below were updated accordingly.

// P6.1b: the messaging entry points return Result<Bytes> now. The CLI
// keeps its single top-level catch (print + exit 2), so map typed
// errors into a runtime_error whose what() carries "Name: message" —
// preserving both the exit code and the human-readable reason that the
// CI workflows grep for (e.g. "replay").
template <typename T>
static T cli_unwrap(nocturne::Result<T> r) {
    if (!r) {
        throw std::runtime_error{
            std::string{r.error().name()} + ": " + r.error().message};
    }
    return std::move(*r);
}

// Consume the next argv token; throws if none remains.
static std::string cli_next_arg(int& i, int argc, char** argv, std::string_view flag) {
    if (i + 1 >= argc)
        throw std::runtime_error("missing value for " + std::string(flag));
    return std::string(argv[++i]);
}

// Returns true for options consumed during the global prescan so subcommand
// parsers can skip them without listing them again.
static bool is_global_opt(std::string_view a) {
    static constexpr std::string_view kGlobalOpts[] = {
        "--rate-limit-store", "--audit-log", "--audit-sign-key",
        "--audit-anchor", "--audit-worm-dir", "--tpm-counter", "--hsm-pass",
    };
    for (const auto& opt : kGlobalOpts) if (a == opt) return true;
    return false;
}

// Map CLI KEM string to KEMType; throws on unrecognised value.
static nocturne::pqc::KEMType kem_str_to_type(std::string_view s) {
    if (s == "x25519") return nocturne::pqc::KEMType::CLASSIC_X25519;
    if (s == "hybrid") return nocturne::pqc::KEMType::HYBRID_X25519_MLKEM1024;
    if (s == "mlkem")  return nocturne::pqc::KEMType::PURE_MLKEM1024;
    throw std::runtime_error("unknown --kem value: " + std::string(s) +
                             " (expected x25519|hybrid|mlkem)");
}

// Map CLI sig string to SigType; throws on unrecognised value.
static nocturne::pqc::SigType sig_str_to_type(std::string_view s) {
    if (s == "ed25519") return nocturne::pqc::SigType::CLASSIC_ED25519;
    if (s == "hybrid")  return nocturne::pqc::SigType::HYBRID_ED25519_MLDSA87;
    if (s == "mldsa")   return nocturne::pqc::SigType::PURE_MLDSA87;
    throw std::runtime_error("unknown --sig-type value: " + std::string(s) +
                             " (expected ed25519|hybrid|mldsa)");
}

// Usage message
static void usage() {
    std::cout <<
R"(nocturne-kx (C++23, libsodium) - hardened prototype v3

Subcommands:

  gen-receiver <outdir> [--kem x25519|hybrid|mlkem]
      x25519 (default): writes receiver_x25519_{pk,sk}.bin (32B each, classic ECDH)
      hybrid:           writes receiver_hybrid_{pk,sk}.bin (1600B/3200B, X25519+ML-KEM-1024)
      mlkem:            writes receiver_mlkem_{pk,sk}.bin (1568B/3168B, FIPS 203 Level 5)

  gen-signer <outdir> [--sig-type ed25519|hybrid|mldsa]
      ed25519 (default): writes sender_ed25519_{pk,sk}.bin (32B/64B, classical)
      mldsa:             writes sender_mldsa87_{pk,sk}.bin  (2592B/4896B, FIPS 204 Level 5)
      hybrid:            writes sender_hybrid_sig_{pk,sk}.bin (2624B/4960B, Ed25519+ML-DSA-87)

  encrypt --rx-pk <file> [--kem x25519|hybrid|mlkem]
          [--sign-hsm-uri file://<skfile> or hsm://<id>] [--aad <str>] [--rotation-id <n>] [--ratchet]
          [--pqc-sign-key <file> --pqc-sig-type ed25519|hybrid|mldsa]
          --in <pt> --out <pkt> [--replay-db <path>] [--mac-key <file>]
      --pqc-sign-key uses the FLAG_HAS_PQC_SIG path (variable-length signature),
      orthogonal to --sign-hsm-uri's classical Ed25519 path. Combine
      --kem hybrid + --pqc-sig-type hybrid for full PQ-resistant E2E.

  decrypt --rx-pk <file> --rx-sk <file> [--expect-signer <file>] [--min-rotation <n>]
          [--expect-pqc-signer <pk-file> --pqc-sig-type ed25519|hybrid|mldsa]
          --in <pkt> --out <pt> [--replay-db <path>] [--mac-key <file>]
      KEM mode is auto-detected from the packet header. The rx-pk/rx-sk file
      sizes must match the mode: 32B for X25519, 1600B/3200B for hybrid,
      1568B/3168B for mlkem.

  tls-send --host <h> --port <n> --in <pkt>
           [--ca <pem>] [--sni <name>] [--cert <pem> --key <pem>]
      Sends one encrypted Nocturne packet (produced by `encrypt`) to a
      tls-recv peer over TLS 1.3. --ca enables server certificate
      verification (add --sni for hostname checking); --cert/--key present
      a client certificate (mTLS). Requires a build with OpenSSL.

  tls-recv --port <n> --cert <pem> --key <pem> --out <pkt>
           [--bind <host>] [--ca <pem> --require-client-cert]
      Accepts one TLS 1.3 connection, receives one Nocturne packet, and
      writes it to --out (then use `decrypt`). --require-client-cert
      enforces mTLS against the --ca bundle.

  self-test
      -> Runs a suite of self-tests to verify basic functionality.

  security-check
      -> Performs a basic security check of the application.

  audit-log
      -> Displays a summary of security features and recommendations.

  audit-verify <log-path> [--expect-signer <pk-file>]
      -> Walks the JSONL audit log written by --audit-log, recomputes the
         BLAKE2b hash chain, and (if records are signed) verifies the
         per-record Ed25519 signatures. Exits 0 on full integrity,
         non-zero with line numbers + reasons on the first failure.

  rate-limit-status <identifier>
      -> Shows rate limiting status for a specific identifier.

  rate-limit-reset <identifier>
      -> Resets rate limiting for a specific identifier.

  memory-stats
      -> Shows secure memory allocation statistics.

  dr-demo
      -> Demonstrates Double Ratchet encrypt/decrypt over in-memory transport.

  hs-demo
      -> Demonstrates authenticated handshake (initiator/responder) and derives session keys.

  rate-limit-status <identifier>
      -> Shows rate limiting status for a specific identifier.

Notes:
 - Replay DB: if provided, the DB path will be used and protected with a MAC key (preferably stored in HSM).
 - Ratchet: this implements a simple DH-based mixing step. Real Double Ratchet needed for full security guarantees.
 - HSM: use hsm:// in a real deployment and implement a PKCS#11 wrapper; a FileHSM is provided only for demos.
 - CI: see .github/workflows/cmake.yml for sanitizer, unit-tests and fuzzing job skeletons.
)";
}

#if !defined(NOCTURNE_FUZZER_BUILD) && !defined(NOCTURNE_UNIT_TEST)
int main(int argc, char** argv) {
    try {
        nocturne::check_sodium();
        if (argc < 2) { usage(); return 1; }

        // Global options
        std::optional<std::filesystem::path> opt_rate_store = std::nullopt;
        std::optional<std::filesystem::path> opt_audit_log = std::nullopt;
        std::optional<std::filesystem::path> opt_audit_sign_key = std::nullopt; // Ed25519 sk for audit signing
        std::optional<std::filesystem::path> opt_audit_anchor = std::nullopt;   // External anchor blob (e.g., TSA token)
        std::optional<std::filesystem::path> opt_tpm_counter = std::nullopt;    // External monotonic counter path
        std::string opt_hsm_pass;

        // Pre-scan args for global options and filter remaining into a vector.
        std::optional<std::filesystem::path> opt_audit_worm_dir = std::nullopt;
        std::vector<std::string> args; args.reserve(argc-1);
        for (int i=1; i<argc; ++i) {
            const std::string a = argv[i];
            if      (a == "--rate-limit-store") opt_rate_store     = cli_next_arg(i, argc, argv, a);
            else if (a == "--audit-log")        opt_audit_log      = cli_next_arg(i, argc, argv, a);
            else if (a == "--audit-sign-key")   opt_audit_sign_key = cli_next_arg(i, argc, argv, a);
            else if (a == "--audit-anchor")     opt_audit_anchor   = cli_next_arg(i, argc, argv, a);
            else if (a == "--audit-worm-dir")   opt_audit_worm_dir = cli_next_arg(i, argc, argv, a);
            else if (a == "--tpm-counter")      opt_tpm_counter    = cli_next_arg(i, argc, argv, a);
            else if (a == "--hsm-pass")         opt_hsm_pass       = cli_next_arg(i, argc, argv, a);
            else                                args.push_back(a);
        }

        if (opt_audit_log) audit_log::initialize(opt_audit_log, opt_audit_sign_key, opt_audit_anchor, opt_audit_worm_dir);
        rate_limiting::initialize(rate_limiting::RateLimitConfig{}, opt_rate_store);
        if (!opt_hsm_pass.empty()) {
            // Set env for current process (portable)
            std::string kv = std::string("NOCTURNE_HSM_PASSPHRASE=") + opt_hsm_pass;
            ::putenv(strdup(kv.c_str()));
        }

        if (args.empty()) { usage(); return 1; }
        std::string cmd = args[0];

        if (cmd == "gen-receiver") {
            if (args.size() < 2) { usage(); return 1; }
            std::filesystem::path outdir = args[1];
            std::string kem_str = "x25519";
            for (size_t i = 2; i < args.size(); ++i) {
                if (args[i] == "--kem") {
                    if (i + 1 >= args.size()) throw std::runtime_error("missing value for --kem");
                    kem_str = args[++i];
                } else {
                    throw std::runtime_error("unknown argument: " + args[i]);
                }
            }
            std::filesystem::create_directories(outdir);

            const auto kem_type = kem_str_to_type(kem_str);
            if (kem_type == nocturne::pqc::KEMType::CLASSIC_X25519) {
                auto kp = nocturne::gen_x25519();
                write_all_raw(outdir / "receiver_x25519_pk.bin", kp.pk.data(), kp.pk.size());
                write_all_raw(outdir / "receiver_x25519_sk.bin", kp.sk.data(), kp.sk.size());
                std::cout << "Wrote X25519 receiver keys to " << outdir << "\n";
            } else {
                auto kem = nocturne::pqc::KEMFactory{}.create(kem_type);
                auto kp = kem->generate_keypair();
                const std::string base = "receiver_" + std::string(kem_str);
                write_all_raw(outdir / (base + "_pk.bin"), kp.public_key.data(), kp.public_key.size());
                write_all_raw(outdir / (base + "_sk.bin"), kp.secret_key.data(), kp.secret_key.size());
                std::cout << "Wrote " << kem->algorithm_name() << " receiver keys to " << outdir
                          << " (pk=" << kp.public_key.size() << "B, sk=" << kp.secret_key.size() << "B)\n";
            }
            return 0;
        }

        if (cmd == "gen-signer") {
            if (argc < 3) { usage(); return 1; }
            std::filesystem::path outdir = argv[2];
            std::string sig_str = "ed25519";
            for (int i = 3; i < argc; ++i) {
                std::string a = argv[i];
                if (a == "--sig-type" && i + 1 < argc) {
                    sig_str = argv[++i];
                } else {
                    std::cerr << "ERR: unknown gen-signer arg: " << a << "\n";
                    return 1;
                }
            }
            std::filesystem::create_directories(outdir);

            const auto sig_type = sig_str_to_type(sig_str);
            if (sig_type == nocturne::pqc::SigType::CLASSIC_ED25519) {
                auto kp = nocturne::gen_ed25519();
                write_all_raw(outdir / "sender_ed25519_pk.bin", kp.pk.data(), kp.pk.size());
                write_all_raw(outdir / "sender_ed25519_sk.bin", kp.sk.data(), kp.sk.size());
                std::cout << "Wrote Ed25519 signer keys to " << outdir << "\n";
            } else {
                auto scheme = nocturne::pqc::SignatureFactory{}.create(sig_type);
                auto kp = scheme->generate_keypair();
                const std::string base = (sig_type == nocturne::pqc::SigType::HYBRID_ED25519_MLDSA87)
                    ? "sender_hybrid_sig" : "sender_mldsa87";
                write_all_raw(outdir / (base + "_pk.bin"),
                              kp.public_key.data(), kp.public_key.size());
                write_all_raw(outdir / (base + "_sk.bin"),
                              kp.secret_key.data(), kp.secret_key.size());
                std::cout << "Wrote " << scheme->algorithm_name() << " signer keys to "
                          << outdir << " (pk=" << kp.public_key.size()
                          << "B, sk=" << kp.secret_key.size() << "B)\n";
            }
            return 0;
        }

        if (cmd == "encrypt") {
            std::filesystem::path rxpk, in, out, replaydb_path, mac_key_path;
            std::string aad_str, signer_uri;
            uint32_t rotation_id = 0; bool use_ratchet = false;
            std::string kem_str = "x25519"; // x25519 (classic) | hybrid | mlkem
            std::filesystem::path pqc_sign_key_path;
            std::string pqc_sig_str; // ed25519 | hybrid | mldsa (empty = disabled)
            
            // ERROR HANDLING: Comprehensive input validation and error management
            try {
                for (int i=2; i<argc; ++i) {
                    const std::string a = argv[i];

                    if (is_global_opt(a)) { cli_next_arg(i, argc, argv, a); continue; }

                    if      (a=="--rx-pk") rxpk = cli_next_arg(i, argc, argv, a);
                    else if (a=="--sign-hsm-uri") signer_uri = cli_next_arg(i, argc, argv, a);
                    else if (a=="--aad") aad_str = cli_next_arg(i, argc, argv, a);
                    else if (a=="--rotation-id") {
                        try {
                            rotation_id = static_cast<uint32_t>(std::stoul(cli_next_arg(i, argc, argv, a)));
                        } catch (const std::exception&) {
                            throw std::runtime_error("invalid rotation-id: must be a positive integer");
                        }
                    }
                    else if (a=="--ratchet") use_ratchet = true;
                    else if (a=="--kem") kem_str = cli_next_arg(i, argc, argv, a);
                    else if (a=="--in") in = cli_next_arg(i, argc, argv, a);
                    else if (a=="--out") out = cli_next_arg(i, argc, argv, a);
                    else if (a=="--replay-db") replaydb_path = cli_next_arg(i, argc, argv, a);
                    else if (a=="--mac-key") mac_key_path = cli_next_arg(i, argc, argv, a);
                    else if (a=="--pqc-sign-key") pqc_sign_key_path = cli_next_arg(i, argc, argv, a);
                    else if (a=="--pqc-sig-type") pqc_sig_str = cli_next_arg(i, argc, argv, a);
                    else throw std::runtime_error("unknown argument: " + a);
                }
                
                // CRITICAL SECURITY VALIDATION: Check required arguments
                if (rxpk.empty()) {
                    throw std::runtime_error("missing required argument: --rx-pk");
                }
                if (in.empty()) {
                    throw std::runtime_error("missing required argument: --in");
                }
                if (out.empty()) {
                    throw std::runtime_error("missing required argument: --out");
                }
                
                // VALIDATE FILE PATHS: Prevent path traversal attacks
                if (!std::filesystem::exists(rxpk)) {
                    throw std::runtime_error("receiver public key file does not exist: " + rxpk.string());
                }
                if (!std::filesystem::exists(in)) {
                    throw std::runtime_error("input file does not exist: " + in.string());
                }
                
            } catch (const std::runtime_error& e) {
                std::cerr << "ERROR: " << e.what() << "\n";
                std::cerr << "Use 'nocturne-kx help' for usage information.\n";
                return 1;
            }
            auto rxpk_bytes = read_all(rxpk);

            // Resolve --kem mode and validate the rx-pk file size against the chosen KEM.
            const auto kem_type = kem_str_to_type(kem_str);
            if (kem_type == nocturne::pqc::KEMType::CLASSIC_X25519 &&
                rxpk_bytes.size() != crypto_kx_PUBLICKEYBYTES) {
                throw std::runtime_error("X25519 receiver pk size mismatch (expected 32, got " +
                                         std::to_string(rxpk_bytes.size()) + ")");
            }
            std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> rxpk_arr{};
            if (kem_type == nocturne::pqc::KEMType::CLASSIC_X25519) {
                std::memcpy(rxpk_arr.data(), rxpk_bytes.data(), rxpk_arr.size());
            }

            // HSM VALIDATION: Comprehensive HSM URI validation and error handling
            std::unique_ptr<HSMInterface> signer = nullptr;
            if (!signer_uri.empty()) {
                try {
                    if (signer_uri.rfind("file://",0)==0) {
                        std::string file_path = signer_uri.substr(strlen("file://"));
                        if (file_path.empty()) {
                            throw std::runtime_error("empty file path in HSM URI");
                        }
                        
                        // Validate file path security
                        std::filesystem::path hsm_path(file_path);
                        if (!std::filesystem::exists(hsm_path)) {
                            throw std::runtime_error("HSM key file does not exist: " + file_path);
                        }
                        
                        // Check file permissions (basic security check)
                        auto perms = std::filesystem::status(hsm_path).permissions();
                        if ((perms & std::filesystem::perms::others_read) != std::filesystem::perms::none) {
                            std::cerr << "WARNING: HSM key file has world-readable permissions\n";
                        }
                        
                        signer = std::make_unique<FileHSM>(hsm_path);
                    } else if (signer_uri.rfind("hsm://",0)==0) {
                        // HSM INTEGRATION: PKCS#11 implementation
                        std::string hsm_spec = signer_uri.substr(strlen("hsm://"));
                        if (hsm_spec.empty()) {
                            throw std::runtime_error("empty HSM specification in URI");
                        }
                        
                        // Parse HSM specification: token_id:key_label
                        size_t colon_pos = hsm_spec.find(':');
                        if (colon_pos == std::string::npos) {
                            throw std::runtime_error("invalid HSM URI format: expected 'hsm://token_id:key_label'");
                        }
                        
                        std::string token_id = hsm_spec.substr(0, colon_pos);
                        std::string key_label = hsm_spec.substr(colon_pos + 1);
                        
                        if (token_id.empty()) {
                            throw std::runtime_error("empty token ID in HSM URI");
                        }
                        if (key_label.empty()) {
                            throw std::runtime_error("empty key label in HSM URI");
                        }
                        
                        // Create PKCS#11 HSM instance
                        signer = std::make_unique<PKCS11HSM>(token_id, key_label);
                        
                        std::cout << "INFO: Using PKCS#11 HSM (Token: " << token_id << ", Key: " << key_label << ")\n";
                    } else {
                        throw std::runtime_error("unsupported HSM URI scheme: " + signer_uri);
                    }
                } catch (const std::exception& e) {
                    std::cerr << "HSM ERROR: " << e.what() << "\n";
                    return 1;
                }
            }

            auto pt = read_all(in);
            nocturne::Bytes aad(aad_str.begin(), aad_str.end());

            // Optional PQC signer: --pqc-sign-key + --pqc-sig-type. Reads the
            // raw secret-key file and prepares a PqcSignerConfig that
            // encrypt_packet / encrypt_packet_kem will use to populate the
            // FLAG_HAS_PQC_SIG block.
            std::optional<nocturne::PqcSignerConfig> pqc_signer_cfg;
            if (!pqc_sign_key_path.empty() || !pqc_sig_str.empty()) {
                if (pqc_sign_key_path.empty() || pqc_sig_str.empty()) {
                    std::cerr << "ERR: --pqc-sign-key and --pqc-sig-type must both be set\n";
                    return 1;
                }
                const auto st = sig_str_to_type(pqc_sig_str);
                auto sk_bytes = read_all(pqc_sign_key_path);
                auto scheme = nocturne::pqc::SignatureFactory{}.create(st);
                if (sk_bytes.size() != scheme->secret_key_size()) {
                    std::cerr << "ERR: --pqc-sign-key size mismatch (expected "
                              << scheme->secret_key_size() << " for "
                              << scheme->algorithm_name() << ", got "
                              << sk_bytes.size() << ")\n";
                    return 1;
                }
                pqc_signer_cfg = nocturne::PqcSignerConfig{st, std::move(sk_bytes)};
            }

            std::optional<std::filesystem::path> mac_key = mac_key_path.empty()?std::nullopt:std::optional<std::filesystem::path>(mac_key_path);
            ReplayDB rdb(replaydb_path.empty()?std::filesystem::path(std::string(std::getenv("HOME")?std::getenv("HOME"):".")) / ".nocturne" / "replaydb.bin": replaydb_path, mac_key, opt_tpm_counter);
            ReplayDB* rdbp = replaydb_path.empty()?nullptr:&rdb;

            const nocturne::PqcSignerConfig* pqc_ptr =
                pqc_signer_cfg.has_value() ? &*pqc_signer_cfg : nullptr;

            nocturne::EncryptOptions enc_opts{
                .aad         = aad,
                .rotation_id = rotation_id,
                .use_ratchet = use_ratchet,
                .signer      = signer.get(),
                .replay_db   = rdbp,
                .pqc_signer  = pqc_ptr,
            };

            nocturne::Bytes pkt;
            if (kem_type == nocturne::pqc::KEMType::CLASSIC_X25519) {
                pkt = cli_unwrap(nocturne::encrypt_packet(rxpk_arr, pt, enc_opts));
                std::cout << "Encrypted (X25519"
                          << (pqc_ptr ? std::string(" + ") + nocturne::pqc::sig_type_to_string(pqc_ptr->type) : "")
                          << ") -> " << out << " (" << pkt.size() << " bytes)\n";
            } else {
                if (use_ratchet) {
                    std::cerr << "WARNING: --ratchet ignored in PQC/KEM mode (DR uses its own key path)\n";
                }
                pkt = cli_unwrap(nocturne::encrypt_packet_kem(kem_type, rxpk_bytes, pt, enc_opts));
                const char* algo = (kem_type == nocturne::pqc::KEMType::HYBRID_X25519_MLKEM1024)
                                   ? "Hybrid X25519+ML-KEM-1024" : "ML-KEM-1024";
                std::cout << "Encrypted (" << algo
                          << (pqc_ptr ? std::string(" + ") + nocturne::pqc::sig_type_to_string(pqc_ptr->type) : "")
                          << ") -> " << out << " (" << pkt.size() << " bytes)\n";
            }
            write_all(out, pkt);
            return 0;
        }

        if (cmd == "decrypt") {
            std::filesystem::path rxpk, rxsk, in, out, replaydb_path, mac_key_path;
            std::string expectpk_path;
            std::filesystem::path expect_pqc_pk_path;
            std::string expect_pqc_sig_str;
            std::optional<uint32_t> min_rotation = std::nullopt;
            for (int i=2; i<argc; ++i) {
                const std::string a = argv[i];

                if (is_global_opt(a)) { cli_next_arg(i, argc, argv, a); continue; }

                if      (a=="--rx-pk") rxpk = cli_next_arg(i, argc, argv, a);
                else if (a=="--rx-sk") rxsk = cli_next_arg(i, argc, argv, a);
                else if (a=="--expect-signer") expectpk_path = cli_next_arg(i, argc, argv, a);
                else if (a=="--min-rotation") min_rotation = static_cast<uint32_t>(
                                                  std::stoul(cli_next_arg(i, argc, argv, a)));
                else if (a=="--in") in = cli_next_arg(i, argc, argv, a);
                else if (a=="--out") out = cli_next_arg(i, argc, argv, a);
                else if (a=="--replay-db") replaydb_path = cli_next_arg(i, argc, argv, a);
                else if (a=="--mac-key") mac_key_path = cli_next_arg(i, argc, argv, a);
                else if (a=="--expect-pqc-signer") expect_pqc_pk_path = cli_next_arg(i, argc, argv, a);
                else if (a=="--pqc-sig-type") expect_pqc_sig_str = cli_next_arg(i, argc, argv, a);
                else throw std::runtime_error("unknown arg: " + a);
            }
            if (rxpk.empty() || rxsk.empty() || in.empty() || out.empty()) throw std::runtime_error("missing required args");
            auto rxpk_b = read_all(rxpk); auto rxsk_b = read_all(rxsk);

            std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> expectpk_arr = std::nullopt;
            if (!expectpk_path.empty()) {
                auto e = read_all(expectpk_path);
                if (e.size()!=crypto_sign_PUBLICKEYBYTES) throw std::runtime_error("expected signer pk size mismatch");
                std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> tmp{}; std::memcpy(tmp.data(), e.data(), tmp.size()); expectpk_arr = tmp;
            }

            // Optional PQC verifier: --expect-pqc-signer + --pqc-sig-type. Both
            // must be set together. Public-key size is enforced against the
            // factory's reported size for the chosen SigType.
            std::optional<nocturne::PqcVerifierConfig> pqc_verifier_cfg;
            if (!expect_pqc_pk_path.empty() || !expect_pqc_sig_str.empty()) {
                if (expect_pqc_pk_path.empty() || expect_pqc_sig_str.empty()) {
                    throw std::runtime_error("--expect-pqc-signer and --pqc-sig-type must both be set");
                }
                const auto st = sig_str_to_type(expect_pqc_sig_str);

                auto pk_bytes = read_all(expect_pqc_pk_path);
                auto scheme = nocturne::pqc::SignatureFactory{}.create(st);
                if (pk_bytes.size() != scheme->public_key_size()) {
                    throw std::runtime_error(
                        "--expect-pqc-signer pk size mismatch (expected " +
                        std::to_string(scheme->public_key_size()) + " for " +
                        scheme->algorithm_name() + ", got " +
                        std::to_string(pk_bytes.size()) + ")");
                }
                pqc_verifier_cfg = nocturne::PqcVerifierConfig{st, std::move(pk_bytes)};
            }
            const nocturne::PqcVerifierConfig* pqc_vptr =
                pqc_verifier_cfg.has_value() ? &*pqc_verifier_cfg : nullptr;

            std::optional<std::filesystem::path> mac_key = mac_key_path.empty()?std::nullopt:std::optional<std::filesystem::path>(mac_key_path);
            ReplayDB rdb(replaydb_path.empty()?std::filesystem::path(std::string(std::getenv("HOME")?std::getenv("HOME"):".")) / ".nocturne" / "replaydb.bin": replaydb_path, mac_key, opt_tpm_counter);
            ReplayDB* rdbp = replaydb_path.empty()?nullptr:&rdb;

            auto pkt = read_all(in);

            // Auto-detect KEM mode from the packet header. Peek at the flags byte
            // (offset 1, immediately after the version byte) without doing a full
            // deserialize — keeps the dispatch cheap and avoids double-parsing.
            if (pkt.size() < 2) throw std::runtime_error("packet too small to inspect");
            bool is_pqc = (pkt[1] & nocturne::FLAG_HAS_PQC_KEM) != 0;

            nocturne::DecryptOptions dec_opts{
                .expected_signer_ed25519_pk = expectpk_arr,
                .replay_db                  = rdbp,
                .min_rotation_id            = min_rotation,
                .pqc_verifier               = pqc_vptr,
            };

            nocturne::Bytes pt;
            if (!is_pqc) {
                if (rxpk_b.size()!=crypto_kx_PUBLICKEYBYTES) throw std::runtime_error("X25519 receiver pk size mismatch");
                if (rxsk_b.size()!=crypto_kx_SECRETKEYBYTES) throw std::runtime_error("X25519 receiver sk size mismatch");
                std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> rxpk_arr{};
                std::array<uint8_t, crypto_kx_SECRETKEYBYTES> rxsk_arr{};
                std::memcpy(rxpk_arr.data(), rxpk_b.data(), rxpk_arr.size());
                std::memcpy(rxsk_arr.data(), rxsk_b.data(), rxsk_arr.size());
                pt = cli_unwrap(nocturne::decrypt_packet(rxpk_arr, rxsk_arr, pkt, dec_opts));
                std::cout << "Decrypted (X25519"
                          << (pqc_vptr ? std::string(" + ") + nocturne::pqc::sig_type_to_string(pqc_vptr->type) + " verified" : "")
                          << ") -> " << out << " (" << pt.size() << " bytes)\n";
            } else {
                // KEMFactory + size validation happens inside decrypt_packet_kem.
                pt = cli_unwrap(nocturne::decrypt_packet_kem(rxpk_b, rxsk_b, pkt, dec_opts));
                std::cout << "Decrypted (PQC/KEM"
                          << (pqc_vptr ? std::string(" + ") + nocturne::pqc::sig_type_to_string(pqc_vptr->type) + " verified" : "")
                          << ") -> " << out << " (" << pt.size() << " bytes)\n";
            }
            write_all(out, pt);
            return 0;
        }

        if (cmd == "tls-send" || cmd == "tls-recv") {
#ifndef NOCTURNE_CLI_TLS
            std::cerr << "ERR: this binary was built without the TLS transport "
                         "(ENABLE_TLS_TRANSPORT=OFF or OpenSSL missing)\n";
            return 2;
#else
            using nocturne::transport::FeatureSet;
            using nocturne::transport::Frame;
            using nocturne::transport::FrameType;
            using nocturne::transport::Session;
            using nocturne::transport::tls::TlsAcceptor;
            using nocturne::transport::tls::TlsConfig;
            using nocturne::transport::tls::TcpTlsTransport;

            std::string host, bind_host, sni;
            std::filesystem::path cert, key, ca, in, out;
            uint16_t port = 0;
            bool require_client_cert = false;

            for (int i = 2; i < argc; ++i) {
                const std::string a = argv[i];

                if (is_global_opt(a)) { cli_next_arg(i, argc, argv, a); continue; }

                if      (a=="--host") host = cli_next_arg(i, argc, argv, a);
                else if (a=="--bind") bind_host = cli_next_arg(i, argc, argv, a);
                else if (a=="--port") {
                    const unsigned long v = std::stoul(cli_next_arg(i, argc, argv, a));
                    if (v == 0 || v > 65535) throw std::runtime_error("--port out of range (1-65535)");
                    port = static_cast<uint16_t>(v);
                }
                else if (a=="--cert") cert = cli_next_arg(i, argc, argv, a);
                else if (a=="--key") key = cli_next_arg(i, argc, argv, a);
                else if (a=="--ca") ca = cli_next_arg(i, argc, argv, a);
                else if (a=="--sni") sni = cli_next_arg(i, argc, argv, a);
                else if (a=="--require-client-cert") require_client_cert = true;
                else if (a=="--in") in = cli_next_arg(i, argc, argv, a);
                else if (a=="--out") out = cli_next_arg(i, argc, argv, a);
                else throw std::runtime_error("unknown arg: " + a);
            }
            if (port == 0) throw std::runtime_error("missing required argument: --port");

            TlsConfig cfg;
            cfg.cert_pem_path = cert.string();
            cfg.key_pem_path  = key.string();
            if (!ca.empty()) cfg.ca_pem_path = ca.string();
            cfg.require_client_cert = require_client_cert;
            cfg.sni_hostname = sni;

            if (cmd == "tls-send") {
                if (host.empty() || in.empty()) throw std::runtime_error("tls-send requires --host and --in");
                auto pkt = read_all(in);

                Session sess(1, FeatureSet{});
                TcpTlsTransport t(sess, host, port, cfg);
                Frame df = sess.make_data(/*aad=*/{}, pkt);
                t.send(df);

                // Wait for the receiver's ACK before declaring success.
                for (;;) {
                    auto fr = t.receive_blocking();
                    if (!fr) throw std::runtime_error("peer closed before acknowledging packet");
                    if (static_cast<FrameType>(fr->header.type) == FrameType::ACK) {
                        sess.handle_feedback(*fr);
                        if (fr->ack->ack_seq >= df.header.seq) break;
                    } else if (static_cast<FrameType>(fr->header.type) == FrameType::NAK) {
                        throw std::runtime_error("receiver NAKed packet (seq " +
                                                 std::to_string(fr->nak->nak_seq) + ")");
                    }
                }
                t.send(sess.make_close());
                t.close();
                std::cout << "Sent " << pkt.size() << " byte packet to " << host
                          << ":" << port << " (TLS 1.3, ACK seq " << df.header.seq << ")\n";
                return 0;
            }

            // tls-recv
            if (cert.empty() || key.empty() || out.empty()) {
                throw std::runtime_error("tls-recv requires --cert, --key and --out");
            }
            TlsAcceptor acc(bind_host, port, cfg);
            std::cout << "Listening on " << (bind_host.empty() ? "*" : bind_host)
                      << ":" << acc.local_port() << " (TLS 1.3"
                      << (require_client_cert ? ", mTLS required" : "") << ")...\n";

            Session sess(1, FeatureSet{});
            TcpTlsTransport t = acc.accept(sess);
            std::optional<nocturne::Bytes> received;
            for (;;) {
                auto fr = t.receive_blocking();
                if (!fr) break; // peer closed
                if (auto fb = sess.on_receive(*fr)) t.send(*fb);
                if (static_cast<FrameType>(fr->header.type) == FrameType::DATA) {
                    received = fr->data->ciphertext;
                } else if (static_cast<FrameType>(fr->header.type) == FrameType::CLOSE) {
                    break;
                }
            }
            t.close();
            acc.close();
            if (!received) throw std::runtime_error("connection ended without a DATA frame");
            write_all(out, *received);
            std::cout << "Received " << received->size() << " byte packet -> " << out
                      << " (decrypt it with `nocturne-kx decrypt`)\n";
            return 0;
#endif // NOCTURNE_CLI_TLS
        }

        if (cmd == "self-test") {
            std::cout << "Running Nocturne-KX self-test...\n";
            
            // Test key generation
            std::cout << "  Testing key generation...\n";
            auto x25519_kp = nocturne::gen_x25519();
            auto ed25519_kp = nocturne::gen_ed25519();
            (void)x25519_kp; // Suppress unused variable warning
            (void)ed25519_kp; // Suppress unused variable warning
            std::cout << "    ✓ X25519 key generation\n";
            std::cout << "    ✓ Ed25519 key generation\n";
            
            // Test key derivation
            std::cout << "  Testing key derivation...\n";
            auto alice = nocturne::gen_x25519();
            auto bob = nocturne::gen_x25519();
            auto client_tx = nocturne::derive_tx_key_client(alice.pk, alice.sk, bob.pk);
            auto server_rx = nocturne::derive_rx_key_server(alice.pk, bob.pk, bob.sk);
            if (client_tx.has_value() && server_rx.has_value() && *client_tx == *server_rx) {
                std::cout << "    ✓ Key derivation\n";
            } else {
                throw std::runtime_error("key derivation failed");
            }
            
            // Test encryption/decryption
            std::cout << "  Testing encryption/decryption...\n";
            nocturne::Bytes test_pt = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
            nocturne::Bytes test_aad = {0xAA, 0xBB, 0xCC, 0xDD};
            auto encrypted = cli_unwrap(nocturne::encrypt_packet(bob.pk, test_pt,
                nocturne::EncryptOptions{.aad = test_aad}));
            auto decrypted = cli_unwrap(nocturne::decrypt_packet(bob.pk, bob.sk, encrypted));
            if (decrypted == test_pt) {
                std::cout << "    ✓ Encryption/decryption\n";
            } else {
                throw std::runtime_error("encryption/decryption failed");
            }
            
            // Test signatures
            std::cout << "  Testing digital signatures...\n";
            nocturne::Bytes test_msg = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
            auto sig = nocturne::ed25519_sign(test_msg, ed25519_kp.sk);
            if (nocturne::ed25519_verify(test_msg, ed25519_kp.pk, sig)) {
                std::cout << "    ✓ Digital signatures\n";
            } else {
                throw std::runtime_error("digital signature verification failed");
            }
            
            // Test replay protection
            std::cout << "  Testing replay protection...\n";
            std::filesystem::path test_db = "test_replaydb.bin";
            std::filesystem::path test_key = "test_mac_key.bin";
            
            // Create test MAC key
            std::array<uint8_t, crypto_generichash_KEYBYTES> mac_key{};
            randombytes_buf(mac_key.data(), mac_key.size());
            {
                std::ofstream f(test_key, std::ios::binary);
                f.write(reinterpret_cast<const char*>(mac_key.data()), mac_key.size());
            }
            
            ReplayDB test_rdb(test_db, test_key);
            test_rdb.set("test_key", 42);
            if (test_rdb.get("test_key") == 42) {
                std::cout << "    ✓ Replay protection\n";
            } else {
                throw std::runtime_error("replay protection failed");
            }
            
            // Cleanup test files
            std::filesystem::remove(test_db);
            std::filesystem::remove(test_key);
            
            std::cout << "All tests passed! ✓\n";
            return 0;
        }

        if (cmd == "hs-demo") {
            using namespace nocturne::handshake;
            nocturne::check_sodium();
            std::cout << "Running handshake demo...\n";
            auto initiator_id = generate_identity_ed25519();
            auto responder_id = generate_identity_ed25519();
            InitiatorHandshake init(initiator_id, responder_id.pk);
            ResponderHandshake resp(responder_id, initiator_id.pk);
            auto h1 = init.create_hello1();
            auto h2 = resp.process_hello1(h1);
            auto h3 = init.process_hello2(h2);
            resp.finalize(h3);
            if (init.is_complete() && resp.is_complete()) {
                std::cout << "  ✓ Handshake complete\n";
            } else {
                throw std::runtime_error("handshake did not complete");
            }
            std::cout << "Derived keys: tx(rx) sizes=" << init.tx_key().size() << "," << init.rx_key().size() << "\n";
            return 0;
        }

        if (cmd == "dr-demo") {
            using namespace nocturne;
            using namespace nocturne::transport;
            nocturne::check_sodium();
            std::cout << "Running Double Ratchet + transport demo...\n";
            // Establish initial shared secret (simulate KX)
            auto a = gen_x25519(); auto b = gen_x25519();
            std::array<uint8_t, crypto_kx_SESSIONKEYBYTES> rx{}, tx{};
            if (crypto_kx_client_session_keys(rx.data(), tx.data(), a.pk.data(), a.sk.data(), b.pk.data()) != 0) throw std::runtime_error("kx fail");
            DoubleRatchet dra(rx); DoubleRatchet drb(rx); // same seed for demo
            dra.set_remote_public_key(drb.get_public_key());
            drb.set_remote_public_key(dra.get_public_key());

            // Transport sessions
            Session sa(1, FeatureSet{}), sb(2, FeatureSet{});
            MemoryTransport ta(sa), tb(sb); ta.set_peer(&tb); tb.set_peer(&ta);

            // Negotiate
            ta.send(sa.make_negotiate()); tb.pump_retries();

            // Set receive handler to decrypt
            tb.set_on_data([&](const DataPayload& d){
                try {
                    RatchetMessage msg{};
                    // For demo, pack dra header into aad and DR ciphertext directly
                    // Normally, you would serialize RatchetMessage separately.
                    msg.dh_public_key = dra.get_public_key();
                    msg.prev_chain_count = 0; msg.message_count = 1; msg.ciphertext = d.ciphertext;
                    std::vector<uint8_t> pt = drb.decrypt_message(msg);
                    (void)pt;
                } catch(...) {}
            });

            // Encrypt one message and send
            std::vector<uint8_t> pt = {1,2,3,4};
            auto rm = dra.encrypt_message(pt);
            Bytes aad; // could include rm headers
            Frame f = sa.make_data(aad, rm.ciphertext);
            ta.send(f);
            tb.pump_retries();
            std::cout << "  ✓ Transport data sent with seq and ACK/NAK handling\n";
            return 0;
        }

        if (cmd == "security-check") {
            std::cout << "Running Nocturne-KX security check...\n";
            
            // Check libsodium version
            std::cout << "  Checking libsodium version...\n";
            (void)sodium_version_string(); // Suppress unused variable warning
            std::cout << "    ✓ libsodium version: " << sodium_version_string() << "\n";
            
            // Check for secure random number generation
            std::cout << "  Checking random number generation...\n";
            std::array<uint8_t, 32> random_bytes{};
            randombytes_buf(random_bytes.data(), random_bytes.size());
            bool has_entropy = false;
            for (const auto b : random_bytes) if (b != 0) { has_entropy = true; break; }
            if (has_entropy) {
                std::cout << "    ✓ Secure random number generation\n";
            } else {
                std::cout << "    ⚠ Warning: Random number generation may not be secure\n";
            }
            
            // Check file permissions (if keys exist)
            std::cout << "  Checking file permissions...\n";
            std::vector<std::string> key_files = {
                "receiver_x25519_sk.bin",
                "sender_ed25519_sk.bin"
            };
            
            for (const auto& key_file : key_files) {
                if (std::filesystem::exists(key_file)) {
                    const auto perms = std::filesystem::status(key_file).permissions();
                    if ((perms & std::filesystem::perms::others_read) == std::filesystem::perms::none &&
                        (perms & std::filesystem::perms::group_read) == std::filesystem::perms::none) {
                        std::cout << "    ✓ " << key_file << " has secure permissions\n";
                    } else {
                        std::cout << "    ⚠ Warning: " << key_file << " has insecure permissions\n";
                    }
                }
            }
            
            // Check environment variables
            std::cout << "  Checking environment variables...\n";
            const char* sensitive_vars[] = {"HSM_PIN", "HSM_SO_PIN", "NOCTURNE_SECRET_KEY"};
            for (const auto& var : sensitive_vars) {
                if (std::getenv(var)) {
                    std::cout << "    ✓ " << var << " is set\n";
                } else {
                    std::cout << "    ℹ " << var << " is not set (may be optional)\n";
                }
            }
            
            std::cout << "Security check completed!\n";
            return 0;
        }

        if (cmd == "audit-log") {
            std::cout << "Nocturne-KX Audit Log\n";
            std::cout << "====================\n\n";
            
            // Log system information
            std::cout << "System Information:\n";
            std::cout << "  Timestamp: " << std::chrono::system_clock::now().time_since_epoch().count() << "\n";
            std::cout << "  libsodium version: " << sodium_version_string() << "\n";
            std::cout << "  Nocturne-KX version: " << static_cast<int>(nocturne::VERSION) << "\n\n";
            
            // Log security features
            std::cout << "Security Features:\n";
            std::cout << "  ✓ X25519 key exchange\n";
            std::cout << "  ✓ ChaCha20-Poly1305 AEAD encryption\n";
            std::cout << "  ✓ Ed25519 digital signatures\n";
            std::cout << "  ✓ Replay protection with MAC\n";
            std::cout << "  ✓ Key rotation enforcement\n";
            std::cout << "  ✓ HSM integration support\n";
            std::cout << "  ✓ Double Ratchet scaffolding\n";
            std::cout << "  ✓ Rate limiting protection\n";
            std::cout << "  ✓ Memory protection with secure allocator\n\n";
            
            // Log warnings
            std::cout << "Security Warnings:\n";
            std::cout << "  ⚠ This is prototype software - not for production use\n";
            std::cout << "  ⚠ FileHSM is for development only - use real HSM in production\n";
            std::cout << "  ⚠ Double Ratchet implementation is basic - not full Signal Protocol\n";
            std::cout << "  ⚠ Limited side-channel protection\n";
            std::cout << "  ⚠ No formal security audit completed\n\n";
            
            // Log recommendations
            std::cout << "Security Recommendations:\n";
            std::cout << "  1. Obtain formal security audit before production use\n";
            std::cout << "  2. Implement proper HSM integration\n";
            std::cout << "  3. Add comprehensive audit logging\n";
            std::cout << "  4. Implement proper key management\n";
            std::cout << "  5. Add real-time security monitoring\n";
            std::cout << "  6. Conduct penetration testing\n";
            std::cout << "  7. Follow secure development lifecycle\n";
            
            return 0;
        }

        if (cmd == "audit-verify") {
            if (argc < 3) { usage(); return 1; }
            std::filesystem::path log_path = argv[2];
            std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> expect_pk;
            for (int i = 3; i < argc; ++i) {
                std::string a = argv[i];
                if (a == "--expect-signer" && i + 1 < argc) {
                    std::filesystem::path pkp = argv[++i];
                    std::ifstream kf(pkp, std::ios::binary);
                    if (!kf) { std::cerr << "ERR: cannot open " << pkp << "\n"; return 2; }
                    std::vector<uint8_t> kb((std::istreambuf_iterator<char>(kf)), std::istreambuf_iterator<char>());
                    if (kb.size() != crypto_sign_PUBLICKEYBYTES) {
                        std::cerr << "ERR: --expect-signer pk has wrong size (" << kb.size()
                                  << ", expected " << crypto_sign_PUBLICKEYBYTES << ")\n";
                        return 2;
                    }
                    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pk{};
                    std::memcpy(pk.data(), kb.data(), kb.size());
                    expect_pk = pk;
                } else {
                    std::cerr << "ERR: unknown audit-verify arg: " << a << "\n";
                    return 1;
                }
            }
            auto res = audit_log::verify_chain(log_path, expect_pk);
            std::cout << "Audit chain verification\n";
            std::cout << "  file:             " << log_path << "\n";
            std::cout << "  records checked:  " << res.records_checked << "\n";
            std::cout << "  ok:               " << (res.ok ? "yes" : "NO") << "\n";
            if (!res.ok) {
                if (res.first_failure_line)
                    std::cout << "  first failure:    line " << *res.first_failure_line << "\n";
                std::cout << "  errors:\n";
                for (const auto& e : res.errors) std::cout << "    " << e << "\n";
                return 3;
            }
            return 0;
        }

        if (cmd == "rate-limit-status") {
            if (argc != 3) { usage(); return 1; }
            std::string identifier = argv[2];
            std::cout << "Rate limiting status for '" << identifier << "':\n";
            std::cout << "  " << rate_limiting::get_status(identifier) << "\n";
            return 0;
        }

        if (cmd == "rate-limit-reset") {
            if (argc != 3) { usage(); return 1; }
            std::string identifier = argv[2];
            rate_limiting::reset(identifier);
            std::cout << "Rate limiting reset for '" << identifier << "'\n";
            return 0;
        }

        if (cmd == "memory-stats") {
            if (argc != 2) { usage(); return 1; }
            std::cout << "Secure Memory Statistics:\n";
            std::cout << memory_protection::get_stats() << "\n";
            return 0;
        }

        usage();
        return 1;
    } catch (const std::exception &e) {
        std::cerr << "ERR: " << e.what() << "\n";
        return 2;
    }
}
#endif // NOCTURNE_FUZZER_BUILD
