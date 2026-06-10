/// @file messaging.cpp
/// @brief Implementation of the high-level encrypt/decrypt entry points
///        declared in messaging.hpp.
///
/// Extracted from the inline scaffolding in @c nocturne-kx.cpp during
/// P5.7. No behavior change — the wire format and KDF/AEAD/signature
/// composition are byte-for-byte preserved.

#include "messaging.hpp"

#include "aead.hpp"
#include "kdf.hpp"
#include "keys.hpp"
#include "packet_io.hpp"
#include "../core/byte_span.hpp"
#include "../core/flags.hpp"
#include "../core/result.hpp"
#include "../core/side_channel.hpp"
#include "../core/types.hpp"
#include "../pqc/kem/kem_factory.hpp"
#include "../pqc/pqc_config.hpp"
#include "../security/inline/rate_limiter.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>

namespace nocturne {
namespace {

/// File-local hex encoder used to build rate-limit and replay-DB keys
/// from receiver public keys. Modern span-based interface; not exposed
/// outside this TU.
[[nodiscard]] std::string hexify(std::span<const std::uint8_t> bytes) {
    static constexpr std::array<char, 16> nibble = {
        '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
    };
    std::string out;
    out.reserve(bytes.size() * 2);
    for (auto b : bytes) {
        out.push_back(nibble[b >> 4]);
        out.push_back(nibble[b & 0x0F]);
    }
    return out;
}

/// Local helper used by both encrypt entry points; appends @p session_id
/// to a rate-limit key only when it's non-empty.
[[nodiscard]] std::string with_session(std::string base, const std::string& session_id) {
    if (!session_id.empty()) {
        base += ":";
        base += session_id;
    }
    return base;
}

/// P6.1a shim: primitives (kdf/aead/packet) now return Result<T> while
/// these entry points still expose the throwing API. P6.1b converts the
/// entry points themselves to Result and deletes this helper.
template <typename T>
[[nodiscard]] T unwrap(Result<T> r) {
    if (!r) {
        throw std::runtime_error{std::string{r.error().name()} + ": "
                                 + r.error().message};
    }
    return std::move(*r);
}

}  // namespace

// ---------------------------------------------------------------------
// Classical X25519 path
// ---------------------------------------------------------------------

Bytes encrypt_packet(
    const std::array<std::uint8_t, crypto_kx_PUBLICKEYBYTES>& receiver_x25519_pk,
    const Bytes& plaintext,
    const EncryptOptions& opts)
{
    check_sodium();

    const std::string rate_limit_id = with_session(
        "encrypt:" + hexify(receiver_x25519_pk), opts.session_id);
    if (!rate_limiting::allow_request(rate_limit_id)) {
        throw std::runtime_error("Rate limit exceeded for encryption operation");
    }

    auto eph = gen_x25519();
    auto key = unwrap(derive_tx_key_client(eph.pk, eph.sk, receiver_x25519_pk));

    Packet p;
    p.version = VERSION;
    p.flags = 0;
    p.rotation_id = opts.rotation_id;
    randombytes_buf(p.nonce.data(), p.nonce.size());
    p.eph_pk = eph.pk;

    if (opts.replay_db != nullptr) {
        const std::string rid = "tx:" + hexify(receiver_x25519_pk);
        const std::uint64_t prev = opts.replay_db->get(rid);
        p.counter = prev + 1;
        opts.replay_db->set(rid, p.counter);
    } else {
        std::uint64_t c{0};
        randombytes_buf(&c, sizeof(c));
        p.counter = c;
    }

    if (opts.use_ratchet) {
        p.flags |= FLAG_HAS_RATCHET;
        auto ratk = gen_x25519();
        p.ratchet_pk = ratk.pk;
        std::array<std::uint8_t, crypto_scalarmult_BYTES> dh_shared{};
        if (crypto_scalarmult(dh_shared.data(), ratk.sk.data(), receiver_x25519_pk.data()) != 0) {
            throw std::runtime_error("dh failed");
        }
        auto mixed = unwrap(ratchet_mix(key, BytesView{dh_shared.data(), dh_shared.size()}));
        side_channel::secure_zero_memory(key.data(), key.size());
        side_channel::secure_zero_memory(ratk.sk.data(), ratk.sk.size());
        side_channel::flush_cache_line(key.data());
        side_channel::flush_cache_line(ratk.sk.data());
        key = mixed;
    }

    p.aad = opts.aad;
    p.ciphertext = unwrap(aead_encrypt_xchacha(key, p.nonce, p.aad, plaintext));

    if (opts.signer != nullptr) {
        packet_io::attach_classical_signature(p, *opts.signer, opts.session_id);
    }
    if (opts.pqc_signer != nullptr) {
        packet_io::attach_pqc_signature(p, *opts.pqc_signer, opts.session_id);
    }

    auto out = unwrap(serialize(p));

    side_channel::secure_zero_memory(eph.sk.data(), eph.sk.size());
    side_channel::secure_zero_memory(key.data(), key.size());
    side_channel::flush_cache_line(eph.sk.data());
    side_channel::flush_cache_line(key.data());
    side_channel::memory_barrier();

    return out;
}

Bytes decrypt_packet(
    const std::array<std::uint8_t, crypto_kx_PUBLICKEYBYTES>& receiver_x25519_pk,
    const std::array<std::uint8_t, crypto_kx_SECRETKEYBYTES>& receiver_x25519_sk,
    const Bytes& packet_bytes,
    const DecryptOptions& opts)
{
    check_sodium();

    const std::string rate_limit_id = with_session(
        "decrypt:" + hexify(receiver_x25519_pk), opts.session_id);
    if (!rate_limiting::allow_request(rate_limit_id)) {
        throw std::runtime_error("Rate limit exceeded for decryption operation");
    }

    Packet p = unwrap(deserialize(packet_bytes));

    if (opts.expected_signer_ed25519_pk.has_value()) {
        packet_io::verify_classical_signature(
            p, *opts.expected_signer_ed25519_pk, opts.session_id);
    }
    if (opts.pqc_verifier != nullptr) {
        packet_io::verify_pqc_signature(p, *opts.pqc_verifier, opts.session_id);
    }

    if (opts.min_rotation_id.has_value() && p.rotation_id < *opts.min_rotation_id) {
        throw std::runtime_error("stale rotation_id: reject message");
    }

    if (opts.replay_db != nullptr) {
        const std::string rid = "rx:" + hexify(receiver_x25519_pk);
        const std::uint64_t last = opts.replay_db->get(rid);
        if (p.counter <= last) {
            throw std::runtime_error("replay detected: counter too small");
        }
        if (p.counter > last + 1000) {
            std::cerr << "WARNING: Large counter gap detected: "
                      << last << " -> " << p.counter << std::endl;
        }
        opts.replay_db->set(rid, p.counter);
    }

    auto key = unwrap(derive_rx_key_server(p.eph_pk, receiver_x25519_pk, receiver_x25519_sk));

    if ((p.flags & FLAG_HAS_RATCHET) != 0) {
        if (!p.ratchet_pk.has_value()) {
            throw std::runtime_error("ratchet pk missing");
        }
        std::array<std::uint8_t, crypto_scalarmult_BYTES> dh_shared{};
        if (crypto_scalarmult(dh_shared.data(), receiver_x25519_sk.data(),
                              p.ratchet_pk->data()) != 0) {
            throw std::runtime_error("dh failed");
        }
        auto mixed = unwrap(ratchet_mix(key, BytesView{dh_shared.data(), dh_shared.size()}));
        side_channel::secure_zero_memory(key.data(), key.size());
        side_channel::flush_cache_line(key.data());
        key = mixed;
    }

    auto pt = unwrap(aead_decrypt_xchacha(key, p.nonce, p.aad, p.ciphertext));

    side_channel::secure_zero_memory(key.data(), key.size());
    side_channel::flush_cache_line(key.data());
    side_channel::memory_barrier();

    if (pt.size() > 1024 * 1024) {
        throw std::runtime_error("decrypted plaintext too large");
    }

    return pt;
}

// ---------------------------------------------------------------------
// Post-Quantum / Hybrid KEM path
// ---------------------------------------------------------------------

Bytes encrypt_packet_kem(
    pqc::KEMType kem_type,
    const std::vector<std::uint8_t>& receiver_pk,
    const Bytes& plaintext,
    const EncryptOptions& opts)
{
    check_sodium();

    if (kem_type == pqc::KEMType::CLASSIC_X25519) {
        throw std::runtime_error("encrypt_packet_kem: use encrypt_packet for X25519");
    }

    auto kem = pqc::KEMFactory{}.create(kem_type);
    if (receiver_pk.size() != kem->public_key_size()) {
        throw std::runtime_error("receiver kem pk size mismatch (expected " +
                                 std::to_string(kem->public_key_size()) + ", got " +
                                 std::to_string(receiver_pk.size()) + ")");
    }

    const auto pk_prefix = std::span{receiver_pk}.first(
        std::min<std::size_t>(receiver_pk.size(), 32));
    const std::string rate_limit_id = with_session(
        "encrypt_kem:" + hexify(pk_prefix), opts.session_id);
    if (!rate_limiting::allow_request(rate_limit_id)) {
        throw std::runtime_error("Rate limit exceeded for kem encryption operation");
    }

    auto [kem_ct, kem_ss] = kem->encapsulate(receiver_pk);
    auto key = unwrap(derive_aead_key_from_kem_secret(kem_ss.secret, "nocturne-kem-tx-v4"));

    Packet p;
    p.version = VERSION;
    p.flags = FLAG_HAS_PQC_KEM;
    p.rotation_id = opts.rotation_id;
    randombytes_buf(p.nonce.data(), p.nonce.size());
    p.pqc_kem_type = static_cast<std::uint8_t>(kem_type);
    p.pqc_kem_ct = std::move(kem_ct.ciphertext);

    if (opts.replay_db != nullptr) {
        const std::string rid = "tx-kem:" + hexify(pk_prefix);
        const std::uint64_t prev = opts.replay_db->get(rid);
        p.counter = prev + 1;
        opts.replay_db->set(rid, p.counter);
    } else {
        std::uint64_t c{0};
        randombytes_buf(&c, sizeof(c));
        p.counter = c;
    }

    p.aad = opts.aad;
    p.ciphertext = unwrap(aead_encrypt_xchacha(key, p.nonce, p.aad, plaintext));

    if (opts.signer != nullptr) {
        packet_io::attach_classical_signature(p, *opts.signer, opts.session_id);
    }
    if (opts.pqc_signer != nullptr) {
        packet_io::attach_pqc_signature(p, *opts.pqc_signer, opts.session_id);
    }

    auto out = unwrap(serialize(p));

    side_channel::secure_zero_memory(key.data(), key.size());
    side_channel::flush_cache_line(key.data());
    side_channel::memory_barrier();
    return out;
}

Bytes decrypt_packet_kem(
    const std::vector<std::uint8_t>& receiver_pk,
    const std::vector<std::uint8_t>& receiver_sk,
    const Bytes& packet_bytes,
    const DecryptOptions& opts)
{
    check_sodium();

    Packet p = unwrap(deserialize(packet_bytes));

    if ((p.flags & FLAG_HAS_PQC_KEM) == 0 || p.pqc_kem_ct.empty()) {
        throw std::runtime_error("packet is not a PQC/KEM packet");
    }

    const auto kem_type = static_cast<pqc::KEMType>(p.pqc_kem_type);
    if (kem_type == pqc::KEMType::CLASSIC_X25519) {
        throw std::runtime_error("X25519 packet flagged as PQC — refusing");
    }

    auto kem = pqc::KEMFactory{}.create(kem_type);
    if (receiver_pk.size() != kem->public_key_size()) {
        throw std::runtime_error("receiver kem pk size mismatch");
    }
    if (receiver_sk.size() != kem->secret_key_size()) {
        throw std::runtime_error("receiver kem sk size mismatch");
    }
    if (p.pqc_kem_ct.size() != kem->ciphertext_size()) {
        throw std::runtime_error("kem ciphertext size mismatch");
    }

    const auto pk_prefix = std::span{receiver_pk}.first(
        std::min<std::size_t>(receiver_pk.size(), 32));
    const std::string rate_limit_id = with_session(
        "decrypt_kem:" + hexify(pk_prefix), opts.session_id);
    if (!rate_limiting::allow_request(rate_limit_id)) {
        throw std::runtime_error("Rate limit exceeded for kem decryption operation");
    }

    if (opts.expected_signer_ed25519_pk.has_value()) {
        packet_io::verify_classical_signature(
            p, *opts.expected_signer_ed25519_pk, opts.session_id);
    }
    if (opts.pqc_verifier != nullptr) {
        packet_io::verify_pqc_signature(p, *opts.pqc_verifier, opts.session_id);
    }

    if (opts.min_rotation_id.has_value() && p.rotation_id < *opts.min_rotation_id) {
        throw std::runtime_error("stale rotation_id: reject message");
    }

    if (opts.replay_db != nullptr) {
        const std::string rid = "rx-kem:" + hexify(pk_prefix);
        const std::uint64_t last = opts.replay_db->get(rid);
        if (p.counter <= last) {
            throw std::runtime_error("replay detected: counter too small");
        }
        if (p.counter > last + 1000) {
            std::cerr << "WARNING: Large counter gap detected: "
                      << last << " -> " << p.counter << std::endl;
        }
        opts.replay_db->set(rid, p.counter);
    }

    pqc::KEMCiphertext ct;
    ct.type = kem_type;
    // HybridKEM::combine_secrets binds the derived shared secret to
    // NOCTURNE_PROTOCOL_VERSION (the PQC protocol version, 4), NOT to
    // the outer Nocturne packet version (still 3 for backward compat).
    // The sender's encapsulate() uses NOCTURNE_PROTOCOL_VERSION here, so
    // the receiver must mirror it — otherwise sender and receiver derive
    // different combined secrets and the AEAD tag fails to authenticate
    // even though the KEM math is correct.
    ct.version = static_cast<std::uint32_t>(NOCTURNE_PROTOCOL_VERSION);
    ct.ciphertext = p.pqc_kem_ct;
    auto kem_ss = kem->decapsulate(ct, receiver_sk);
    auto key = unwrap(derive_aead_key_from_kem_secret(kem_ss.secret, "nocturne-kem-tx-v4"));

    auto pt = unwrap(aead_decrypt_xchacha(key, p.nonce, p.aad, p.ciphertext));

    side_channel::secure_zero_memory(key.data(), key.size());
    side_channel::flush_cache_line(key.data());
    side_channel::memory_barrier();

    if (pt.size() > 1024 * 1024) {
        throw std::runtime_error("decrypted plaintext too large");
    }
    return pt;
}

}  // namespace nocturne
