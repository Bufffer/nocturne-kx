/// @file keys.hpp
/// @brief Thin inline wrappers around libsodium's X25519 and Ed25519
///        keypair primitives.
///
/// The two helpers use @c memory_protection::SecureMemory to keep the
/// freshly-generated secret key in a destructor-zeroed buffer until it's
/// copied out into the caller's @ref X25519KeyPair / @ref Ed25519KeyPair,
/// flush the cache line, then return. The post-copy keypair is plain
/// memory — call-site code is responsible for wiping it once it's
/// finished consuming the secret (which is what
/// @c side_channel::secure_zero_memory in the encrypt/decrypt paths does).
///
/// Extracted from @c nocturne-kx.cpp during P5.7 because both that
/// translation unit and @c src/protocol/messaging.cpp need to call the
/// same generators.

#pragma once

#include "../core/side_channel.hpp"
#include "../core/types.hpp"
#include "../security/inline/memory_protection.hpp"

#include <cstring>

#include <sodium.h>

namespace nocturne {

[[nodiscard]] inline X25519KeyPair gen_x25519() {
    memory_protection::SecureMemory<std::uint8_t> secure_sk(crypto_kx_SECRETKEYBYTES);
    memory_protection::SecureMemory<std::uint8_t> secure_pk(crypto_kx_PUBLICKEYBYTES);

    crypto_kx_keypair(secure_pk.get(), secure_sk.get());

    side_channel::flush_cache_line(secure_sk.get());
    side_channel::random_delay();
    side_channel::memory_barrier();

    X25519KeyPair kp;
    std::memcpy(kp.pk.data(), secure_pk.get(), crypto_kx_PUBLICKEYBYTES);
    std::memcpy(kp.sk.data(), secure_sk.get(), crypto_kx_SECRETKEYBYTES);
    return kp;
}

[[nodiscard]] inline Ed25519KeyPair gen_ed25519() {
    memory_protection::SecureMemory<std::uint8_t> secure_sk(crypto_sign_SECRETKEYBYTES);
    memory_protection::SecureMemory<std::uint8_t> secure_pk(crypto_sign_PUBLICKEYBYTES);

    if (crypto_sign_keypair(secure_pk.get(), secure_sk.get()) != 0) {
        throw CryptoError("ed25519 keypair generation failed");
    }

    side_channel::flush_cache_line(secure_sk.get());
    side_channel::random_delay();
    side_channel::memory_barrier();

    Ed25519KeyPair kp;
    std::memcpy(kp.pk.data(), secure_pk.get(), crypto_sign_PUBLICKEYBYTES);
    std::memcpy(kp.sk.data(), secure_sk.get(), crypto_sign_SECRETKEYBYTES);
    return kp;
}

}  // namespace nocturne
