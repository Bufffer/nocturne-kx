/// @file secure_storage.hpp
/// @brief Passphrase-protected at-rest secret-key envelope used by the
///        inline @c FileHSM.
///
/// **On-disk format.**
/// @code
///   [6B "NCHSM2" magic]
///   [16B salt]
///   [24B XChaCha20-Poly1305 nonce]
///   [N bytes ciphertext]     // = sk(64) + Poly1305 tag(16) = 80 B
/// @endcode
///
/// The key for AEAD decryption is derived from `NOCTURNE_HSM_PASSPHRASE`
/// via Argon2id (libsodium's `crypto_pwhash` with INTERACTIVE limits) +
/// the on-disk salt. The 80-byte ciphertext envelopes a 64-byte Ed25519
/// secret key, the canonical libsodium form (seed+pk concatenated).
///
/// **When to use.** When the operator stores a long-lived signer SK on
/// a filesystem that's not encrypted at rest. The passphrase is read
/// from an environment variable so it stays out of the process's
/// argv / audit log.
///
/// @par Thread safety
///   Pure function, no shared state. Concurrent calls with disjoint
///   inputs are safe.
/// @par Exception safety
///   Strong. Throws std::runtime_error with a concrete diagnostic on
///   format / size / decryption failure; the caller's state is
///   unchanged on the throwing path.

#pragma once

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <sodium.h>

namespace filehsm_secure_storage {

inline constexpr const char* MAGIC     = "NCHSM2";
inline constexpr std::size_t MAGIC_LEN = 6;
inline constexpr std::size_t SALT_LEN  = 16;

/// @brief Recognize the magic header.
[[nodiscard]] inline bool looks_encrypted(const std::vector<std::uint8_t>& blob) noexcept {
    return blob.size() > MAGIC_LEN
        && std::memcmp(blob.data(), MAGIC, MAGIC_LEN) == 0;
}

/// @brief Decrypt a passphrase-protected Ed25519 SK blob.
///
/// @param blob Raw bytes (output of @c read_all on the key file).
/// @return     std::nullopt if @p blob is unrecognized (not passphrase-
///             encrypted); a populated 64-byte SK on success.
/// @par Pre  If passphrase encryption is in use, the env var
///           `NOCTURNE_HSM_PASSPHRASE` is set and non-empty.
[[nodiscard]] inline std::optional<std::array<std::uint8_t, crypto_sign_SECRETKEYBYTES>>
decrypt_sk_with_passphrase(const std::vector<std::uint8_t>& blob)
{
    if (!looks_encrypted(blob)) return std::nullopt;

    const std::uint8_t* p   = blob.data() + MAGIC_LEN;
    std::size_t         rem = blob.size() - MAGIC_LEN;
    if (rem < SALT_LEN
            + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
            + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        throw std::runtime_error{"FileHSM: encrypted blob truncated"};
    }

    std::array<std::uint8_t, SALT_LEN> salt{};
    std::memcpy(salt.data(), p, SALT_LEN);
    p += SALT_LEN;  rem -= SALT_LEN;

    std::array<std::uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> npub{};
    std::memcpy(npub.data(), p, npub.size());
    p += npub.size();  rem -= npub.size();

    std::vector<std::uint8_t> ct(p, p + rem);

    const char* pass = std::getenv("NOCTURNE_HSM_PASSPHRASE");
    if (!pass || std::strlen(pass) == 0) {
        throw std::runtime_error{
            "FileHSM: NOCTURNE_HSM_PASSPHRASE not set for encrypted key"};
    }

    std::array<std::uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> k{};
    if (crypto_pwhash(k.data(), k.size(),
                      pass, std::strlen(pass),
                      salt.data(),
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error{"FileHSM: key derivation failed"};
    }

    if (ct.size() != crypto_sign_SECRETKEYBYTES
                     + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        throw std::runtime_error{"FileHSM: encrypted payload size invalid"};
    }

    std::array<std::uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
    unsigned long long pt_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            sk.data(), &pt_len, nullptr,
            ct.data(), ct.size(),
            nullptr, 0,
            npub.data(), k.data()) != 0) {
        throw std::runtime_error{"FileHSM: decryption failed"};
    }
    if (pt_len != crypto_sign_SECRETKEYBYTES) {
        throw std::runtime_error{"FileHSM: decrypted length mismatch"};
    }
    return sk;
}

}  // namespace filehsm_secure_storage
