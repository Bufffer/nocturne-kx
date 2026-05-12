/// @file file_hsm.hpp
/// @brief File-backed HSMInterface implementation used by the CLI when
///        `--sign-hsm-uri file://...` is supplied.
///
/// **At-rest semantics.** The SK file may be either:
///   - **Raw 64 bytes** — libsodium-canonical Ed25519 SK. Suitable for
///     dev/test only; the file is plaintext on disk.
///   - **Passphrase-encrypted** — `NCHSM2` envelope decoded by
///     @ref secure_storage.hpp. The passphrase comes from
///     `NOCTURNE_HSM_PASSPHRASE`.
///
/// In both cases the SK lives in process memory inside a
/// @ref memory_protection::SecureMemory<uint8_t> for the lifetime of
/// the @c FileHSM — pinned, scrubbed on destruction.
///
/// **Sign discipline.** Every call to @ref sign copies the SK into a
/// stack-allocated buffer, invokes Ed25519, then zeroes the copy via
/// @c side_channel::secure_zero_memory. The SecureMemory store itself
/// is never exposed by reference to libsodium.
///
/// @par Thread safety
///   Read-only after construction (the SK never mutates). Concurrent
///   sign() calls are safe — libsodium's Ed25519 is reentrant.
/// @par Exception safety
///   Ctor throws @ref nocturne::HSMError / @ref nocturne::IOError /
///   @ref nocturne::CryptoError on key-load failure. sign() throws
///   only if the HSM was never initialized successfully.

#pragma once

#include "../../core/types.hpp"
#include "../../core/file_io.hpp"
#include "../../core/side_channel.hpp"
#include "../../protocol/signing.hpp"
#include "../../security/inline/memory_protection.hpp"
#include "hsm_interface.hpp"
#include "secure_storage.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <sodium.h>

class FileHSM : public HSMInterface {
  public:
    explicit FileHSM(const std::filesystem::path& path)
        : secure_sk_{crypto_sign_SECRETKEYBYTES},
          secure_pk_{crypto_sign_PUBLICKEYBYTES}
    {
        std::vector<std::uint8_t> blob;
        try {
            blob = nocturne::read_all(path);
        } catch (const std::exception& e) {
            throw nocturne::IOError{
                std::string{"FileHSM: failed to read key file: "} + e.what()};
        }

        try {
            if (auto dec = filehsm_secure_storage::decrypt_sk_with_passphrase(blob)) {
                std::memcpy(secure_sk_.get(), dec->data(), crypto_sign_SECRETKEYBYTES);
            } else {
                if (blob.size() != crypto_sign_SECRETKEYBYTES) {
                    throw nocturne::HSMError{"filehsm sk size mismatch"};
                }
                std::memcpy(secure_sk_.get(), blob.data(), crypto_sign_SECRETKEYBYTES);
            }
        } catch (const std::exception& e) {
            throw nocturne::HSMError{
                std::string{"FileHSM: failed to load/decrypt key: "} + e.what()};
        }

        if (crypto_sign_ed25519_sk_to_pk(secure_pk_.get(), secure_sk_.get()) != 0) {
            throw nocturne::CryptoError{"failed to derive public key from secret key"};
        }
        initialized_ = true;
    }

    std::array<std::uint8_t, crypto_sign_BYTES>
    sign(const std::uint8_t* data, std::size_t len) override {
        if (!initialized_) throw nocturne::HSMError{"FileHSM not initialized"};

        // Lift the SK into a stack buffer for the libsodium call; zero it
        // afterward so the working copy never lingers in the call frame.
        std::array<std::uint8_t, crypto_sign_SECRETKEYBYTES> temp_sk{};
        std::memcpy(temp_sk.data(), secure_sk_.get(), crypto_sign_SECRETKEYBYTES);

        const nocturne::BytesView msg{data, len};
        const auto sig = nocturne::ed25519_sign(msg, temp_sk);

        nocturne::side_channel::secure_zero_memory(temp_sk.data(), temp_sk.size());
        return sig;
    }

    [[nodiscard]] std::optional<std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES>>
    get_public_key() override {
        if (!initialized_) return std::nullopt;
        std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES> pk{};
        std::memcpy(pk.data(), secure_pk_.get(), crypto_sign_PUBLICKEYBYTES);
        return pk;
    }

    [[nodiscard]] bool has_key(const std::string& label) override {
        return initialized_ && label == "default";
    }

    [[nodiscard]] std::vector<std::uint8_t> generate_random(std::size_t length) override {
        std::vector<std::uint8_t> out(length);
        randombytes_buf(out.data(), length);
        return out;
    }

    [[nodiscard]] bool is_healthy() override {
        return initialized_;
    }

    // SecureMemory destructors auto-zero the SK and pk pages on drop.
    ~FileHSM() override = default;

  private:
    memory_protection::SecureMemory<std::uint8_t> secure_sk_;
    memory_protection::SecureMemory<std::uint8_t> secure_pk_;
    bool                                          initialized_ = false;
};
