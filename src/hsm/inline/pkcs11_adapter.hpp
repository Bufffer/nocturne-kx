/// @file pkcs11_adapter.hpp
/// @brief Thin adapter binding the CLI's inline @ref HSMInterface to
///        the production-grade @c nocturne::hsm::PKCS11HSM.
///
/// **CLI URI.** `hsm://<token_label>:<key_label>`. The token label
/// selects the PKCS#11 slot; the key label identifies the on-token
/// object holding the Ed25519 SK.
///
/// **Environment variables.**
///   - `PKCS11_LIB`        absolute path to the PKCS#11 module
///                         (`.so` / `.dll`). REQUIRED.
///   - `NOCTURNE_HSM_PIN`  user PIN for `C_Login`. Optional but
///                         required for sign on most tokens. The PIN
///                         buffer is securely zeroed after authenticate
///                         returns.
///   - `NOCTURNE_HSM_FIPS` "1" to enforce FIPS mode (default: 0).
///
/// **Why an adapter.** The enterprise `nocturne::hsm::PKCS11HSM` has a
/// richer surface (audit trail, dual-control approvals, key
/// generation) than the inline interface needs. The adapter exposes
/// only the four CLI-facing methods.
///
/// @par Thread safety
///   The underlying enterprise PKCS11HSM is internally synchronized.
///   The adapter is stateless beyond the unique_ptr to it; concurrent
///   sign/verify calls are safe.
/// @par Exception safety
///   Ctor throws @ref nocturne::HSMError on missing PKCS11_LIB env,
///   library load failure, or C_Login failure. sign() propagates the
///   underlying HSM's exception unchanged.

#pragma once

#include "../../core/side_channel.hpp"
#include "../../core/types.hpp"
#include "../pkcs11_hsm.hpp"  // nocturne::hsm::PKCS11HSM
#include "hsm_interface.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <sodium.h>

class PKCS11HSM : public HSMInterface {
  public:
    PKCS11HSM(const std::string& token_id, const std::string& key_label)
        : token_id_{token_id}, key_label_{key_label}
    {
        if (token_id.empty())  throw nocturne::HSMError{"HSM token ID cannot be empty"};
        if (key_label.empty()) throw nocturne::HSMError{"HSM key label cannot be empty"};

        const std::string lib_path = env_or_empty("PKCS11_LIB");
        if (lib_path.empty()) {
            throw nocturne::HSMError{
                "PKCS#11 library path not configured: set PKCS11_LIB env var "
                "(e.g. /usr/lib/softhsm/libsofthsm2.so)"};
        }

        const bool require_fips = env_or_empty("NOCTURNE_HSM_FIPS") == "1";

        try {
            impl_ = std::make_unique<nocturne::hsm::PKCS11HSM>(
                lib_path, token_id_, key_label_, require_fips);
        } catch (const std::exception& e) {
            throw nocturne::HSMError{
                std::string{"PKCS#11 init failed: "} + e.what()};
        }

        std::string pin = env_or_empty("NOCTURNE_HSM_PIN");
        if (!pin.empty()) {
            std::string pin_copy = pin;  // mutable for authenticate()
            // Best-effort scrub of the env-derived buffer too.
            nocturne::side_channel::secure_zero_memory(pin.data(), pin.size());
            if (!impl_->authenticate(pin_copy)) {
                throw nocturne::HSMError{
                    "PKCS#11 C_Login failed (check PIN/lockout)"};
            }
        }
    }

    ~PKCS11HSM() override {
        if (impl_) {
            try { impl_->logout(); } catch (...) {
                // Destructors must not throw — best-effort logout.
            }
        }
    }

    std::array<std::uint8_t, crypto_sign_BYTES>
    sign(nocturne::BytesView data) override {
        if (!impl_) throw nocturne::HSMError{"PKCS#11 HSM not initialized"};
        return impl_->sign(data);
    }

    [[nodiscard]] std::optional<std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES>>
    get_public_key() override {
        if (!impl_) return std::nullopt;
        return impl_->get_public_key();
    }

    [[nodiscard]] bool has_key(const std::string& label) override {
        return impl_ && impl_->has_key(label);
    }

    [[nodiscard]] std::vector<std::uint8_t> generate_random(std::size_t length) override {
        if (!impl_) {
            // Fallback to libsodium if the HSM dropped out.
            std::vector<std::uint8_t> out(length);
            randombytes_buf(out.data(), length);
            return out;
        }
        return impl_->generate_random(length);
    }

    [[nodiscard]] bool is_healthy() override {
        return impl_ && impl_->is_healthy();
    }

  private:
    static std::string env_or_empty(const char* name) {
        const char* v = std::getenv(name);
        return v ? std::string{v} : std::string{};
    }

    std::string                              token_id_;
    std::string                              key_label_;
    std::unique_ptr<nocturne::hsm::PKCS11HSM> impl_;
};
