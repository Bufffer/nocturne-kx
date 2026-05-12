/// @file replay_db.hpp
/// @brief Encrypted, MAC-authenticated on-disk counter store used to
///        detect replayed packets.
///
/// **Threat model.** A packet's counter must monotonically increase
/// for a given (receiver, sender, session) tuple. The ReplayDB persists
/// the highest counter seen so far for each tuple. On every received
/// packet the receiver consults the DB; a counter ≤ the stored value
/// is a replay and is rejected.
///
/// **Storage.** The on-disk file is XChaCha20-Poly1305 encrypted with a
/// key derived from the MAC key (`crypto_generichash(mac_key,
/// "replaydb-enc")`). Each persist cycle increments the file's version
/// counter; rollback by an attacker with file-system access is
/// detected by an optional external monotonic counter (TPM-backed or
/// file-bridged) the user supplies.
///
/// **Legacy format.** Older deployments may still hold an unencrypted
/// `[version|json_len|json|MAC]` file. The loader auto-detects via the
/// MSB of the version field; the encrypted format sets that bit.
///
/// @par Thread safety
///   Every public method takes an internal mutex. Safe to share across
///   threads.
/// @par Exception safety
///   Strong. The on-disk store is updated via temp-file rename so a
///   crash leaves the previous file intact. In-memory state changes
///   commit only after persist_unlocked succeeds.
///
/// @version 1.0.0

#pragma once

#include "../../core/byte_span.hpp"
#include "../../core/types.hpp"
#include "audit_logger.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <sodium.h>

namespace nocturne {

/// @brief Encrypted, MAC-protected replay counter store.
class ReplayDB {
  public:
    /// @brief Open or create a ReplayDB at @p p.
    /// @param p                Path to the JSONL-like encrypted file.
    /// @param keyfile          Optional file holding the @c crypto_generichash_KEYBYTES
    ///                         MAC key. If absent or nullopt, a
    ///                         transient (not persisted) key is
    ///                         generated — useful for tests, never for
    ///                         production.
    /// @param tpm_counter_path Optional path to an external monotonic
    ///                         counter (TPM or file-bridge). When set,
    ///                         load() refuses to open a file whose
    ///                         version is less than the counter's
    ///                         value — that catches file-system rollback.
    /// @par Exception safety: Strong. Throws @ref IOError /
    ///                        std::runtime_error on corrupt files,
    ///                        size mismatches, or MAC failures.
    ReplayDB(std::filesystem::path                       p,
             const std::optional<std::filesystem::path>& keyfile          = std::nullopt,
             const std::optional<std::filesystem::path>& tpm_counter_path = std::nullopt);

    /// @brief Look up the highest counter for the legacy (rx-only) key.
    [[nodiscard]] std::uint64_t get(const std::string& hexpk);

    /// @brief Record a new high-water counter for the legacy key.
    void set(const std::string& hexpk, std::uint64_t v);

    /// @brief Scoped lookup: composite key of (rx, sender, session).
    [[nodiscard]] std::uint64_t get_scoped(const std::string&                rx_hex,
                                            const std::optional<std::string>& sender_pk_hex,
                                            const std::optional<std::string>& session_id);

    /// @brief Scoped update.
    void set_scoped(const std::string&                rx_hex,
                    const std::optional<std::string>& sender_pk_hex,
                    const std::optional<std::string>& session_id,
                    std::uint64_t                      v);

    /// @brief Force a flush to disk. Normally automatic on every set*.
    void persist();

  private:
    void persist_unlocked();
    void load();

    static std::string db_temp_path(const std::filesystem::path& p) {
        return p.string() + ".tmp";
    }

    static std::string make_scope_key(const std::string&                rx_hex,
                                      const std::optional<std::string>& sender_pk_hex,
                                      const std::optional<std::string>& session_id) {
        std::string key;
        key.reserve(rx_hex.size()
                    + (sender_pk_hex ? sender_pk_hex->size() : 1)
                    + (session_id    ? session_id->size()    : 1) + 16);
        key += "rx=";   key += rx_hex;
        key += "&snd="; key += (sender_pk_hex ? *sender_pk_hex : std::string{"-"});
        key += "&sid="; key += (session_id    ? *session_id    : std::string{"-"});
        return key;
    }

    std::filesystem::path                                                            path_;
    std::unordered_map<std::string, std::uint64_t>                                    m_;
    std::mutex                                                                        mu_;
    std::array<std::uint8_t, crypto_generichash_KEYBYTES>                             mac_key_{};
    std::array<std::uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>             enc_key_{};
    std::uint64_t                                                                     version_{1};
    std::optional<std::filesystem::path>                                              tpm_counter_path_{};
};

}  // namespace nocturne
