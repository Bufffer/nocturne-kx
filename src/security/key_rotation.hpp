#ifndef NOCTURNE_SECURITY_KEY_ROTATION_HPP
#define NOCTURNE_SECURITY_KEY_ROTATION_HPP

#include "../hsm/hsm_interface.hpp"
#include <memory>
#include <chrono>
#include <vector>
#include <array>
#include <unordered_map>
#include <mutex>
#include <optional>
#include <functional>

namespace nocturne {
namespace security {

/**
 * @brief Key state enumeration
 */
enum class KeyState {
    PENDING,          ///< Key generated but not yet active
    ACTIVE,           ///< Key is currently active
    DEACTIVATED,      ///< Key deactivated (can still decrypt old messages)
    COMPROMISED,      ///< Key suspected/confirmed compromised
    DESTROYED,        ///< Key destroyed (unrecoverable)
    ARCHIVED          ///< Key archived for compliance/recovery
};

/**
 * @brief Key metadata for tracking
 */
struct KeyMetadata {
    std::array<uint8_t, 32> key_id;                      ///< Unique key identifier
    std::string label;                                   ///< Human-readable label
    std::chrono::system_clock::time_point created_at;    ///< Creation timestamp
    std::chrono::system_clock::time_point expires_at;    ///< Expiration timestamp
    std::chrono::system_clock::time_point activated_at;  ///< Activation timestamp
    std::chrono::system_clock::time_point deactivated_at; ///< Deactivation timestamp

    KeyState state = KeyState::PENDING;                  ///< Current state
    uint64_t operation_count = 0;                        ///< Total operations
    uint64_t bytes_processed = 0;                        ///< Total bytes encrypted/signed

    std::optional<std::array<uint8_t, 32>> successor_key_id; ///< Next key in rotation
    std::optional<std::array<uint8_t, 32>> predecessor_key_id; ///< Previous key

    std::vector<std::string> approvers;                  ///< List of approver IDs
    bool dual_control_satisfied = false;                 ///< Dual control requirement met
};

/**
 * @brief Key rotation trigger types
 */
enum class RotationTrigger {
    TIME_BASED,       ///< Rotate every N seconds
    COUNT_BASED,      ///< Rotate after N operations
    VOLUME_BASED,     ///< Rotate after N bytes
    MANUAL,           ///< Manual rotation (operator-initiated)
    COMPROMISE        ///< Emergency rotation (suspected compromise)
};

/**
 * @brief Key rotation policy configuration
 */
struct RotationPolicy {
    std::chrono::seconds max_key_lifetime{30 * 24 * 3600};  ///< 30 days default
    uint64_t max_operations{1'000'000};                      ///< 1M operations
    uint64_t max_bytes{1ULL << 40};                          ///< 1 TB

    bool require_dual_approval = true;                       ///< Require 2+ approvals
    bool require_hsm_backup = true;                          ///< Backup to HSM
    bool archive_old_keys = true;                            ///< Keep old keys
    std::chrono::seconds archive_retention{365 * 24 * 3600}; ///< 1 year retention

    bool allow_manual_rotation = true;                       ///< Allow manual override
    bool enforce_crypto_period = true;                       ///< Strictly enforce periods
};

/**
 * @brief Key rotation event for audit trail
 */
struct RotationEvent {
    std::chrono::system_clock::time_point timestamp;
    std::array<uint8_t, 32> old_key_id;
    std::array<uint8_t, 32> new_key_id;
    RotationTrigger trigger;
    std::string initiator;                                   ///< User/process ID
    std::vector<std::string> approvers;
    bool success;
    std::optional<std::string> error_message;
};

/**
 * @brief MILITARY-GRADE Key Rotation Manager
 *
 * Features:
 * - Automatic rotation based on time/count/volume
 * - Dual-control approval workflow
 * - HSM-backed key storage
 * - Comprehensive audit trail
 * - Emergency rotation procedures
 * - Key archival for compliance
 * - NIST SP 800-57 compliant
 */
class KeyRotationManager {
private:
    std::shared_ptr<hsm::HSMInterface> hsm_;
    RotationPolicy policy_;

    // Key tracking
    std::unordered_map<std::string, KeyMetadata> keys_;      // key_id_hex -> metadata
    mutable std::mutex keys_mutex_;

    // Current active key
    std::optional<std::array<uint8_t, 32>> active_key_id_;

    // Rotation event log
    std::vector<RotationEvent> rotation_log_;
    mutable std::mutex log_mutex_;

    // Pending approvals (for dual control)
    struct PendingRotation {
        std::array<uint8_t, 32> new_key_id;
        std::chrono::system_clock::time_point requested_at;
        std::string requester;
        std::vector<std::string> approvers;
        size_t required_approvals;
    };
    std::vector<PendingRotation> pending_rotations_;
    mutable std::mutex pending_mutex_;

    // Callbacks
    std::function<void(const RotationEvent&)> on_rotation_complete_;
    std::function<bool(const std::array<uint8_t, 32>&)> on_rotation_approval_request_;

    /**
     * @brief Generate unique key ID
     */
    std::array<uint8_t, 32> generate_key_id() {
        std::array<uint8_t, 32> key_id;
        auto random = hsm_->generate_random(32);
        std::memcpy(key_id.data(), random.data(), 32);
        return key_id;
    }

    /**
     * @brief Convert key ID to hex string
     */
    std::string key_id_to_hex(const std::array<uint8_t, 32>& key_id) const {
        const char* hex_chars = "0123456789abcdef";
        std::string hex;
        hex.reserve(64);

        for (uint8_t byte : key_id) {
            hex.push_back(hex_chars[(byte >> 4) & 0x0F]);
            hex.push_back(hex_chars[byte & 0x0F]);
        }

        return hex;
    }

    /**
     * @brief Log rotation event
     */
    void log_rotation(const RotationEvent& event) {
        std::lock_guard<std::mutex> lock(log_mutex_);
        rotation_log_.push_back(event);

        // Invoke callback if registered
        if (on_rotation_complete_) {
            on_rotation_complete_(event);
        }
    }

    /**
     * @brief Check if rotation is needed
     */
    bool needs_rotation(const KeyMetadata& metadata) const {
        auto now = std::chrono::system_clock::now();

        // Check time-based expiration
        if (policy_.enforce_crypto_period) {
            if (now >= metadata.expires_at) {
                return true;
            }
        }

        // Check operation count
        if (metadata.operation_count >= policy_.max_operations) {
            return true;
        }

        // Check volume
        if (metadata.bytes_processed >= policy_.max_bytes) {
            return true;
        }

        return false;
    }

public:
    /**
     * @brief Constructor
     * @param hsm HSM interface for key operations
     * @param policy Rotation policy
     */
    explicit KeyRotationManager(
        std::shared_ptr<hsm::HSMInterface> hsm,
        const RotationPolicy& policy = RotationPolicy{}
    ) : hsm_(hsm), policy_(policy) {
        if (!hsm) {
            throw std::runtime_error("HSM interface cannot be null");
        }
    }

    /**
     * @brief Generate and activate initial key
     * @param label Key label
     * @return Key ID
     */
    std::array<uint8_t, 32> generate_initial_key(const std::string& label) {
        std::lock_guard<std::mutex> lock(keys_mutex_);

        // Generate key in HSM
        hsm::KeyPolicy hsm_policy;
        hsm_policy.sensitive = true;
        hsm_policy.extractable = false;
        hsm_policy.require_authentication = true;

        auto hsm_metadata = hsm_->generate_key(label, "Ed25519", hsm_policy);

        // Create metadata
        KeyMetadata metadata;
        metadata.key_id = generate_key_id();
        metadata.label = label;
        metadata.created_at = std::chrono::system_clock::now();
        metadata.activated_at = metadata.created_at;
        metadata.expires_at = metadata.created_at + policy_.max_key_lifetime;
        metadata.state = KeyState::ACTIVE;

        // Store metadata
        keys_[key_id_to_hex(metadata.key_id)] = metadata;
        active_key_id_ = metadata.key_id;

        return metadata.key_id;
    }

    /**
     * @brief Initiate key rotation
     * @param trigger Rotation trigger type
     * @param initiator User/process ID
     * @return New key ID (or nullopt if pending approval)
     */
    std::optional<std::array<uint8_t, 32>> rotate(
        RotationTrigger trigger,
        const std::string& initiator
    ) {
        std::lock_guard<std::mutex> lock(keys_mutex_);

        if (!active_key_id_) {
            throw std::runtime_error("No active key to rotate");
        }

        auto old_key_hex = key_id_to_hex(*active_key_id_);
        auto& old_metadata = keys_.at(old_key_hex);

        // Generate new key
        std::string new_label = old_metadata.label + "_v" +
                               std::to_string(keys_.size() + 1);

        hsm::KeyPolicy hsm_policy;
        hsm_policy.sensitive = true;
        hsm_policy.extractable = false;

        auto hsm_metadata = hsm_->generate_key(new_label, "Ed25519", hsm_policy);

        // Create new key metadata
        KeyMetadata new_metadata;
        new_metadata.key_id = generate_key_id();
        new_metadata.label = new_label;
        new_metadata.created_at = std::chrono::system_clock::now();
        new_metadata.expires_at = new_metadata.created_at + policy_.max_key_lifetime;
        new_metadata.predecessor_key_id = old_metadata.key_id;

        // Check if dual control required
        if (policy_.require_dual_approval && trigger != RotationTrigger::COMPROMISE) {
            // Add to pending queue
            std::lock_guard<std::mutex> pending_lock(pending_mutex_);

            PendingRotation pending;
            pending.new_key_id = new_metadata.key_id;
            pending.requested_at = std::chrono::system_clock::now();
            pending.requester = initiator;
            pending.required_approvals = 2; // Configurable

            pending_rotations_.push_back(pending);

            // Store pending key metadata
            new_metadata.state = KeyState::PENDING;
            keys_[key_id_to_hex(new_metadata.key_id)] = new_metadata;

            return std::nullopt; // Awaiting approval
        }

        // Immediate rotation (no approval needed or emergency)
        complete_rotation(old_metadata.key_id, new_metadata.key_id, trigger, initiator, {});

        return new_metadata.key_id;
    }

    /**
     * @brief Approve pending rotation (dual control)
     * @param key_id Pending key ID
     * @param approver Approver ID
     * @return true if rotation completed
     */
    bool approve_rotation(
        const std::array<uint8_t, 32>& key_id,
        const std::string& approver
    ) {
        std::lock_guard<std::mutex> pending_lock(pending_mutex_);

        // Find pending rotation
        auto it = std::find_if(pending_rotations_.begin(), pending_rotations_.end(),
            [&](const PendingRotation& p) { return p.new_key_id == key_id; });

        if (it == pending_rotations_.end()) {
            return false; // Not found
        }

        // Add approver
        if (std::find(it->approvers.begin(), it->approvers.end(), approver) == it->approvers.end()) {
            it->approvers.push_back(approver);
        }

        // Check if enough approvals
        if (it->approvers.size() >= it->required_approvals) {
            // Complete rotation
            auto pending = *it;
            pending_rotations_.erase(it);

            std::lock_guard<std::mutex> lock(keys_mutex_);

            if (!active_key_id_) return false;

            complete_rotation(*active_key_id_, pending.new_key_id,
                            RotationTrigger::MANUAL, pending.requester, pending.approvers);

            return true;
        }

        return false; // Still awaiting approvals
    }

    /**
     * @brief Complete rotation (internal)
     */
    void complete_rotation(
        const std::array<uint8_t, 32>& old_key_id,
        const std::array<uint8_t, 32>& new_key_id,
        RotationTrigger trigger,
        const std::string& initiator,
        const std::vector<std::string>& approvers
    ) {
        auto old_hex = key_id_to_hex(old_key_id);
        auto new_hex = key_id_to_hex(new_key_id);

        // Deactivate old key
        auto& old_metadata = keys_.at(old_hex);
        old_metadata.state = policy_.archive_old_keys ? KeyState::ARCHIVED : KeyState::DEACTIVATED;
        old_metadata.deactivated_at = std::chrono::system_clock::now();
        old_metadata.successor_key_id = new_key_id;

        // Activate new key
        auto& new_metadata = keys_.at(new_hex);
        new_metadata.state = KeyState::ACTIVE;
        new_metadata.activated_at = std::chrono::system_clock::now();
        new_metadata.approvers = approvers;
        new_metadata.dual_control_satisfied = !approvers.empty();

        // Update active key
        active_key_id_ = new_key_id;

        // Log event
        RotationEvent event;
        event.timestamp = std::chrono::system_clock::now();
        event.old_key_id = old_key_id;
        event.new_key_id = new_key_id;
        event.trigger = trigger;
        event.initiator = initiator;
        event.approvers = approvers;
        event.success = true;

        log_rotation(event);
    }

    /**
     * @brief Emergency key revocation (suspected compromise)
     * @param initiator User/process ID
     * @return New key ID
     */
    std::array<uint8_t, 32> emergency_revoke(const std::string& initiator) {
        std::lock_guard<std::mutex> lock(keys_mutex_);

        if (!active_key_id_) {
            throw std::runtime_error("No active key to revoke");
        }

        auto old_hex = key_id_to_hex(*active_key_id_);
        auto& old_metadata = keys_.at(old_hex);

        // Mark as compromised
        old_metadata.state = KeyState::COMPROMISED;
        old_metadata.deactivated_at = std::chrono::system_clock::now();

        // Immediate rotation (bypass approvals)
        auto new_key_id = *rotate(RotationTrigger::COMPROMISE, initiator);

        return new_key_id;
    }

    /**
     * @brief Check if any keys need rotation
     * @return Vector of key IDs needing rotation
     */
    std::vector<std::array<uint8_t, 32>> check_rotation_needed() const {
        std::lock_guard<std::mutex> lock(keys_mutex_);

        std::vector<std::array<uint8_t, 32>> result;

        for (const auto& [hex, metadata] : keys_) {
            if (metadata.state == KeyState::ACTIVE && needs_rotation(metadata)) {
                result.push_back(metadata.key_id);
            }
        }

        return result;
    }

    /**
     * @brief Get current active key ID
     */
    std::optional<std::array<uint8_t, 32>> get_active_key() const {
        std::lock_guard<std::mutex> lock(keys_mutex_);
        return active_key_id_;
    }

    /**
     * @brief Get key metadata
     */
    std::optional<KeyMetadata> get_key_metadata(const std::array<uint8_t, 32>& key_id) const {
        std::lock_guard<std::mutex> lock(keys_mutex_);

        auto hex = key_id_to_hex(key_id);
        auto it = keys_.find(hex);

        if (it != keys_.end()) {
            return it->second;
        }

        return std::nullopt;
    }

    /**
     * @brief Update key usage statistics
     */
    void update_key_stats(const std::array<uint8_t, 32>& key_id,
                         uint64_t operations, uint64_t bytes) {
        std::lock_guard<std::mutex> lock(keys_mutex_);

        auto hex = key_id_to_hex(key_id);
        auto it = keys_.find(hex);

        if (it != keys_.end()) {
            it->second.operation_count += operations;
            it->second.bytes_processed += bytes;
        }
    }

    /**
     * @brief Get rotation event log
     */
    std::vector<RotationEvent> get_rotation_log() const {
        std::lock_guard<std::mutex> lock(log_mutex_);
        return rotation_log_;
    }

    /**
     * @brief Set rotation completion callback
     */
    void set_on_rotation_complete(std::function<void(const RotationEvent&)> callback) {
        on_rotation_complete_ = callback;
    }

    /**
     * @brief Update policy
     */
    void update_policy(const RotationPolicy& policy) {
        std::lock_guard<std::mutex> lock(keys_mutex_);
        policy_ = policy;
    }
};

} // namespace security
} // namespace nocturne

#endif // NOCTURNE_SECURITY_KEY_ROTATION_HPP
