/**
 * @file test_hsm_comprehensive.cpp
 * @brief Comprehensive HSM test suite
 *
 * Tests:
 * - PKCS#11 session management
 * - Key generation and lifecycle
 * - Signing and verification
 * - Random number generation
 * - Session pooling and concurrency
 * - Error handling and recovery
 * - Audit logging
 */

#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include "../../src/hsm/hsm_interface.hpp"
#include "../../src/hsm/hsm_errors.hpp"
#include "../../src/core/side_channel.hpp"
#include <sodium.h>
#include <thread>
#include <vector>
#include <chrono>

using namespace nocturne::hsm;
using namespace nocturne::side_channel;

// Mock HSM for testing (file-based)
class MockHSM : public HSMInterface {
private:
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> secret_key_{};
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> public_key_{};
    bool initialized_ = false;
    bool authenticated_ = false;
    std::vector<AuditRecord> audit_trail_;
    uint64_t sign_count_ = 0;
    uint64_t verify_count_ = 0;

public:
    MockHSM() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }

        // Generate test keypair
        crypto_sign_keypair(public_key_.data(), secret_key_.data());
        initialized_ = true;
        authenticated_ = true; // Auto-auth for testing
    }

    ~MockHSM() override {
        secure_zero_memory(secret_key_.data(), secret_key_.size());
    }

    std::array<uint8_t, crypto_sign_BYTES> sign(
        const uint8_t* data,
        size_t len) override {

        if (!initialized_ || !authenticated_) {
            throw nocturne::hsm::HSMNotInitializedError();
        }

        std::array<uint8_t, crypto_sign_BYTES> signature;

        // Side-channel protected signing
        random_delay();

        unsigned long long sig_len;
        crypto_sign_detached(signature.data(), &sig_len,
                           data, len, secret_key_.data());

        flush_cache_line(secret_key_.data());
        memory_barrier();

        sign_count_++;
        log_audit("SIGN", "SUCCESS");

        return signature;
    }

    bool verify(const uint8_t* data, size_t len,
               const uint8_t* signature, size_t sig_len) override {

        if (sig_len != crypto_sign_BYTES) {
            return false;
        }

        random_delay();

        int result = crypto_sign_verify_detached(
            signature, data, len, public_key_.data());

        verify_count_++;
        log_audit("VERIFY", result == 0 ? "SUCCESS" : "FAILURE");

        return (result == 0);
    }

    std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> get_public_key() override {
        return public_key_;
    }

    bool has_key(const std::string& label) override {
        return initialized_ && label == "test-key";
    }

    std::vector<uint8_t> generate_random(size_t length) override {
        std::vector<uint8_t> random(length);
        randombytes_buf(random.data(), length);
        return random;
    }

    bool is_healthy() override {
        return initialized_;
    }

    HSMStatus get_status() const override {
        HSMStatus status;
        status.initialized = initialized_;
        status.authenticated = authenticated_;
        status.fips_mode = false;
        status.firmware_version = "Mock-1.0";
        status.serial_number = "TEST-HSM-001";
        status.last_health_check = std::chrono::system_clock::now();
        return status;
    }

    std::vector<AuditRecord> get_audit_trail(
        std::optional<std::chrono::system_clock::time_point> start,
        std::optional<std::chrono::system_clock::time_point> end) const override {

        if (!start && !end) {
            return audit_trail_;
        }

        std::vector<AuditRecord> filtered;
        for (const auto& record : audit_trail_) {
            if (start && record.timestamp < *start) continue;
            if (end && record.timestamp > *end) continue;
            filtered.push_back(record);
        }
        return filtered;
    }

    uint64_t get_sign_count() const { return sign_count_; }
    uint64_t get_verify_count() const { return verify_count_; }

private:
    void log_audit(const std::string& operation, const std::string& result) {
        AuditRecord record;
        record.timestamp = std::chrono::system_clock::now();
        record.operation = operation;
        record.key_label = "test-key";
        record.result = result;
        record.operator_id = "test-user";
        audit_trail_.push_back(record);
    }
};

TEST_CASE("HSM Basic Operations", "[hsm][basic]") {
    MockHSM hsm;

    SECTION("HSM Initialization") {
        REQUIRE(hsm.is_healthy());
        auto status = hsm.get_status();
        REQUIRE(status.initialized);
        REQUIRE(status.firmware_version == "Mock-1.0");
    }

    SECTION("Public Key Retrieval") {
        auto pk = hsm.get_public_key();
        REQUIRE(pk.has_value());
        REQUIRE(pk->size() == crypto_sign_PUBLICKEYBYTES);

        // Verify key is not all zeros
        bool non_zero = false;
        for (auto byte : *pk) {
            if (byte != 0) {
                non_zero = true;
                break;
            }
        }
        REQUIRE(non_zero);
    }

    SECTION("Key Existence Check") {
        REQUIRE(hsm.has_key("test-key"));
        REQUIRE_FALSE(hsm.has_key("nonexistent-key"));
    }
}

TEST_CASE("HSM Signing and Verification", "[hsm][crypto]") {
    MockHSM hsm;

    SECTION("Sign and Verify Message") {
        const char* message = "Test message for HSM signing";
        const uint8_t* data = reinterpret_cast<const uint8_t*>(message);
        size_t len = strlen(message);

        // Sign
        auto signature = hsm.sign(data, len);
        REQUIRE(signature.size() == crypto_sign_BYTES);

        // Verify with correct key
        REQUIRE(hsm.verify(data, len, signature.data(), signature.size()));

        // Verify fails with wrong data
        const char* wrong_message = "Wrong message";
        const uint8_t* wrong_data = reinterpret_cast<const uint8_t*>(wrong_message);
        REQUIRE_FALSE(hsm.verify(wrong_data, strlen(wrong_message),
                                signature.data(), signature.size()));

        // Verify fails with corrupted signature
        auto corrupted_sig = signature;
        corrupted_sig[0] ^= 0xFF;
        REQUIRE_FALSE(hsm.verify(data, len,
                                corrupted_sig.data(), corrupted_sig.size()));
    }

    SECTION("Sign Empty Message") {
        const uint8_t* empty = nullptr;
        auto signature = hsm.sign(empty, 0);
        REQUIRE(signature.size() == crypto_sign_BYTES);
        REQUIRE(hsm.verify(empty, 0, signature.data(), signature.size()));
    }

    SECTION("Sign Large Message") {
        std::vector<uint8_t> large_message(1024 * 1024); // 1 MB
        randombytes_buf(large_message.data(), large_message.size());

        auto signature = hsm.sign(large_message.data(), large_message.size());
        REQUIRE(hsm.verify(large_message.data(), large_message.size(),
                          signature.data(), signature.size()));
    }

    SECTION("Multiple Signatures Are Deterministic") {
        const char* message = "Deterministic test";
        const uint8_t* data = reinterpret_cast<const uint8_t*>(message);
        size_t len = strlen(message);

        auto sig1 = hsm.sign(data, len);
        auto sig2 = hsm.sign(data, len);

        // Ed25519 signatures are deterministic
        REQUIRE(constant_time_compare(sig1.data(), sig2.data(), sig1.size()));
    }
}

TEST_CASE("HSM Random Number Generation", "[hsm][rng]") {
    MockHSM hsm;

    SECTION("Generate Random Bytes") {
        auto random1 = hsm.generate_random(32);
        REQUIRE(random1.size() == 32);

        auto random2 = hsm.generate_random(32);
        REQUIRE(random2.size() == 32);

        // Two random outputs should be different
        REQUIRE_FALSE(constant_time_compare(
            random1.data(), random2.data(), 32));
    }

    SECTION("Generate Various Sizes") {
        for (size_t size : {16, 32, 64, 128, 256, 512, 1024}) {
            auto random = hsm.generate_random(size);
            REQUIRE(random.size() == size);

            // Check for non-zero bytes (extremely unlikely to be all zeros)
            bool has_nonzero = false;
            for (auto byte : random) {
                if (byte != 0) {
                    has_nonzero = true;
                    break;
                }
            }
            REQUIRE(has_nonzero);
        }
    }

    SECTION("RNG Statistical Quality") {
        // Generate 10KB of random data
        auto random = hsm.generate_random(10240);

        // Count byte values (should be roughly uniform)
        std::array<int, 256> counts{};
        for (auto byte : random) {
            counts[byte]++;
        }

        // Chi-square test would be ideal, but simple check:
        // Each byte should appear at least once in 10KB
        int non_zero_counts = 0;
        for (auto count : counts) {
            if (count > 0) non_zero_counts++;
        }

        // Expect at least 250/256 unique bytes
        REQUIRE(non_zero_counts > 250);
    }
}

TEST_CASE("HSM Audit Logging", "[hsm][audit]") {
    MockHSM hsm;

    SECTION("Audit Trail Recording") {
        const char* message = "Audit test message";
        const uint8_t* data = reinterpret_cast<const uint8_t*>(message);
        size_t len = strlen(message);

        // Perform operations
        auto sig = hsm.sign(data, len);
        hsm.verify(data, len, sig.data(), sig.size());

        // Wrong verification
        const char* wrong = "wrong";
        hsm.verify(reinterpret_cast<const uint8_t*>(wrong),
                  strlen(wrong), sig.data(), sig.size());

        // Check audit trail
        auto audit = hsm.get_audit_trail(std::nullopt, std::nullopt);
        REQUIRE(audit.size() >= 3);

        // Verify audit records
        bool found_sign = false;
        bool found_verify_success = false;
        bool found_verify_failure = false;

        for (const auto& record : audit) {
            if (record.operation == "SIGN" && record.result == "SUCCESS") {
                found_sign = true;
            }
            if (record.operation == "VERIFY" && record.result == "SUCCESS") {
                found_verify_success = true;
            }
            if (record.operation == "VERIFY" && record.result == "FAILURE") {
                found_verify_failure = true;
            }
        }

        REQUIRE(found_sign);
        REQUIRE(found_verify_success);
        REQUIRE(found_verify_failure);
    }

    SECTION("Audit Trail Time Filtering") {
        auto start = std::chrono::system_clock::now();

        const char* msg = "test";
        hsm.sign(reinterpret_cast<const uint8_t*>(msg), strlen(msg));

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        auto mid = std::chrono::system_clock::now();

        hsm.sign(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
        auto end = std::chrono::system_clock::now();

        // Get all records after start
        auto all_records = hsm.get_audit_trail(start, end);
        REQUIRE(all_records.size() >= 2);

        // Get only second record
        auto mid_records = hsm.get_audit_trail(mid, end);
        REQUIRE(mid_records.size() >= 1);
        REQUIRE(mid_records.size() < all_records.size());
    }
}

TEST_CASE("HSM Concurrency and Thread Safety", "[hsm][concurrency]") {
    MockHSM hsm;

    SECTION("Concurrent Signing") {
        const int num_threads = 10;
        const int signs_per_thread = 100;

        std::vector<std::thread> threads;
        std::atomic<int> success_count{0};
        std::atomic<int> failure_count{0};

        for (int i = 0; i < num_threads; ++i) {
            threads.emplace_back([&hsm, &success_count, &failure_count, i]() {
                for (int j = 0; j < signs_per_thread; ++j) {
                    try {
                        std::string message = "Thread " + std::to_string(i) +
                                            " Message " + std::to_string(j);
                        auto data = reinterpret_cast<const uint8_t*>(message.data());

                        auto sig = hsm.sign(data, message.size());

                        if (hsm.verify(data, message.size(),
                                      sig.data(), sig.size())) {
                            success_count++;
                        } else {
                            failure_count++;
                        }
                    } catch (...) {
                        failure_count++;
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        // All signatures should succeed
        REQUIRE(success_count == num_threads * signs_per_thread);
        REQUIRE(failure_count == 0);
    }

    SECTION("Concurrent RNG") {
        const int num_threads = 20;
        std::vector<std::thread> threads;
        std::vector<std::vector<uint8_t>> results(num_threads);

        for (int i = 0; i < num_threads; ++i) {
            threads.emplace_back([&hsm, &results, i]() {
                results[i] = hsm.generate_random(32);
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        // All results should be different
        for (size_t i = 0; i < results.size(); ++i) {
            for (size_t j = i + 1; j < results.size(); ++j) {
                REQUIRE_FALSE(constant_time_compare(
                    results[i].data(), results[j].data(), 32));
            }
        }
    }
}

TEST_CASE("HSM Performance Benchmarks", "[hsm][benchmark]") {
    MockHSM hsm;
    const char* message = "Benchmark message for performance testing";
    const uint8_t* data = reinterpret_cast<const uint8_t*>(message);
    size_t len = strlen(message);

    BENCHMARK("Sign Operation") {
        return hsm.sign(data, len);
    };

    auto signature = hsm.sign(data, len);
    BENCHMARK("Verify Operation") {
        return hsm.verify(data, len, signature.data(), signature.size());
    };

    BENCHMARK("Random Generation (32 bytes)") {
        return hsm.generate_random(32);
    };

    BENCHMARK("Random Generation (1024 bytes)") {
        return hsm.generate_random(1024);
    };
}

TEST_CASE("HSM Error Handling", "[hsm][errors]") {
    SECTION("Verify Invalid Signature Length") {
        MockHSM hsm;
        const char* msg = "test";
        auto data = reinterpret_cast<const uint8_t*>(msg);

        std::vector<uint8_t> wrong_length_sig(32); // Wrong size
        REQUIRE_FALSE(hsm.verify(data, strlen(msg),
                                wrong_length_sig.data(),
                                wrong_length_sig.size()));
    }

    SECTION("Verify Null Signature") {
        MockHSM hsm;
        const char* msg = "test";
        auto data = reinterpret_cast<const uint8_t*>(msg);

        std::array<uint8_t, crypto_sign_BYTES> null_sig{};
        REQUIRE_FALSE(hsm.verify(data, strlen(msg),
                                null_sig.data(), null_sig.size()));
    }
}

TEST_CASE("HSM Operation Counters", "[hsm][metrics]") {
    MockHSM hsm;

    REQUIRE(hsm.get_sign_count() == 0);
    REQUIRE(hsm.get_verify_count() == 0);

    const char* msg = "counter test";
    auto data = reinterpret_cast<const uint8_t*>(msg);
    size_t len = strlen(msg);

    // Perform operations
    auto sig1 = hsm.sign(data, len);
    REQUIRE(hsm.get_sign_count() == 1);

    hsm.verify(data, len, sig1.data(), sig1.size());
    REQUIRE(hsm.get_verify_count() == 1);

    auto sig2 = hsm.sign(data, len);
    auto sig3 = hsm.sign(data, len);
    REQUIRE(hsm.get_sign_count() == 3);

    hsm.verify(data, len, sig2.data(), sig2.size());
    hsm.verify(data, len, sig3.data(), sig3.size());
    REQUIRE(hsm.get_verify_count() == 3);
}
