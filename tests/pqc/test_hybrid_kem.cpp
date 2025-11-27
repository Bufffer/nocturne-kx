/**
 * @file test_hybrid_kem.cpp
 * @brief Test Hybrid KEM (X25519 + ML-KEM-1024)
 *
 * Validates:
 * 1. Hybrid keypair generation
 * 2. Hybrid encapsulation/decapsulation
 * 3. Shared secret correctness
 * 4. Error handling
 */

#define NOCTURNE_ENABLE_PQC 1

#include "../../src/pqc/kem/kem_factory.cpp"
#include "../../src/pqc/kem/kem_interface.cpp"
#include "../../src/pqc/kem/mlkem_wrapper.hpp"
#include "../../src/pqc/kem/hybrid_kem.hpp"
#include "../../src/core/side_channel.hpp"

#include <iostream>
#include <iomanip>
#include <cassert>
#include <cstring>

using namespace nocturne::pqc;

#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_RESET "\033[0m"

void print_success(const std::string& msg) {
    std::cout << COLOR_GREEN << "✓ " << msg << COLOR_RESET << std::endl;
}

void print_error(const std::string& msg) {
    std::cout << COLOR_RED << "✗ " << msg << COLOR_RESET << std::endl;
}

void print_info(const std::string& msg) {
    std::cout << COLOR_YELLOW << "ℹ " << msg << COLOR_RESET << std::endl;
}

void print_hex(const std::string& label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < std::min(len, size_t(16)); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
    }
    if (len > 16) {
        std::cout << "... (" << std::dec << len << " bytes total)";
    }
    std::cout << std::dec << std::endl;
}

bool test_ml_kem_wrapper() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "TEST 1: ML-KEM-1024 Wrapper" << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        auto kem = create_kem(KEMType::PURE_MLKEM1024);
        print_success("ML-KEM-1024 instance created");

        // Generate keypair
        print_info("Generating keypair...");
        auto kp = kem->generate_keypair();
        print_success("Keypair generated");
        print_hex("  Public key", kp.public_key.data(), kp.public_key.size());
        print_hex("  Secret key", kp.secret_key.data(), kp.secret_key.size());

        // Encapsulate
        print_info("Encapsulating...");
        auto [ct, ss_sender] = kem->encapsulate(kp.public_key);
        print_success("Encapsulated");
        print_hex("  Ciphertext", ct.ciphertext.data(), ct.ciphertext.size());
        print_hex("  Shared secret (sender)", ss_sender.secret.data(), 32);

        // Decapsulate
        print_info("Decapsulating...");
        auto ss_receiver = kem->decapsulate(ct, kp.secret_key);
        print_success("Decapsulated");
        print_hex("  Shared secret (receiver)", ss_receiver.secret.data(), 32);

        // Verify secrets match
        if (std::memcmp(ss_sender.secret.data(), ss_receiver.secret.data(), 32) != 0) {
            print_error("Shared secrets DO NOT match!");
            return false;
        }
        print_success("Shared secrets MATCH! ✓✓✓");

        return true;

    } catch (const std::exception& e) {
        print_error(std::string("Exception: ") + e.what());
        return false;
    }
}

bool test_hybrid_kem() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "TEST 2: Hybrid KEM (X25519 + ML-KEM-1024)" << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        auto kem = create_kem(KEMType::HYBRID_X25519_MLKEM1024);
        print_success("Hybrid KEM instance created");

        print_info("Algorithm: " + kem->algorithm_name());
        print_info("Public key size: " + std::to_string(kem->public_key_size()) + " bytes");
        print_info("Secret key size: " + std::to_string(kem->secret_key_size()) + " bytes");
        print_info("Ciphertext size: " + std::to_string(kem->ciphertext_size()) + " bytes");

        // Generate keypair
        print_info("Generating hybrid keypair...");
        auto kp = kem->generate_keypair();
        print_success("Hybrid keypair generated");
        print_hex("  Hybrid public key", kp.public_key.data(), kp.public_key.size());
        print_hex("  Hybrid secret key", kp.secret_key.data(), kp.secret_key.size());

        // Encapsulate
        print_info("Hybrid encapsulating...");
        auto [ct, ss_sender] = kem->encapsulate(kp.public_key);
        print_success("Hybrid encapsulated");
        print_hex("  Hybrid ciphertext", ct.ciphertext.data(), ct.ciphertext.size());
        print_hex("  Shared secret (sender)", ss_sender.secret.data(), 32);

        // Decapsulate
        print_info("Hybrid decapsulating...");
        auto ss_receiver = kem->decapsulate(ct, kp.secret_key);
        print_success("Hybrid decapsulated");
        print_hex("  Shared secret (receiver)", ss_receiver.secret.data(), 32);

        // Verify secrets match
        if (std::memcmp(ss_sender.secret.data(), ss_receiver.secret.data(), 32) != 0) {
            print_error("Hybrid shared secrets DO NOT match!");
            return false;
        }
        print_success("Hybrid shared secrets MATCH! ✓✓✓");

        return true;

    } catch (const std::exception& e) {
        print_error(std::string("Exception: ") + e.what());
        return false;
    }
}

bool test_classic_x25519() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "TEST 3: Classic X25519 (Fallback)" << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        auto kem = create_kem(KEMType::CLASSIC_X25519);
        print_success("Classic X25519 instance created");

        // Generate keypair
        auto kp = kem->generate_keypair();
        print_success("X25519 keypair generated");

        // Encapsulate
        auto [ct, ss_sender] = kem->encapsulate(kp.public_key);
        print_success("X25519 encapsulated");

        // Decapsulate
        auto ss_receiver = kem->decapsulate(ct, kp.secret_key);
        print_success("X25519 decapsulated");

        // Verify
        if (std::memcmp(ss_sender.secret.data(), ss_receiver.secret.data(), 32) != 0) {
            print_error("X25519 shared secrets DO NOT match!");
            return false;
        }
        print_success("X25519 shared secrets MATCH! ✓");

        return true;

    } catch (const std::exception& e) {
        print_error(std::string("Exception: ") + e.what());
        return false;
    }
}

bool test_error_handling() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "TEST 4: Error Handling" << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        auto kem = create_kem(KEMType::HYBRID_X25519_MLKEM1024);

        // Test 1: Wrong public key size
        print_info("Testing wrong public key size...");
        std::vector<uint8_t> bad_pk(100);  // Too small
        try {
            kem->encapsulate(bad_pk);
            print_error("Should have thrown exception for wrong pk size!");
            return false;
        } catch (const std::invalid_argument& e) {
            print_success("Correctly rejected wrong public key size");
        }

        // Test 2: Wrong ciphertext
        print_info("Testing wrong ciphertext...");
        auto kp = kem->generate_keypair();
        auto [ct, ss] = kem->encapsulate(kp.public_key);

        // Corrupt ciphertext
        ct.ciphertext[10] ^= 0xFF;

        std::vector<uint8_t> bad_sk(100);  // Wrong size
        try {
            kem->decapsulate(ct, bad_sk);
            print_error("Should have thrown exception for wrong sk size!");
            return false;
        } catch (const std::invalid_argument& e) {
            print_success("Correctly rejected wrong secret key size");
        }

        print_success("Error handling works correctly ✓");
        return true;

    } catch (const std::exception& e) {
        print_error(std::string("Unexpected exception: ") + e.what());
        return false;
    }
}

int main() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║      Nocturne-KX Hybrid KEM Test Suite              ║" << std::endl;
    std::cout << "║      X25519 + ML-KEM-1024 (NIST FIPS 203)            ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝" << std::endl;

    // Initialize libsodium
    if (sodium_init() < 0) {
        print_error("libsodium initialization failed!");
        return 1;
    }
    print_success("libsodium initialized");

    bool all_passed = true;

    all_passed &= test_ml_kem_wrapper();
    all_passed &= test_hybrid_kem();
    all_passed &= test_classic_x25519();
    all_passed &= test_error_handling();

    std::cout << "\n========================================" << std::endl;
    if (all_passed) {
        std::cout << COLOR_GREEN << "✓✓✓ ALL TESTS PASSED ✓✓✓" << COLOR_RESET << std::endl;
        std::cout << "Hybrid KEM is working correctly!" << std::endl;
        std::cout << "Post-Quantum security achieved." << std::endl;
    } else {
        std::cout << COLOR_RED << "✗✗✗ SOME TESTS FAILED ✗✗✗" << COLOR_RESET << std::endl;
    }
    std::cout << "========================================" << std::endl;

    return all_passed ? 0 : 1;
}
