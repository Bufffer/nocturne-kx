/**
 * @file test_liboqs_basic.cpp
 * @brief Basic test to verify liboqs is working correctly
 *
 * This test verifies:
 * 1. liboqs library loads and initializes
 * 2. ML-KEM-1024 (Kyber) is available
 * 3. ML-DSA-87 (Dilithium) is available
 * 4. Basic KEM operations work (keygen, encaps, decaps)
 * 5. Basic signature operations work (keygen, sign, verify)
 */

#include <oqs/oqs.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <string>
#include <vector>

// ANSI color codes for output
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

void print_hex(const std::string& label, const uint8_t* data, size_t len, size_t max_display = 16) {
    std::cout << label << ": ";
    for (size_t i = 0; i < std::min(len, max_display); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
    }
    if (len > max_display) {
        std::cout << "... (" << std::dec << len << " bytes total)";
    }
    std::cout << std::dec << std::endl;
}

bool test_kem_availability() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "TEST 1: KEM Algorithm Availability" << std::endl;
    std::cout << "========================================" << std::endl;

    // Check if ML-KEM-1024 is available
    if (!OQS_KEM_alg_is_enabled(OQS_KEM_alg_ml_kem_1024)) {
        print_error("ML-KEM-1024 not available");
        return false;
    }
    print_success("ML-KEM-1024 is available");

    // Try to create KEM instance
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) {
        print_error("Failed to create ML-KEM-1024 instance");
        return false;
    }
    print_success("ML-KEM-1024 instance created");

    // Print algorithm details
    print_info("Algorithm name: " + std::string(kem->method_name));
    print_info("Public key size: " + std::to_string(kem->length_public_key) + " bytes");
    print_info("Secret key size: " + std::to_string(kem->length_secret_key) + " bytes");
    print_info("Ciphertext size: " + std::to_string(kem->length_ciphertext) + " bytes");
    print_info("Shared secret size: " + std::to_string(kem->length_shared_secret) + " bytes");

    // Verify expected sizes
    if (kem->length_public_key != 1568 ||
        kem->length_secret_key != 3168 ||
        kem->length_ciphertext != 1568 ||
        kem->length_shared_secret != 32) {
        print_error("ML-KEM-1024 size mismatch with FIPS 203 specification");
        OQS_KEM_free(kem);
        return false;
    }
    print_success("ML-KEM-1024 sizes match FIPS 203 specification");

    OQS_KEM_free(kem);
    return true;
}

bool test_kem_operations() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "TEST 2: KEM Operations" << std::endl;
    std::cout << "========================================" << std::endl;

    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) {
        print_error("Failed to create KEM instance");
        return false;
    }

    // Allocate buffers
    std::vector<uint8_t> public_key(kem->length_public_key);
    std::vector<uint8_t> secret_key(kem->length_secret_key);
    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> shared_secret_sender(kem->length_shared_secret);
    std::vector<uint8_t> shared_secret_receiver(kem->length_shared_secret);

    // 1. Key generation
    print_info("Generating keypair...");
    OQS_STATUS status = OQS_KEM_keypair(kem, public_key.data(), secret_key.data());
    if (status != OQS_SUCCESS) {
        print_error("Keypair generation failed");
        OQS_KEM_free(kem);
        return false;
    }
    print_success("Keypair generated");
    print_hex("  Public key", public_key.data(), public_key.size(), 16);
    print_hex("  Secret key", secret_key.data(), secret_key.size(), 16);

    // 2. Encapsulation (sender side)
    print_info("Encapsulating shared secret...");
    status = OQS_KEM_encaps(kem, ciphertext.data(), shared_secret_sender.data(),
                           public_key.data());
    if (status != OQS_SUCCESS) {
        print_error("Encapsulation failed");
        OQS_KEM_free(kem);
        return false;
    }
    print_success("Shared secret encapsulated");
    print_hex("  Ciphertext", ciphertext.data(), ciphertext.size(), 16);
    print_hex("  Shared secret (sender)", shared_secret_sender.data(),
              shared_secret_sender.size(), 32);

    // 3. Decapsulation (receiver side)
    print_info("Decapsulating shared secret...");
    status = OQS_KEM_decaps(kem, shared_secret_receiver.data(), ciphertext.data(),
                           secret_key.data());
    if (status != OQS_SUCCESS) {
        print_error("Decapsulation failed");
        OQS_KEM_free(kem);
        return false;
    }
    print_success("Shared secret decapsulated");
    print_hex("  Shared secret (receiver)", shared_secret_receiver.data(),
              shared_secret_receiver.size(), 32);

    // 4. Verify shared secrets match
    if (std::memcmp(shared_secret_sender.data(), shared_secret_receiver.data(),
                    kem->length_shared_secret) != 0) {
        print_error("Shared secrets do not match!");
        OQS_KEM_free(kem);
        return false;
    }
    print_success("Shared secrets match! ✓✓✓");

    OQS_KEM_free(kem);
    return true;
}

bool test_signature_availability() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "TEST 3: Signature Algorithm Availability" << std::endl;
    std::cout << "========================================" << std::endl;

    // Check if ML-DSA-87 is available
    if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_ml_dsa_87)) {
        print_error("ML-DSA-87 not available");
        return false;
    }
    print_success("ML-DSA-87 is available");

    // Try to create signature instance
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (!sig) {
        print_error("Failed to create ML-DSA-87 instance");
        return false;
    }
    print_success("ML-DSA-87 instance created");

    // Print algorithm details
    print_info("Algorithm name: " + std::string(sig->method_name));
    print_info("Public key size: " + std::to_string(sig->length_public_key) + " bytes");
    print_info("Secret key size: " + std::to_string(sig->length_secret_key) + " bytes");
    print_info("Signature size: " + std::to_string(sig->length_signature) + " bytes");

    OQS_SIG_free(sig);
    return true;
}

bool test_signature_operations() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "TEST 4: Signature Operations" << std::endl;
    std::cout << "========================================" << std::endl;

    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (!sig) {
        print_error("Failed to create signature instance");
        return false;
    }

    // Allocate buffers
    std::vector<uint8_t> public_key(sig->length_public_key);
    std::vector<uint8_t> secret_key(sig->length_secret_key);
    std::vector<uint8_t> signature(sig->length_signature);
    size_t signature_len;

    const char* message = "Hello, Post-Quantum World! This is ML-DSA-87 from NIST FIPS 204.";

    // 1. Key generation
    print_info("Generating signature keypair...");
    OQS_STATUS status = OQS_SIG_keypair(sig, public_key.data(), secret_key.data());
    if (status != OQS_SUCCESS) {
        print_error("Signature keypair generation failed");
        OQS_SIG_free(sig);
        return false;
    }
    print_success("Signature keypair generated");
    print_hex("  Public key", public_key.data(), public_key.size(), 16);

    // 2. Sign message
    print_info("Signing message: \"" + std::string(message) + "\"");
    status = OQS_SIG_sign(sig, signature.data(), &signature_len,
                         reinterpret_cast<const uint8_t*>(message),
                         std::strlen(message), secret_key.data());
    if (status != OQS_SUCCESS) {
        print_error("Signing failed");
        OQS_SIG_free(sig);
        return false;
    }
    print_success("Message signed");
    print_hex("  Signature", signature.data(), signature_len, 16);
    print_info("Signature length: " + std::to_string(signature_len) + " bytes");

    // 3. Verify signature (correct)
    print_info("Verifying signature...");
    status = OQS_SIG_verify(sig, reinterpret_cast<const uint8_t*>(message),
                           std::strlen(message), signature.data(), signature_len,
                           public_key.data());
    if (status != OQS_SUCCESS) {
        print_error("Signature verification failed");
        OQS_SIG_free(sig);
        return false;
    }
    print_success("Signature verified! ✓✓✓");

    // 4. Verify with wrong message (should fail)
    const char* wrong_message = "Wrong message!";
    print_info("Testing with wrong message (should fail)...");
    status = OQS_SIG_verify(sig, reinterpret_cast<const uint8_t*>(wrong_message),
                           std::strlen(wrong_message), signature.data(), signature_len,
                           public_key.data());
    if (status == OQS_SUCCESS) {
        print_error("Signature verification should have failed but succeeded!");
        OQS_SIG_free(sig);
        return false;
    }
    print_success("Wrong message correctly rejected ✓");

    OQS_SIG_free(sig);
    return true;
}

int main() {
    std::cout << "\n╔═══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║       liboqs Post-Quantum Cryptography Test         ║" << std::endl;
    std::cout << "║              NIST FIPS 203/204/205                   ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════╝" << std::endl;

    bool all_passed = true;

    // Test KEM
    all_passed &= test_kem_availability();
    all_passed &= test_kem_operations();

    // Test Signatures
    all_passed &= test_signature_availability();
    all_passed &= test_signature_operations();

    // Final result
    std::cout << "\n========================================" << std::endl;
    if (all_passed) {
        std::cout << COLOR_GREEN << "✓✓✓ ALL TESTS PASSED ✓✓✓" << COLOR_RESET << std::endl;
        std::cout << "liboqs is working correctly!" << std::endl;
        std::cout << "Ready for Nocturne-KX PQC integration." << std::endl;
    } else {
        std::cout << COLOR_RED << "✗✗✗ SOME TESTS FAILED ✗✗✗" << COLOR_RESET << std::endl;
        std::cout << "Please check liboqs installation." << std::endl;
    }
    std::cout << "========================================" << std::endl;

    return all_passed ? 0 : 1;
}
