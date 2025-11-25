#include <sodium.h>
#include <iostream>
#include <cstring>

int main() {
    std::cout << "Testing libsodium key generation..." << std::endl;
    
    // Initialize libsodium
    if (sodium_init() < 0) {
        std::cerr << "ERROR: sodium_init failed" << std::endl;
        return 1;
    }
    std::cout << "✓ sodium_init successful" << std::endl;
    
    // Test X25519 key generation
    unsigned char pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char sk[crypto_kx_SECRETKEYBYTES];
    
    std::cout << "Calling crypto_kx_keypair..." << std::endl;
    int result = crypto_kx_keypair(pk, sk);
    std::cout << "crypto_kx_keypair result: " << result << std::endl;
    
    if (result != 0) {
        std::cerr << "ERROR: crypto_kx_keypair failed" << std::endl;
        return 1;
    }
    
    std::cout << "✓ X25519 key generation successful" << std::endl;
    
    // Test Ed25519 key generation
    unsigned char ed_pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char ed_sk[crypto_sign_SECRETKEYBYTES];
    
    std::cout << "Calling crypto_sign_keypair..." << std::endl;
    result = crypto_sign_keypair(ed_pk, ed_sk);
    std::cout << "crypto_sign_keypair result: " << result << std::endl;
    
    if (result != 0) {
        std::cerr << "ERROR: crypto_sign_keypair failed" << std::endl;
        return 1;
    }
    
    std::cout << "✓ Ed25519 key generation successful" << std::endl;
    std::cout << "All tests passed!" << std::endl;
    
    return 0;
}


