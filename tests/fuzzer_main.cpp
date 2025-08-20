#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <algorithm>
#include <random>
#include <thread>
#include <atomic>

// Include the main header but exclude main function
#define NOCTURNE_FUZZER_BUILD
#include "../nocturne-kx.cpp"

using namespace nocturne;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 100) return 0; // Skip very small inputs
    
    try {
        check_sodium();
        
        // Convert input to vector
        Bytes input(data, data + size);
        
        // Test packet deserialization
        try {
            auto packet = deserialize(input);
            
            // Test serialization of deserialized packet
            auto reserialized = serialize(packet);
            
            // Test deserialization of reserialized packet
            auto redeserialized = deserialize(reserialized);
            
            // Verify round-trip consistency
            if (packet.version != redeserialized.version ||
                packet.flags != redeserialized.flags ||
                packet.rotation_id != redeserialized.rotation_id ||
                packet.counter != redeserialized.counter ||
                packet.eph_pk != redeserialized.eph_pk ||
                packet.nonce != redeserialized.nonce ||
                packet.aad != redeserialized.aad ||
                packet.ciphertext != redeserialized.ciphertext ||
                packet.signature != redeserialized.signature) {
                // This should never happen - indicates a bug
                __builtin_trap();
            }
        } catch (const std::runtime_error&) {
            // Expected for malformed input
        }
        
        // Test key derivation with random data
        if (size >= crypto_kx_PUBLICKEYBYTES * 2 + crypto_kx_SECRETKEYBYTES) {
            std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> pk1{}, pk2{};
            std::array<uint8_t, crypto_kx_SECRETKEYBYTES> sk{};
            
            std::memcpy(pk1.data(), data, crypto_kx_PUBLICKEYBYTES);
            std::memcpy(pk2.data(), data + crypto_kx_PUBLICKEYBYTES, crypto_kx_PUBLICKEYBYTES);
            std::memcpy(sk.data(), data + crypto_kx_PUBLICKEYBYTES * 2, crypto_kx_SECRETKEYBYTES);
            
            try {
                auto tx_key = derive_tx_key_client(pk1, sk, pk2);
                auto rx_key = derive_rx_key_server(pk1, pk2, sk);
                
                // Keys should match
                if (tx_key != rx_key) {
                    __builtin_trap();
                }
            } catch (const std::runtime_error&) {
                // Expected for invalid keys
            }
        }
        
        // Test AEAD with random data
        if (size >= crypto_aead_xchacha20poly1305_ietf_KEYBYTES + 
                   crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 10) {
            
            std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> key{};
            std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce{};
            
            std::memcpy(key.data(), data, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
            std::memcpy(nonce.data(), data + crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 
                       crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
            
            Bytes plaintext(data + crypto_aead_xchacha20poly1305_ietf_KEYBYTES + 
                           crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 
                           data + std::min(size, static_cast<size_t>(crypto_aead_xchacha20poly1305_ietf_KEYBYTES + 
                                          crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 10)));
            
            Bytes aad = {0xAA, 0xBB, 0xCC, 0xDD};
            
            try {
                auto ciphertext = aead_encrypt_xchacha(key, nonce, aad, plaintext);
                auto decrypted = aead_decrypt_xchacha(key, nonce, aad, ciphertext);
                
                if (decrypted != plaintext) {
                    __builtin_trap();
                }
                
                // Test tampered ciphertext
                if (ciphertext.size() > 0) {
                    ciphertext[0] ^= 1;
                    try {
                        aead_decrypt_xchacha(key, nonce, aad, ciphertext);
                        // Should have thrown
                        __builtin_trap();
                    } catch (const std::runtime_error&) {
                        // Expected
                    }
                }
            } catch (const std::runtime_error&) {
                // Expected for invalid keys/nonces
            }
        }
        
        // Test digital signatures with random data
        if (size >= crypto_sign_SECRETKEYBYTES + 10) {
            std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
            std::memcpy(sk.data(), data, crypto_sign_SECRETKEYBYTES);
            
            Bytes message(data + crypto_sign_SECRETKEYBYTES, 
                         data + std::min(size, static_cast<size_t>(crypto_sign_SECRETKEYBYTES + 10)));
            
            try {
                auto signature = ed25519_sign(message, sk);
                
                // Verify with correct message
                if (!ed25519_verify(message, 
                                   std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>{}, // Will be wrong but shouldn't crash
                                   signature)) {
                    // Expected to fail with wrong public key
                }
                
                // Test tampered message
                if (message.size() > 0) {
                    message[0] ^= 1;
                    if (ed25519_verify(message, 
                                      std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>{}, 
                                      signature)) {
                        // Should have failed
                        __builtin_trap();
                    }
                }
            } catch (const std::runtime_error&) {
                // Expected for invalid keys
            }
        }
        
    } catch (const std::exception&) {
        // Catch any unexpected exceptions
    }
    
    return 0;
}
