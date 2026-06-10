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
        
        // Test packet deserialization. Malformed input is a typed
        // Result error now — no exception edge to catch.
        if (auto packet = deserialize(input); packet.has_value()) {
            // A packet accepted by the parser MUST reserialize and
            // re-parse byte-consistently; any failure here is a bug.
            auto reserialized = serialize(*packet);
            if (!reserialized) {
                __builtin_trap();
            }

            auto redeserialized = deserialize(*reserialized);
            if (!redeserialized) {
                __builtin_trap();
            }

            // Verify round-trip consistency
            if (packet->version != redeserialized->version ||
                packet->flags != redeserialized->flags ||
                packet->rotation_id != redeserialized->rotation_id ||
                packet->counter != redeserialized->counter ||
                packet->eph_pk != redeserialized->eph_pk ||
                packet->nonce != redeserialized->nonce ||
                packet->aad != redeserialized->aad ||
                packet->ciphertext != redeserialized->ciphertext ||
                packet->signature != redeserialized->signature) {
                // This should never happen - indicates a bug
                __builtin_trap();
            }
        }
        
        // Test key derivation with random data — exercise the code paths
        // for memory safety, not the mathematical key-agreement invariant.
        // tx_key == rx_key only holds when (pk1, sk) is a legitimate
        // X25519 keypair; with arbitrary fuzz bytes that's almost never
        // true, so asserting equality was incorrect (and was the crash
        // surfaced by libFuzzer input 0x0a, 101× 0xff).
        if (size >= crypto_kx_PUBLICKEYBYTES * 2 + crypto_kx_SECRETKEYBYTES) {
            std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> pk1{}, pk2{};
            std::array<uint8_t, crypto_kx_SECRETKEYBYTES> sk{};

            std::memcpy(pk1.data(), data, crypto_kx_PUBLICKEYBYTES);
            std::memcpy(pk2.data(), data + crypto_kx_PUBLICKEYBYTES, crypto_kx_PUBLICKEYBYTES);
            std::memcpy(sk.data(), data + crypto_kx_PUBLICKEYBYTES * 2, crypto_kx_SECRETKEYBYTES);

            // Result-based now: invalid DH inputs come back as typed
            // errors instead of exceptions. Either outcome is fine —
            // we're exercising the paths for memory safety only.
            auto tx_key = derive_tx_key_client(pk1, sk, pk2);
            auto rx_key = derive_rx_key_server(pk1, pk2, sk);
            (void)tx_key; (void)rx_key;
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
            
            if (auto ciphertext = aead_encrypt_xchacha(key, nonce, aad, plaintext);
                ciphertext.has_value()) {
                auto decrypted = aead_decrypt_xchacha(key, nonce, aad, *ciphertext);
                if (!decrypted || *decrypted != plaintext) {
                    __builtin_trap();
                }

                // Test tampered ciphertext — must come back as a typed
                // AEAD auth failure, never as a success.
                if (!ciphertext->empty()) {
                    (*ciphertext)[0] ^= 1;
                    if (aead_decrypt_xchacha(key, nonce, aad, *ciphertext).has_value()) {
                        __builtin_trap();
                    }
                }
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
