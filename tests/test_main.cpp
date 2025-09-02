#define CATCH_CONFIG_MAIN
#define NOCTURNE_UNIT_TEST
#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>
#include <array>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <sstream>

// Include the main source but instruct it to exclude the CLI `main` when building unit tests
#define CATCH_CONFIG_MAIN
#define NOCTURNE_UNIT_TEST
#include "../nocturne-kx.cpp"

using namespace nocturne;

TEST_CASE("Basic key generation", "[crypto]") {
    check_sodium();
    
    SECTION("X25519 key generation") {
        auto kp = gen_x25519();
        REQUIRE(kp.pk.size() == crypto_kx_PUBLICKEYBYTES);
        REQUIRE(kp.sk.size() == crypto_kx_SECRETKEYBYTES);
        
        // Verify keys are not all zeros
        bool pk_nonzero = false, sk_nonzero = false;
        for (auto b : kp.pk) if (b != 0) { pk_nonzero = true; break; }
        for (auto b : kp.sk) if (b != 0) { sk_nonzero = true; break; }
        REQUIRE(pk_nonzero);
        REQUIRE(sk_nonzero);
    }
    
    SECTION("Ed25519 key generation") {
        auto kp = gen_ed25519();
        REQUIRE(kp.pk.size() == crypto_sign_PUBLICKEYBYTES);
        REQUIRE(kp.sk.size() == crypto_sign_SECRETKEYBYTES);
        
        // Verify keys are not all zeros
        bool pk_nonzero = false, sk_nonzero = false;
        for (auto b : kp.pk) if (b != 0) { pk_nonzero = true; break; }
        for (auto b : kp.sk) if (b != 0) { sk_nonzero = true; break; }
        REQUIRE(pk_nonzero);
        REQUIRE(sk_nonzero);
    }
}

TEST_CASE("Packet serialization", "[serialization]") {
    check_sodium();
    
    Packet p;
    p.version = VERSION;
    p.flags = FLAG_HAS_SIG;
    p.rotation_id = 42;
    p.counter = 12345;
    
    // Fill with random data
    randombytes_buf(p.eph_pk.data(), p.eph_pk.size());
    randombytes_buf(p.nonce.data(), p.nonce.size());
    
    p.aad = {1, 2, 3, 4, 5};
    p.ciphertext = {10, 20, 30, 40, 50};
    
    std::array<uint8_t, crypto_sign_BYTES> sig{};
    randombytes_buf(sig.data(), sig.size());
    p.signature = sig;
    
    SECTION("Serialize and deserialize") {
        auto serialized = serialize(p);
        REQUIRE(!serialized.empty());
        
        auto deserialized = deserialize(serialized);
        REQUIRE(deserialized.version == p.version);
        REQUIRE(deserialized.flags == p.flags);
        REQUIRE(deserialized.rotation_id == p.rotation_id);
        REQUIRE(deserialized.counter == p.counter);
        REQUIRE(deserialized.eph_pk == p.eph_pk);
        REQUIRE(deserialized.nonce == p.nonce);
        REQUIRE(deserialized.aad == p.aad);
        REQUIRE(deserialized.ciphertext == p.ciphertext);
        REQUIRE(deserialized.signature == p.signature);
    }
}

TEST_CASE("Key derivation", "[crypto]") {
    check_sodium();
    
    auto alice = gen_x25519();
    auto bob = gen_x25519();
    
    SECTION("Client-server key derivation") {
        auto client_tx = derive_tx_key_client(alice.pk, alice.sk, bob.pk);
        auto server_rx = derive_rx_key_server(alice.pk, bob.pk, bob.sk);
        
        REQUIRE(client_tx.size() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        REQUIRE(server_rx.size() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        
        // Keys should match (client tx = server rx)
        REQUIRE(client_tx == server_rx);
    }
}

TEST_CASE("AEAD encryption/decryption", "[crypto]") {
    check_sodium();
    
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> key{};
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce{};
    randombytes_buf(key.data(), key.size());
    randombytes_buf(nonce.data(), nonce.size());
    
    Bytes plaintext = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    Bytes aad = {0xAA, 0xBB, 0xCC, 0xDD};
    
    SECTION("Basic encryption/decryption") {
        auto ciphertext = aead_encrypt_xchacha(key, nonce, aad, plaintext);
        REQUIRE(ciphertext.size() > plaintext.size()); // Should include auth tag
        
        auto decrypted = aead_decrypt_xchacha(key, nonce, aad, ciphertext);
        REQUIRE(decrypted == plaintext);
    }
    
    SECTION("Tampered ciphertext should fail") {
        auto ciphertext = aead_encrypt_xchacha(key, nonce, aad, plaintext);
        ciphertext[0] ^= 1; // Flip one bit
        
        REQUIRE_THROWS_AS(aead_decrypt_xchacha(key, nonce, aad, ciphertext), std::runtime_error);
    }
    
    SECTION("Wrong key should fail") {
        auto ciphertext = aead_encrypt_xchacha(key, nonce, aad, plaintext);
        
        std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> wrong_key{};
        randombytes_buf(wrong_key.data(), wrong_key.size());
        
        REQUIRE_THROWS_AS(aead_decrypt_xchacha(wrong_key, nonce, aad, ciphertext), std::runtime_error);
    }
}

TEST_CASE("Digital signatures", "[crypto]") {
    check_sodium();
    
    auto kp = gen_ed25519();
    Bytes message = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    
    SECTION("Sign and verify") {
        auto signature = ed25519_sign(message, kp.sk);
        REQUIRE(signature.size() == crypto_sign_BYTES);
        
        REQUIRE(ed25519_verify(message, kp.pk, signature));
    }
    
    SECTION("Tampered message should fail") {
        auto signature = ed25519_sign(message, kp.sk);
        message[0] ^= 1; // Flip one bit
        
        REQUIRE_FALSE(ed25519_verify(message, kp.pk, signature));
    }
    
    SECTION("Wrong public key should fail") {
        auto signature = ed25519_sign(message, kp.sk);
        auto wrong_kp = gen_ed25519();
        
        REQUIRE_FALSE(ed25519_verify(message, wrong_kp.pk, signature));
    }
}

TEST_CASE("ReplayDB functionality", "[replay]") {
    std::filesystem::path test_db = "test_replaydb.bin";
    std::filesystem::path test_key = "test_mac_key.bin";
    
    // Clean up from previous tests
    std::filesystem::remove(test_db);
    std::filesystem::remove(test_key);
    
    SECTION("Basic operations") {
        // Create MAC key
        std::array<uint8_t, crypto_generichash_KEYBYTES> mac_key{};
        randombytes_buf(mac_key.data(), mac_key.size());
        {
            std::ofstream f(test_key, std::ios::binary);
            f.write(reinterpret_cast<const char*>(mac_key.data()), mac_key.size());
        }
        
        ReplayDB db(test_db, test_key);
        
        // Test get/set
        REQUIRE(db.get("test_key") == 0);
        db.set("test_key", 42);
        REQUIRE(db.get("test_key") == 42);
        
        // Test persistence
        ReplayDB db2(test_db, test_key);
        REQUIRE(db2.get("test_key") == 42);
    }
    
    // Cleanup
    std::filesystem::remove(test_db);
    std::filesystem::remove(test_key);
}

TEST_CASE("End-to-end encryption/decryption", "[e2e]") {
    check_sodium();
    
    auto receiver = gen_x25519();
    auto sender = gen_ed25519();
    
    Bytes plaintext = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    Bytes aad = {0xAA, 0xBB, 0xCC, 0xDD};
    
    SECTION("Basic encryption without signature") {
        auto encrypted = encrypt_packet(receiver.pk, plaintext, aad, 0, false, nullptr, nullptr);
        REQUIRE(!encrypted.empty());
        
        auto decrypted = decrypt_packet(receiver.pk, receiver.sk, encrypted, std::nullopt, nullptr, std::nullopt);
        REQUIRE(decrypted == plaintext);
    }
    
    SECTION("Encryption with signature") {
        // Create signer key file first
        {
            std::ofstream f("test_signer_sk.bin", std::ios::binary);
            f.write(reinterpret_cast<const char*>(sender.sk.data()), sender.sk.size());
        }
        FileHSM hsm("test_signer_sk.bin");
        
        auto encrypted = encrypt_packet(receiver.pk, plaintext, aad, 0, false, &hsm, nullptr);
        REQUIRE(!encrypted.empty());
        
        auto decrypted = decrypt_packet(receiver.pk, receiver.sk, encrypted, sender.pk, nullptr, std::nullopt);
        REQUIRE(decrypted == plaintext);
        
        // Cleanup
        std::filesystem::remove("test_signer_sk.bin");
    }
    
    SECTION("Encryption with ratchet") {
        auto encrypted = encrypt_packet(receiver.pk, plaintext, aad, 0, true, nullptr, nullptr);
        REQUIRE(!encrypted.empty());
        
        auto decrypted = decrypt_packet(receiver.pk, receiver.sk, encrypted, std::nullopt, nullptr, std::nullopt);
        REQUIRE(decrypted == plaintext);
    }
    
    SECTION("Rotation ID enforcement") {
        auto encrypted = encrypt_packet(receiver.pk, plaintext, aad, 100, false, nullptr, nullptr);
        
        // Should fail with min_rotation_id > packet rotation_id
        REQUIRE_THROWS_AS(
            decrypt_packet(receiver.pk, receiver.sk, encrypted, std::nullopt, nullptr, 101),
            std::runtime_error
        );
        
        // Should succeed with min_rotation_id <= packet rotation_id
        auto decrypted = decrypt_packet(receiver.pk, receiver.sk, encrypted, std::nullopt, nullptr, 100);
        REQUIRE(decrypted == plaintext);
    }
}

TEST_CASE("Error handling", "[errors]") {
    check_sodium();
    
    SECTION("Invalid packet deserialization") {
        Bytes invalid_data = {1, 2, 3}; // Too short
        REQUIRE_THROWS_AS(deserialize(invalid_data), std::runtime_error);
    }
    
    SECTION("Wrong version") {
        Packet p;
        p.version = 0xFF; // Invalid version
        auto serialized = serialize(p);
        
        REQUIRE_THROWS_AS(deserialize(serialized), std::runtime_error);
    }
    
    SECTION("Flag mismatch") {
        Packet p;
        p.flags = FLAG_HAS_SIG; // Set flag but no signature
        auto serialized = serialize(p);
        
        REQUIRE_THROWS_AS(deserialize(serialized), std::runtime_error);
    }
}
