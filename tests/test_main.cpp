#define NOCTURNE_UNIT_TEST
#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>
#include <catch2/catch_session.hpp>
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

int main(int argc, char* argv[]) {
    // Initialize and run Catch2 test session
    Catch::Session session;
    return session.run(argc, argv);
}

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
        REQUIRE(serialized.has_value());
        REQUIRE(!serialized->empty());

        auto deserialized_r = deserialize(*serialized);
        REQUIRE(deserialized_r.has_value());
        const auto& deserialized = *deserialized_r;
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

        REQUIRE(client_tx.has_value());
        REQUIRE(server_rx.has_value());
        REQUIRE(client_tx->size() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        REQUIRE(server_rx->size() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

        // Keys should match (client tx = server rx)
        REQUIRE(*client_tx == *server_rx);
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
        REQUIRE(ciphertext.has_value());
        REQUIRE(ciphertext->size() > plaintext.size()); // Should include auth tag

        auto decrypted = aead_decrypt_xchacha(key, nonce, aad, *ciphertext);
        REQUIRE(decrypted.has_value());
        REQUIRE(*decrypted == plaintext);
    }

    SECTION("Tampered ciphertext should fail") {
        auto ciphertext = aead_encrypt_xchacha(key, nonce, aad, plaintext);
        REQUIRE(ciphertext.has_value());
        (*ciphertext)[0] ^= 1; // Flip one bit

        auto decrypted = aead_decrypt_xchacha(key, nonce, aad, *ciphertext);
        REQUIRE_FALSE(decrypted.has_value());
        REQUIRE(decrypted.error().code == ErrorCode::AeadAuthFailed);
    }

    SECTION("Wrong key should fail") {
        auto ciphertext = aead_encrypt_xchacha(key, nonce, aad, plaintext);
        REQUIRE(ciphertext.has_value());

        std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> wrong_key{};
        randombytes_buf(wrong_key.data(), wrong_key.size());

        auto decrypted = aead_decrypt_xchacha(wrong_key, nonce, aad, *ciphertext);
        REQUIRE_FALSE(decrypted.has_value());
        REQUIRE(decrypted.error().code == ErrorCode::AeadAuthFailed);
    }

    SECTION("Truncated ciphertext is a length reject, not an auth reject") {
        Bytes too_short = {1, 2, 3}; // Shorter than the Poly1305 tag
        auto decrypted = aead_decrypt_xchacha(key, nonce, aad, too_short);
        REQUIRE_FALSE(decrypted.has_value());
        REQUIRE(decrypted.error().code == ErrorCode::PacketTruncated);
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
        auto encrypted = encrypt_packet(receiver.pk, plaintext, EncryptOptions{.aad = aad});
        REQUIRE(encrypted.has_value());
        REQUIRE(!encrypted->empty());

        auto decrypted = decrypt_packet(receiver.pk, receiver.sk, *encrypted);
        REQUIRE(decrypted.has_value());
        REQUIRE(*decrypted == plaintext);
    }

    SECTION("Encryption with signature") {
        // Create signer key file first
        {
            std::ofstream f("test_signer_sk.bin", std::ios::binary);
            f.write(reinterpret_cast<const char*>(sender.sk.data()), sender.sk.size());
        }
        FileHSM hsm("test_signer_sk.bin");

        auto encrypted = encrypt_packet(receiver.pk, plaintext,
            EncryptOptions{.aad = aad, .signer = &hsm});
        REQUIRE(encrypted.has_value());
        REQUIRE(!encrypted->empty());

        auto decrypted = decrypt_packet(receiver.pk, receiver.sk, *encrypted,
            DecryptOptions{.expected_signer_ed25519_pk = sender.pk});
        REQUIRE(decrypted.has_value());
        REQUIRE(*decrypted == plaintext);

        // Cleanup
        std::filesystem::remove("test_signer_sk.bin");
    }

    SECTION("Encryption with ratchet") {
        auto encrypted = encrypt_packet(receiver.pk, plaintext,
            EncryptOptions{.aad = aad, .use_ratchet = true});
        REQUIRE(encrypted.has_value());
        REQUIRE(!encrypted->empty());

        auto decrypted = decrypt_packet(receiver.pk, receiver.sk, *encrypted);
        REQUIRE(decrypted.has_value());
        REQUIRE(*decrypted == plaintext);
    }

    SECTION("Rotation ID enforcement") {
        auto encrypted = encrypt_packet(receiver.pk, plaintext,
            EncryptOptions{.aad = aad, .rotation_id = 100});
        REQUIRE(encrypted.has_value());

        // Must fail with min_rotation_id > packet rotation_id — typed
        // RotationStale, not an exception (P6.1b error contract).
        auto stale = decrypt_packet(receiver.pk, receiver.sk, *encrypted,
            DecryptOptions{.min_rotation_id = 101});
        REQUIRE_FALSE(stale.has_value());
        REQUIRE(stale.error().code == ErrorCode::RotationStale);

        // Should succeed with min_rotation_id <= packet rotation_id
        auto decrypted = decrypt_packet(receiver.pk, receiver.sk, *encrypted,
            DecryptOptions{.min_rotation_id = 100});
        REQUIRE(decrypted.has_value());
        REQUIRE(*decrypted == plaintext);
    }
}

#ifdef NOCTURNE_ENABLE_PQC

// Regression net for the FLAG_HAS_PQC_SIG path landed in P4.2 + P4.3.
// Exercises ML-DSA-87 and hybrid Ed25519+ML-DSA-87 across both the
// classical X25519 encrypt path (encrypt_packet/decrypt_packet) and the
// PQC KEM path (encrypt_packet_kem/decrypt_packet_kem) — that's where a
// quiet wire-format regression would matter most.
TEST_CASE("PQC signature roundtrip on encrypt_packet", "[pqc-sig]") {
    nocturne::check_sodium();

    auto receiver = nocturne::gen_x25519();
    nocturne::Bytes pt  = {'p','q','-','s','i','g'};
    nocturne::Bytes aad = {0xAA, 0xBB};

    auto run = [&](nocturne::pqc::SigType st, const char* label) {
        INFO("sig type: " << label);
        auto scheme = nocturne::pqc::SignatureFactory{}.create(st);
        auto kp = scheme->generate_keypair();
        nocturne::PqcSignerConfig signer{st, kp.secret_key};

        auto packet = encrypt_packet(receiver.pk, pt,
            EncryptOptions{.aad = aad, .pqc_signer = &signer});
        REQUIRE(packet.has_value());
        REQUIRE(!packet->empty());

        SECTION(std::string(label) + " happy path") {
            nocturne::PqcVerifierConfig verifier{st, kp.public_key};
            auto decrypted = decrypt_packet(receiver.pk, receiver.sk, *packet,
                DecryptOptions{.pqc_verifier = &verifier});
            REQUIRE(decrypted.has_value());
            REQUIRE(*decrypted == pt);
        }

        SECTION(std::string(label) + " wrong pk is rejected") {
            auto kp2 = scheme->generate_keypair();
            nocturne::PqcVerifierConfig verifier{st, kp2.public_key};
            auto r = decrypt_packet(receiver.pk, receiver.sk, *packet,
                DecryptOptions{.pqc_verifier = &verifier});
            REQUIRE_FALSE(r.has_value());
            REQUIRE(r.error().code == ErrorCode::SignatureVerifyFailed);
        }

        SECTION(std::string(label) + " missing pqc-sig flag is rejected when verifier set") {
            // Strip FLAG_HAS_PQC_SIG by re-encrypting without a signer.
            auto bare = encrypt_packet(receiver.pk, pt, EncryptOptions{.aad = aad});
            REQUIRE(bare.has_value());
            nocturne::PqcVerifierConfig verifier{st, kp.public_key};
            auto r = decrypt_packet(receiver.pk, receiver.sk, *bare,
                DecryptOptions{.pqc_verifier = &verifier});
            REQUIRE_FALSE(r.has_value());
            REQUIRE(r.error().code == ErrorCode::SignatureMissing);
        }
    };

    run(nocturne::pqc::SigType::PURE_MLDSA87,           "ML-DSA-87");
    run(nocturne::pqc::SigType::HYBRID_ED25519_MLDSA87, "Hybrid Ed25519+ML-DSA-87");
}

TEST_CASE("PQC signature roundtrip on encrypt_packet_kem (full hybrid)", "[pqc-sig]") {
    nocturne::check_sodium();

    // Receiver: hybrid X25519+ML-KEM-1024.
    auto kem = nocturne::pqc::KEMFactory{}.create(
        nocturne::pqc::KEMType::HYBRID_X25519_MLKEM1024);
    auto rx = kem->generate_keypair();

    // Signer: hybrid Ed25519+ML-DSA-87. This is the full
    // PQ-resistant-on-both-sides configuration.
    auto sig_type = nocturne::pqc::SigType::HYBRID_ED25519_MLDSA87;
    auto scheme   = nocturne::pqc::SignatureFactory{}.create(sig_type);
    auto sig_kp   = scheme->generate_keypair();
    nocturne::PqcSignerConfig signer{sig_type, sig_kp.secret_key};

    nocturne::Bytes pt = {0x01, 0x02, 0x03, 0x04};
    auto packet = encrypt_packet_kem(
        nocturne::pqc::KEMType::HYBRID_X25519_MLKEM1024,
        std::vector<uint8_t>(rx.public_key.begin(), rx.public_key.end()),
        pt, EncryptOptions{.pqc_signer = &signer});
    REQUIRE(packet.has_value());
    REQUIRE(!packet->empty());

    SECTION("hybrid KEM + hybrid sig verifies") {
        nocturne::PqcVerifierConfig verifier{sig_type, sig_kp.public_key};
        auto decrypted = decrypt_packet_kem(
            std::vector<uint8_t>(rx.public_key.begin(), rx.public_key.end()),
            std::vector<uint8_t>(rx.secret_key.begin(), rx.secret_key.end()),
            *packet, DecryptOptions{.pqc_verifier = &verifier});
        REQUIRE(decrypted.has_value());
        REQUIRE(*decrypted == pt);
    }

    SECTION("type-mismatch verifier is rejected") {
        // Sender signed hybrid, receiver expects pure ML-DSA-87 — must fail
        // on the type guard before any cryptographic work runs.
        auto wrong_scheme = nocturne::pqc::SignatureFactory{}.create(
            nocturne::pqc::SigType::PURE_MLDSA87);
        auto wrong_kp = wrong_scheme->generate_keypair();
        nocturne::PqcVerifierConfig verifier{
            nocturne::pqc::SigType::PURE_MLDSA87, wrong_kp.public_key};
        auto r = decrypt_packet_kem(
            std::vector<uint8_t>(rx.public_key.begin(), rx.public_key.end()),
            std::vector<uint8_t>(rx.secret_key.begin(), rx.secret_key.end()),
            *packet, DecryptOptions{.pqc_verifier = &verifier});
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == ErrorCode::SignatureTypeMismatch);
    }

    SECTION("tampered pqc_sig byte breaks verification") {
        // Hybrid sig wire layout is ed_sig(64) || mldsa_sig(4627), and the
        // FLAG_HAS_SIG block isn't set in this test, so packet.back() is
        // the last byte of the ML-DSA half. Flipping it must break the
        // hybrid AND-verify.
        auto bad = *packet;
        bad.back() ^= 0x01;
        nocturne::PqcVerifierConfig verifier{sig_type, sig_kp.public_key};
        auto r = decrypt_packet_kem(
            std::vector<uint8_t>(rx.public_key.begin(), rx.public_key.end()),
            std::vector<uint8_t>(rx.secret_key.begin(), rx.secret_key.end()),
            bad, DecryptOptions{.pqc_verifier = &verifier});
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == ErrorCode::SignatureVerifyFailed);
    }
}

// Regression net for commit 9b5c00b: a divergence between the version bound
// into the KEM combined-secret on encrypt vs. decrypt produces a ciphertext
// that round-trips through every CI compile/sanitizer check but fails AEAD
// auth at runtime. End-to-end encrypt+decrypt is the only thing that catches
// it. Exercise both PQC KEM types (hybrid X25519+ML-KEM-1024 and pure
// ML-KEM-1024) plus the negative paths (wrong key, tampered ciphertext).
TEST_CASE("PQC encrypt_packet_kem / decrypt_packet_kem roundtrip", "[e2e][pqc]") {
    nocturne::check_sodium();

    auto run_roundtrip = [](nocturne::pqc::KEMType kt, const char* label) {
        INFO("KEM type: " << label);

        auto kem = nocturne::pqc::KEMFactory{}.create(kt);
        auto kp = kem->generate_keypair();
        std::vector<uint8_t> rx_pk(kp.public_key.begin(), kp.public_key.end());
        std::vector<uint8_t> rx_sk(kp.secret_key.begin(), kp.secret_key.end());

        nocturne::Bytes plaintext = {'h','e','l','l','o','-','p','q','c'};
        nocturne::Bytes aad       = {0xDE, 0xAD, 0xBE, 0xEF};

        SECTION(std::string("happy path: ") + label) {
            auto packet = encrypt_packet_kem(kt, rx_pk, plaintext,
                EncryptOptions{.aad = aad});
            REQUIRE(packet.has_value());
            REQUIRE(!packet->empty());

            auto decrypted = decrypt_packet_kem(rx_pk, rx_sk, *packet);
            REQUIRE(decrypted.has_value());
            REQUIRE(*decrypted == plaintext);
        }

        SECTION(std::string("tampered ciphertext fails: ") + label) {
            auto packet = encrypt_packet_kem(kt, rx_pk, plaintext,
                EncryptOptions{.aad = aad});
            REQUIRE(packet.has_value());
            // Flip a bit in the AEAD ciphertext region by mutating the
            // last byte (which is always inside the AEAD tag).
            packet->back() ^= 0x01;
            auto r = decrypt_packet_kem(rx_pk, rx_sk, *packet);
            REQUIRE_FALSE(r.has_value());
            REQUIRE(r.error().code == ErrorCode::AeadAuthFailed);
        }

        SECTION(std::string("wrong receiver key fails: ") + label) {
            auto packet = encrypt_packet_kem(kt, rx_pk, plaintext,
                EncryptOptions{.aad = aad});
            REQUIRE(packet.has_value());
            auto kp2 = kem->generate_keypair();
            std::vector<uint8_t> wrong_sk(kp2.secret_key.begin(),
                                          kp2.secret_key.end());
            // Pair the original pk with a different sk — depending on the
            // KEM type the mismatch surfaces either as a decapsulate
            // reject or as a different shared secret that fails AEAD
            // auth. Either way the call must fail with a typed error.
            auto r = decrypt_packet_kem(rx_pk, wrong_sk, *packet);
            REQUIRE_FALSE(r.has_value());
            REQUIRE((r.error().code == ErrorCode::AeadAuthFailed ||
                     r.error().code == ErrorCode::KemDecapsulateFailed));
        }
    };

    run_roundtrip(nocturne::pqc::KEMType::HYBRID_X25519_MLKEM1024, "hybrid");
    run_roundtrip(nocturne::pqc::KEMType::PURE_MLKEM1024, "mlkem");
}

TEST_CASE("PQC roundtrip with Ed25519 signer", "[e2e][pqc]") {
    nocturne::check_sodium();

    auto kem_type = nocturne::pqc::KEMType::HYBRID_X25519_MLKEM1024;
    auto kem = nocturne::pqc::KEMFactory{}.create(kem_type);
    auto kp = kem->generate_keypair();
    std::vector<uint8_t> rx_pk(kp.public_key.begin(), kp.public_key.end());
    std::vector<uint8_t> rx_sk(kp.secret_key.begin(), kp.secret_key.end());

    auto sender = nocturne::gen_ed25519();
    {
        std::ofstream f("test_pqc_signer_sk.bin", std::ios::binary);
        f.write(reinterpret_cast<const char*>(sender.sk.data()), sender.sk.size());
    }
    FileHSM hsm("test_pqc_signer_sk.bin");

    nocturne::Bytes plaintext = {0x01, 0x02, 0x03, 0x04};
    nocturne::Bytes aad       = {0xCA, 0xFE};

    auto packet = encrypt_packet_kem(kem_type, rx_pk, plaintext,
        EncryptOptions{.aad = aad, .signer = &hsm});
    REQUIRE(packet.has_value());

    SECTION("signed packet verifies with correct signer pk") {
        auto decrypted = decrypt_packet_kem(rx_pk, rx_sk, *packet,
            DecryptOptions{.expected_signer_ed25519_pk = sender.pk});
        REQUIRE(decrypted.has_value());
        REQUIRE(*decrypted == plaintext);
    }

    SECTION("signed packet rejected with wrong signer pk") {
        auto wrong = nocturne::gen_ed25519();
        auto r = decrypt_packet_kem(rx_pk, rx_sk, *packet,
            DecryptOptions{.expected_signer_ed25519_pk = wrong.pk});
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == ErrorCode::SignatureVerifyFailed);
    }

    std::filesystem::remove("test_pqc_signer_sk.bin");
}
#endif // NOCTURNE_ENABLE_PQC

// Local include — the hsm headers live outside the nocturne-kx.cpp graph.
#include "../src/hsm/file_hsm.hpp"
#include "../src/security/key_rotation.hpp"

TEST_CASE("FileHSM generate_key drives KeyRotationManager", "[hsm]") {
    nocturne::check_sodium();
    namespace fs = std::filesystem;

    auto base = fs::temp_directory_path() / "nocturne_filehsm_rotate_test";
    fs::remove_all(base);
    fs::create_directories(base);

    auto hsm = std::make_shared<nocturne::hsm::FileHSM>(base);
    REQUIRE(hsm->is_healthy());

    SECTION("generate_key produces a usable signing key") {
        nocturne::hsm::KeyPolicy policy;
        policy.sensitive = true;
        policy.extractable = false;

        auto md = hsm->generate_key("test-key", "Ed25519", policy);
        REQUIRE(md.label == "test-key");
        REQUIRE(md.algorithm == "Ed25519");
        REQUIRE(md.is_active);

        auto pk_opt = hsm->get_public_key();
        REQUIRE(pk_opt.has_value());

        // The key the HSM uses to sign must verify against the pk it
        // just reported — the smoke test that proves generate_key
        // actually wired the cache.
        const std::string msg = "rotation test";
        auto sig = hsm->sign(
            {reinterpret_cast<const uint8_t*>(msg.data()), msg.size()});
        REQUIRE(crypto_sign_verify_detached(
                    sig.data(),
                    reinterpret_cast<const uint8_t*>(msg.data()),
                    msg.size(),
                    pk_opt->data()) == 0);

        // The key file should exist on disk.
        REQUIRE(fs::exists(base / "test-key.ed25519.sk"));
    }

    SECTION("KeyRotationManager.generate_initial_key + rotate") {
        nocturne::security::RotationPolicy rpol;
        rpol.require_dual_approval = false;
        nocturne::security::KeyRotationManager krm(hsm, rpol);

        auto k1 = krm.generate_initial_key("rotation-key");
        // generate_initial_key returns a 32-byte key id (random); the
        // HSM-side label is "rotation-key", with a key file on disk.
        REQUIRE(fs::exists(base / "rotation-key.ed25519.sk"));

        // After rotation the HSM is signing with the new key. The
        // *previous* key file should still be present (FileHSM keeps
        // labels around so KRM's archive logic can find them); the new
        // label is "<old>_v<N>".
        auto k2 = krm.rotate(nocturne::security::RotationTrigger::TIME_BASED,
                             "test-operator");
        REQUIRE(k2.has_value());
        // Some entry with prefix "rotation-key_v" must exist.
        bool found_rotated = false;
        for (const auto& entry : fs::directory_iterator(base)) {
            auto name = entry.path().filename().string();
            if (name.rfind("rotation-key_v", 0) == 0) { found_rotated = true; break; }
        }
        REQUIRE(found_rotated);
        REQUIRE(k1 != *k2);
    }

    fs::remove_all(base);
}

TEST_CASE("Audit log verify_chain", "[audit]") {
    nocturne::check_sodium();
    namespace fs = std::filesystem;

    // Use a per-test temp dir so the .chain sidecar from a previous test
    // doesn't poison the new logger's start-of-chain state.
    auto base = fs::temp_directory_path() / "nocturne_audit_verify_test";
    fs::remove_all(base);
    fs::create_directories(base);
    auto log_path = base / "audit.jsonl";
    auto signer_sk_path = base / "signer_sk.bin";

    // Generate an Ed25519 signer and persist the secret key (raw 64B —
    // AuditLogger expects unencrypted raw bytes, matching the inline
    // logger's load path).
    auto signer = nocturne::gen_ed25519();
    {
        std::ofstream f(signer_sk_path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(signer.sk.data()), signer.sk.size());
    }

    SECTION("unsigned chain verifies after multiple records") {
        {
            audit_log::AuditLogger lg(log_path, std::nullopt, std::nullopt, std::nullopt);
            lg.log(audit_log::Severity::INFO, "CAT", "SUB", "first record");
            lg.log(audit_log::Severity::WARN, "CAT", "SUB", "second");
            lg.log(audit_log::Severity::ERROR, "CAT", "SUB", "third with \"quote\"");
        }
        auto r = audit_log::verify_chain(log_path);
        REQUIRE(r.ok);
        REQUIRE(r.records_checked == 3);
        REQUIRE(r.errors.empty());
    }

    SECTION("signed chain verifies with --expect-signer pinned") {
        {
            audit_log::AuditLogger lg(log_path, signer_sk_path, std::nullopt, std::nullopt);
            lg.log(audit_log::Severity::SECURITY, "CRYPTO", "ENCRYPT", "ok");
            lg.log(audit_log::Severity::SECURITY, "CRYPTO", "DECRYPT", "ok");
        }
        auto r = audit_log::verify_chain(log_path, signer.pk);
        REQUIRE(r.ok);
        REQUIRE(r.records_checked == 2);
    }

    SECTION("tampered record is detected") {
        {
            audit_log::AuditLogger lg(log_path, std::nullopt, std::nullopt, std::nullopt);
            lg.log(audit_log::Severity::INFO, "CAT", "SUB", "alpha");
            lg.log(audit_log::Severity::INFO, "CAT", "SUB", "beta");
        }
        // Tamper: rewrite the second line's message in-place. The file
        // structure stays valid JSONL but the hash no longer matches.
        std::vector<std::string> lines;
        {
            std::ifstream in(log_path);
            std::string line;
            while (std::getline(in, line)) lines.push_back(line);
        }
        REQUIRE(lines.size() == 2);
        auto pos = lines[1].find("\"msg\":\"beta\"");
        REQUIRE(pos != std::string::npos);
        lines[1].replace(pos, std::string("\"msg\":\"beta\"").size(),
                         "\"msg\":\"BETA\"");
        {
            std::ofstream out(log_path, std::ios::trunc);
            for (auto& l : lines) out << l << '\n';
        }
        auto r = audit_log::verify_chain(log_path);
        REQUIRE_FALSE(r.ok);
        REQUIRE(r.first_failure_line.has_value());
        REQUIRE(*r.first_failure_line == 2);
    }

    SECTION("wrong --expect-signer is rejected") {
        {
            audit_log::AuditLogger lg(log_path, signer_sk_path, std::nullopt, std::nullopt);
            lg.log(audit_log::Severity::INFO, "CAT", "SUB", "signed");
        }
        auto wrong = nocturne::gen_ed25519();
        auto r = audit_log::verify_chain(log_path, wrong.pk);
        REQUIRE_FALSE(r.ok);
    }

    fs::remove_all(base);
}

TEST_CASE("Error handling", "[errors]") {
    check_sodium();
    
    SECTION("Invalid packet deserialization") {
        Bytes invalid_data = {1, 2, 3}; // Too short
        auto r = deserialize(invalid_data);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == ErrorCode::PacketTruncated);
    }

    SECTION("Wrong version") {
        Packet p;
        p.version = 0xFF; // Invalid version
        auto serialized = serialize(p);
        REQUIRE(serialized.has_value());

        auto r = deserialize(*serialized);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == ErrorCode::PacketUnknownVersion);
    }

    SECTION("Flag mismatch") {
        Packet p;
        p.flags = FLAG_HAS_SIG; // Set flag but no signature
        auto serialized = serialize(p);
        REQUIRE_FALSE(serialized.has_value());
        REQUIRE(serialized.error().code == ErrorCode::PacketFlagInconsistent);
    }

    SECTION("Trailing bytes are rejected") {
        Packet p;
        auto serialized = serialize(p);
        REQUIRE(serialized.has_value());
        serialized->push_back(0x00);

        auto r = deserialize(*serialized);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == ErrorCode::PacketTrailingBytes);
    }
}
