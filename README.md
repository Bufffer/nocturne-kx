# nocturne-kx — Ephemeral X25519 + XChaCha20 AEAD + Ed25519 (C++23, libsodium)

> **Repo Description:**  
> Ephemeral X25519 ECDH + XChaCha20-Poly1305 AEAD with optional Ed25519 sender authentication. Forward secrecy, AAD binding, versioned binary packets. Minimal CLI in C++23.

**nocturne-kx** is a small but serious encryption tool that provides:
- **Perfect Forward Secrecy (PFS)** using ephemeral X25519 keys per message.
- **Authenticated Encryption** with XChaCha20-Poly1305-IETF (24-byte nonce).
- **Optional Identity Authentication** via Ed25519 over `header || aad || ciphertext`.
- **AAD Binding**: Attach metadata such as channel or version to prevent downgrade/mix attacks.
- **Versioned Binary Packet**: Compact format `[ver|flags|eph_pk|nonce|aad_len|ct_len|aad|ct|signature?]`.
- **Minimal CLI** for key generation, encryption, and decryption.
- **Modern C++23 + libsodium**: Clean, safe, and portable.

---

## Features

- **Forward Secrecy**: Ephemeral X25519 keys per message.
- **Message Integrity & Confidentiality**: XChaCha20-Poly1305 AEAD.
- **Optional Sender Authentication**: Ed25519 signature.
- **Additional Authenticated Data (AAD)** support.
- **Versioned Packet Format** for future-proofing.
- **Cross-platform C++23 CLI**.

---

**⚠️ CRITICAL SECURITY WARNING ⚠️**

This is a **PROTOTYPE** implementation. It is **NOT** certified for military or production use. For production deployment, you MUST:

1. Obtain formal security audit and certification
2. Implement all missing security features
3. Use proper HSM integration
4. Conduct comprehensive penetration testing
5. Follow secure development lifecycle practices

## Overview

Nocturne-KX is a hardened cryptographic communication protocol that provides:

- **End-to-end encryption** using X25519 key exchange and ChaCha20-Poly1305 AEAD
- **Digital signatures** using Ed25519 for message authentication
- **Replay protection** with atomic, MAC-protected replay databases
- **Key rotation** with enforced rotation metadata
- **Forward secrecy** through ephemeral key exchange
- **HSM integration** support for secure key storage
- **Double Ratchet** algorithm scaffolding for post-compromise recovery

## Features

### Core Security Features
- **X25519 Key Exchange**: Elliptic curve Diffie-Hellman for secure key establishment
- **ChaCha20-Poly1305 AEAD**: Authenticated encryption with associated data
- **Ed25519 Signatures**: Digital signatures for message authentication
- **Replay Protection**: Atomic, MAC-protected replay database with anti-rollback
- **Key Rotation**: Enforced rotation with metadata tracking
- **Ephemeral Keys**: Forward secrecy through one-time keys

### Advanced Features
- **HSM Integration**: PKCS#11 wrapper for secure hardware integration
- **Double Ratchet**: Signal Protocol implementation for post-compromise recovery
- **Session Management**: Multi-session support with persistence
- **Audit Logging**: Comprehensive security event logging
- **Fuzzing Support**: LibFuzzer integration for security testing

## Installation

### Prerequisites

- C++23 compatible compiler (GCC 12+, Clang 15+, MSVC 2022)
- CMake 3.20+
- libsodium 1.0.18+
- Catch2 3.0+ (for tests)

### Building

```bash
# Clone the repository
git clone https://github.com/your-org/nocturne-kx.git
cd nocturne-kx

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
make -j$(nproc)

# Run tests
make test
```

### Dependencies

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y libsodium-dev pkg-config cmake build-essential
```

#### macOS
```bash
brew install libsodium pkg-config cmake
```

#### Windows
```bash
# Install vcpkg
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.bat
./vcpkg install libsodium:x64-windows

# Configure CMake with vcpkg
cmake .. -DCMAKE_TOOLCHAIN_FILE=path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
```

## Usage

### Basic Key Generation

```bash
# Generate receiver key pair
./nocturne-kx gen-receiver keys/

# Generate signer key pair
./nocturne-kx gen-signer keys/
```

### Basic Encryption/Decryption

```bash
# Encrypt a message
./nocturne-kx encrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --in message.txt \
  --out encrypted.bin

# Decrypt a message
./nocturne-kx decrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --rx-sk keys/receiver_x25519_sk.bin \
  --in encrypted.bin \
  --out decrypted.txt
```

### Advanced Features

#### With Digital Signatures
```bash
# Encrypt with signature
./nocturne-kx encrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --sign-hsm-uri file://keys/sender_ed25519_sk.bin \
  --in message.txt \
  --out encrypted_signed.bin

# Decrypt with signature verification
./nocturne-kx decrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --rx-sk keys/receiver_x25519_sk.bin \
  --expect-signer keys/sender_ed25519_pk.bin \
  --in encrypted_signed.bin \
  --out decrypted.txt
```

#### With Replay Protection
```bash
# Encrypt with replay protection
./nocturne-kx encrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --replay-db /path/to/replay.db \
  --mac-key /path/to/mac.key \
  --in message.txt \
  --out encrypted.bin

# Decrypt with replay protection
./nocturne-kx decrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --rx-sk keys/receiver_x25519_sk.bin \
  --replay-db /path/to/replay.db \
  --mac-key /path/to/mac.key \
  --in encrypted.bin \
  --out decrypted.txt
```

#### With Key Rotation
```bash
# Encrypt with rotation ID
./nocturne-kx encrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --rotation-id 100 \
  --in message.txt \
  --out encrypted.bin

# Decrypt with minimum rotation ID
./nocturne-kx decrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --rx-sk keys/receiver_x25519_sk.bin \
  --min-rotation 100 \
  --in encrypted.bin \
  --out decrypted.txt
```

#### With Ratchet (Simple DH)
```bash
# Encrypt with ratchet
./nocturne-kx encrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --ratchet \
  --in message.txt \
  --out encrypted.bin

# Decrypt with ratchet
./nocturne-kx decrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --rx-sk keys/receiver_x25519_sk.bin \
  --in encrypted.bin \
  --out decrypted.txt
```

## Security Considerations

### Production Deployment Checklist

Before deploying to production, ensure you have:

- [ ] **Formal Security Audit**: Independent security review by qualified experts
- [ ] **HSM Integration**: Replace FileHSM with proper PKCS#11 HSM
- [ ] **Key Management**: Implement proper key lifecycle management
- [ ] **Access Controls**: Implement proper authentication and authorization
- [ ] **Audit Logging**: Comprehensive security event logging
- [ ] **Monitoring**: Real-time security monitoring and alerting
- [ ] **Incident Response**: Plan for security incident response
- [ ] **Compliance**: Ensure compliance with relevant regulations
- [ ] **Testing**: Comprehensive penetration testing
- [ ] **Documentation**: Complete operational documentation

### Security Features

#### Replay Protection
- Atomic writes to prevent corruption
- MAC protection against tampering
- Version counter for anti-rollback
- Persistent storage with integrity checks

#### Key Rotation
- Enforced rotation metadata
- Minimum rotation ID enforcement
- Rotation audit trail
- Automatic rotation triggers

#### HSM Integration
- PKCS#11 wrapper for secure hardware
- Private key never leaves HSM
- Hardware-based random number generation
- Tamper-resistant key storage

#### Double Ratchet
- Forward secrecy through key ratcheting
- Post-compromise recovery
- Message ordering and replay protection
- Skipped message key storage

### Known Limitations

1. **Prototype Status**: This is not production-ready code
2. **Limited Testing**: Comprehensive security testing required
3. **HSM Integration**: FileHSM is for development only
4. **Double Ratchet**: Basic implementation, not full Signal Protocol
5. **Key Management**: Basic key management, enterprise features needed
6. **Audit Logging**: Basic logging, comprehensive audit needed
7. **Error Handling**: Basic error handling, production hardening needed

## Development

### Building Tests

```bash
# Build with tests
cmake .. -DBUILD_TESTS=ON
make -j$(nproc)

# Run tests
./nocturne-tests
```

### Building Fuzzer

```bash
# Build with fuzzer
cmake .. -DBUILD_FUZZER=ON
make -j$(nproc)

# Run fuzzer
./nocturne-fuzzer -max_len=1000 -runs=10000
```

### Code Quality

```bash
# Static analysis
cppcheck --enable=all nocturne-kx.cpp

# Address sanitizer
cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-fsanitize=address"
make
```

### Continuous Integration

The project includes GitHub Actions workflows for:

- **Build Testing**: Multiple compiler and platform testing
- **Sanitizer Testing**: Address, undefined, and memory sanitizers
- **Fuzzing**: Automated fuzzing with LibFuzzer
- **Security Scanning**: Static analysis and security checks

## Architecture

### Core Components

1. **Key Exchange**: X25519-based key establishment
2. **Encryption**: ChaCha20-Poly1305 AEAD encryption
3. **Signatures**: Ed25519 digital signatures
4. **Replay Protection**: Atomic, MAC-protected replay database
5. **HSM Integration**: PKCS#11 wrapper for secure hardware
6. **Double Ratchet**: Signal Protocol implementation
7. **Session Management**: Multi-session support with persistence

### Security Model

- **Confidentiality**: AEAD encryption with ephemeral keys
- **Integrity**: Digital signatures and MAC protection
- **Authenticity**: Ed25519 signatures for message origin
- **Forward Secrecy**: Ephemeral key exchange and ratcheting
- **Replay Protection**: Atomic replay database with versioning
- **Key Rotation**: Enforced rotation with metadata tracking

## Contributing

### Development Guidelines

1. **Security First**: All changes must maintain security properties
2. **Testing**: Comprehensive test coverage required
3. **Documentation**: Clear documentation for all changes
4. **Code Review**: Security-focused code review process
5. **Static Analysis**: Address all static analysis warnings

### Security Review Process

1. **Design Review**: Security architecture review
2. **Implementation Review**: Code-level security review
3. **Testing Review**: Security testing review
4. **Deployment Review**: Production deployment review

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided "as is" without warranty of any kind. The authors and contributors are not liable for any damages arising from the use of this software. This is prototype software and should not be used in production without proper security review and certification.

## Support

For security issues, please contact: security@your-org.com

For general questions, please open an issue on GitHub.

## Acknowledgments

- **libsodium**: Core cryptographic primitives
- **Signal Protocol**: Double Ratchet algorithm inspiration
- **ChaCha20-Poly1305**: AEAD encryption algorithm
- **Ed25519**: Digital signature algorithm
- **X25519**: Key exchange algorithm
