#ifndef NOCTURNE_HSM_ERRORS_HPP
#define NOCTURNE_HSM_ERRORS_HPP

#include <stdexcept>
#include <string>

namespace nocturne {
namespace hsm {

/**
 * @brief Base exception for HSM errors
 */
class HSMError : public std::runtime_error {
public:
    explicit HSMError(const std::string& message)
        : std::runtime_error(message) {}
};

/**
 * @brief HSM not initialized
 */
class HSMNotInitializedError : public HSMError {
public:
    HSMNotInitializedError()
        : HSMError("HSM not initialized") {}
};

/**
 * @brief Authentication required
 */
class HSMAuthenticationError : public HSMError {
public:
    explicit HSMAuthenticationError(const std::string& message)
        : HSMError("Authentication failed: " + message) {}
};

/**
 * @brief Key not found
 */
class HSMKeyNotFoundError : public HSMError {
public:
    explicit HSMKeyNotFoundError(const std::string& key_label)
        : HSMError("Key not found: " + key_label) {}
};

/**
 * @brief Operation not supported by HSM
 */
class HSMOperationNotSupportedError : public HSMError {
public:
    explicit HSMOperationNotSupportedError(const std::string& operation)
        : HSMError("Operation not supported: " + operation) {}
};

/**
 * @brief PKCS#11 specific error
 */
class PKCS11Error : public HSMError {
public:
    PKCS11Error(const std::string& function_name, unsigned long error_code)
        : HSMError(function_name + " failed with code 0x" +
                   std::to_string(error_code)),
          error_code_(error_code) {}

    unsigned long error_code() const { return error_code_; }

private:
    unsigned long error_code_;
};

} // namespace hsm
} // namespace nocturne

#endif // NOCTURNE_HSM_ERRORS_HPP
