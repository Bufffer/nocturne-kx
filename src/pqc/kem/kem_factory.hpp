/**
 * @file kem_factory.hpp
 * @brief Factory pattern for creating KEM instances
 *
 * Provides a centralized factory for instantiating different KEM algorithms
 * based on KEMType. Simplifies code that needs to work with multiple KEM types.
 *
 * @version 4.0.0
 */

#pragma once

#include "kem_interface.hpp"
#include <memory>
#include <stdexcept>

namespace nocturne {
namespace pqc {

/**
 * @brief Factory for creating KEM instances
 *
 * Usage:
 * @code
 * KEMFactory factory;
 * auto hybrid_kem = factory.create(KEMType::HYBRID_X25519_MLKEM1024);
 * auto keypair = hybrid_kem->generate_keypair();
 * @endcode
 */
class KEMFactory {
public:
    /**
     * @brief Create a KEM instance of the specified type
     *
     * @param type The type of KEM to create
     * @return std::unique_ptr<KEMInterface> to the created KEM instance
     * @throws std::invalid_argument if type is not recognized or not available
     */
    std::unique_ptr<KEMInterface> create(KEMType type);

    /**
     * @brief Check if a KEM type is available
     *
     * @param type The type to check
     * @return true if the KEM type can be created, false otherwise
     */
    static bool is_available(KEMType type);

    /**
     * @brief Get a human-readable description of a KEM type
     *
     * @param type The type to describe
     * @return std::string with the description
     */
    static std::string get_description(KEMType type);
};

} // namespace pqc
} // namespace nocturne
