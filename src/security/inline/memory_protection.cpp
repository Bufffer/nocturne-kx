/// @file memory_protection.cpp
/// @brief Global singleton storage + free-function accessors for the
///        memory_protection subsystem declared in @ref memory_protection.hpp.

#include "memory_protection.hpp"

#include <memory>

namespace memory_protection {

namespace {
std::unique_ptr<SecureAllocator> g_allocator;
}  // namespace

void initialize(const MemoryProtectionConfig& config) {
    if (!g_allocator) {
        g_allocator = std::make_unique<SecureAllocator>(config);
    }
}

void* allocate_secure(std::size_t size) {
    if (!g_allocator) initialize();
    return g_allocator->allocate(size);
}

void deallocate_secure(void* ptr) noexcept {
    if (g_allocator) g_allocator->deallocate(ptr);
}

std::string get_stats() {
    if (!g_allocator) return "Secure allocator not initialized";
    return g_allocator->get_stats();
}

}  // namespace memory_protection
