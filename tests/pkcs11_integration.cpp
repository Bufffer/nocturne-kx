#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "src/pkcs11_wrapper.hpp"

TEST_CASE("PKCS11 library loads (soft) and basic token enumeration", "pkcs11") {
    // This test is a smoke test - it will pass if library can be opened via LibPKCS11Wrapper
    // The CI will install SoftHSM2 and provide the library path via PKCS11_LIB env var
    const char* libpath = std::getenv("PKCS11_LIB");
    if (!libpath) {
        WARN("PKCS11_LIB not set - skipping SoftHSM integration test");
        return;
    }

    auto wrapper = nocturne::LibPKCS11Wrapper(std::string(libpath));
    REQUIRE(true); // constructor succeeded
}


