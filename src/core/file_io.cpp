/// @file file_io.cpp
/// @brief Implementations for the @ref file_io.hpp helpers.

#include "file_io.hpp"

#include <fstream>

namespace nocturne {

Bytes read_all(const std::filesystem::path& p) {
    std::ifstream f{p, std::ios::binary};
    if (!f) throw IOError{"open failed: " + p.string()};
    f.seekg(0, std::ios::end);
    const std::streamsize len = f.tellg();
    f.seekg(0, std::ios::beg);
    Bytes out(static_cast<std::size_t>(len));
    if (len > 0) {
        f.read(reinterpret_cast<char*>(out.data()), len);
        if (!f) throw IOError{"read failed: " + p.string()};
    }
    return out;
}

void write_all(const std::filesystem::path& p, const Bytes& data) {
    std::ofstream f{p, std::ios::binary | std::ios::trunc};
    if (!f) throw IOError{"open failed: " + p.string()};
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
    if (!f) throw IOError{"write failed: " + p.string()};
}

void write_all_raw(const std::filesystem::path& p,
                   const std::uint8_t*           data,
                   std::size_t                    n)
{
    std::ofstream f{p, std::ios::binary | std::ios::trunc};
    if (!f) throw IOError{"open failed: " + p.string()};
    f.write(reinterpret_cast<const char*>(data),
            static_cast<std::streamsize>(n));
    if (!f) throw IOError{"write failed: " + p.string()};
}

}  // namespace nocturne
