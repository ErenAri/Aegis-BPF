#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace aegis {

class Sha256 {
public:
    static constexpr size_t kDigestSize = 32;
    static constexpr size_t kBlockSize = 64;

    Sha256();

    void update(const uint8_t *data, size_t len);
    void update(const std::vector<uint8_t> &data);
    void update(const std::string &data);

    std::array<uint8_t, kDigestSize> finalize();
    std::string finalize_hex();

    static std::string hash_hex(const uint8_t *data, size_t len);
    static std::string hash_hex(const std::string &data);

private:
    void transform(const uint8_t data[kBlockSize]);

    std::array<uint32_t, 8> state_;
    uint64_t bitlen_;
    std::array<uint8_t, kBlockSize> buffer_;
    size_t buflen_;
};

bool sha256_file_hex(const std::string &path, std::string &out_hex);
bool parse_sha256_token(const std::string &text, std::string &hex);
bool verify_policy_hash(const std::string &path, const std::string &expected, std::string &computed);
bool read_sha256_file(const std::string &path, std::string &hash);

} // namespace aegis
