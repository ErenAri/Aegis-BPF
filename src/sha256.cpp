// cppcheck-suppress-file missingIncludeSystem
#include "sha256.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace aegis {

namespace {

constexpr uint32_t rotr(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32 - n));
}

constexpr uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

constexpr uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

constexpr uint32_t ep0(uint32_t x)
{
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

constexpr uint32_t ep1(uint32_t x)
{
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

constexpr uint32_t sig0(uint32_t x)
{
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

constexpr uint32_t sig1(uint32_t x)
{
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

constexpr uint32_t kRoundConstants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

constexpr std::array<uint32_t, 8> kInitialState = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

}  // namespace

Sha256::Sha256()
    : state_(kInitialState), bitlen_(0), buffer_{}, buflen_(0)
{
}

void Sha256::transform(const uint8_t data[kBlockSize])
{
    std::array<uint32_t, 64> m{};

    for (size_t i = 0; i < 16; ++i) {
        m[i] = (static_cast<uint32_t>(data[i * 4]) << 24) |
               (static_cast<uint32_t>(data[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(data[i * 4 + 2]) << 8) |
               (static_cast<uint32_t>(data[i * 4 + 3]));
    }
    for (size_t i = 16; i < 64; ++i) {
        m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];
    }

    uint32_t a = state_[0];
    uint32_t b = state_[1];
    uint32_t c = state_[2];
    uint32_t d = state_[3];
    uint32_t e = state_[4];
    uint32_t f = state_[5];
    uint32_t g = state_[6];
    uint32_t h = state_[7];

    for (size_t i = 0; i < 64; ++i) {
        uint32_t t1 = h + ep1(e) + ch(e, f, g) + kRoundConstants[i] + m[i];
        uint32_t t2 = ep0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(const uint8_t* data, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        buffer_[buflen_++] = data[i];
        if (buflen_ == kBlockSize) {
            transform(buffer_.data());
            bitlen_ += 512;
            buflen_ = 0;
        }
    }
}

void Sha256::update(const std::vector<uint8_t>& data)
{
    update(data.data(), data.size());
}

void Sha256::update(const std::string& data)
{
    update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::array<uint8_t, Sha256::kDigestSize> Sha256::finalize()
{
    size_t i = buflen_;

    if (buflen_ < 56) {
        buffer_[i++] = 0x80;
        while (i < 56) {
            buffer_[i++] = 0x00;
        }
    }
    else {
        buffer_[i++] = 0x80;
        while (i < kBlockSize) {
            buffer_[i++] = 0x00;
        }
        transform(buffer_.data());
        std::memset(buffer_.data(), 0, 56);
    }

    bitlen_ += buflen_ * 8;
    buffer_[63] = static_cast<uint8_t>(bitlen_);
    buffer_[62] = static_cast<uint8_t>(bitlen_ >> 8);
    buffer_[61] = static_cast<uint8_t>(bitlen_ >> 16);
    buffer_[60] = static_cast<uint8_t>(bitlen_ >> 24);
    buffer_[59] = static_cast<uint8_t>(bitlen_ >> 32);
    buffer_[58] = static_cast<uint8_t>(bitlen_ >> 40);
    buffer_[57] = static_cast<uint8_t>(bitlen_ >> 48);
    buffer_[56] = static_cast<uint8_t>(bitlen_ >> 56);
    transform(buffer_.data());

    std::array<uint8_t, kDigestSize> hash{};
    for (size_t j = 0; j < 4; ++j) {
        hash[j] = (state_[0] >> (24 - j * 8)) & 0xff;
        hash[j + 4] = (state_[1] >> (24 - j * 8)) & 0xff;
        hash[j + 8] = (state_[2] >> (24 - j * 8)) & 0xff;
        hash[j + 12] = (state_[3] >> (24 - j * 8)) & 0xff;
        hash[j + 16] = (state_[4] >> (24 - j * 8)) & 0xff;
        hash[j + 20] = (state_[5] >> (24 - j * 8)) & 0xff;
        hash[j + 24] = (state_[6] >> (24 - j * 8)) & 0xff;
        hash[j + 28] = (state_[7] >> (24 - j * 8)) & 0xff;
    }
    return hash;
}

std::string Sha256::finalize_hex()
{
    auto hash = finalize();
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : hash) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

std::string Sha256::hash_hex(const uint8_t* data, size_t len)
{
    Sha256 hasher;
    hasher.update(data, len);
    return hasher.finalize_hex();
}

std::string Sha256::hash_hex(const std::string& data)
{
    return hash_hex(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

bool sha256_file_hex(const std::string& path, std::string& out_hex)
{
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }

    Sha256 hasher;
    char buf[4096];
    while (in.good()) {
        in.read(buf, sizeof(buf));
        std::streamsize got = in.gcount();
        if (got > 0) {
            hasher.update(reinterpret_cast<const uint8_t*>(buf), static_cast<size_t>(got));
        }
    }
    if (!in.eof() && in.fail()) {
        return false;
    }
    out_hex = hasher.finalize_hex();
    return true;
}

bool parse_sha256_token(const std::string& text, std::string& hex)
{
    std::istringstream iss(text);
    std::string token;
    if (!(iss >> token)) {
        return false;
    }
    if (token.size() != 64) {
        return false;
    }
    if (!std::all_of(token.begin(), token.end(), [](unsigned char c) {
            return std::isxdigit(c);
        })) {
        return false;
    }
    std::transform(token.begin(), token.end(), token.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    hex = token;
    return true;
}

bool verify_policy_hash(const std::string& path, const std::string& expected, std::string& computed)
{
    if (!sha256_file_hex(path, computed)) {
        return false;
    }
    return constant_time_hex_compare(computed, expected);
}

bool read_sha256_file(const std::string& path, std::string& hash)
{
    std::ifstream in(path);
    if (!in.is_open()) {
        return false;
    }
    std::string line;
    if (!std::getline(in, line)) {
        return false;
    }
    return parse_sha256_token(line, hash);
}

bool constant_time_hex_compare(const std::string& a, const std::string& b)
{
    // Constant-time comparison to prevent timing side-channel attacks.
    // Both strings must be the same length for a valid comparison.
    if (a.size() != b.size()) {
        return false;
    }

    // Accumulate differences without early exit
    volatile unsigned char result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        // Normalize to lowercase for case-insensitive comparison
        unsigned char ca = static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(a[i])));
        unsigned char cb = static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(b[i])));
        result |= ca ^ cb;
    }
    return result == 0;
}

}  // namespace aegis
