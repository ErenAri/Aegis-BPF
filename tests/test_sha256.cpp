// cppcheck-suppress-file missingIncludeSystem
// cppcheck-suppress-file missingInclude
// cppcheck-suppress-file syntaxError
#include <gtest/gtest.h>

#include "sha256.hpp"

namespace aegis {
namespace {

TEST(Sha256Test, EmptyString)
{
    // SHA256 of empty string
    std::string hash = Sha256::hash_hex("");
    EXPECT_EQ(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Sha256Test, HelloWorld)
{
    // SHA256 of "hello world"
    std::string hash = Sha256::hash_hex("hello world");
    EXPECT_EQ(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
}

TEST(Sha256Test, SingleCharacter)
{
    // SHA256 of "a"
    std::string hash = Sha256::hash_hex("a");
    EXPECT_EQ(hash, "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
}

TEST(Sha256Test, LongString)
{
    // SHA256 of a longer string
    std::string input(1000, 'x');
    std::string hash = Sha256::hash_hex(input);
    // Just verify it's 64 hex characters
    EXPECT_EQ(hash.length(), 64u);
    for (char c : hash) {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
}

TEST(Sha256Test, IncrementalUpdate)
{
    Sha256 hasher;
    hasher.update("hello");
    hasher.update(" ");
    hasher.update("world");
    std::string hash = hasher.finalize_hex();
    EXPECT_EQ(hash, Sha256::hash_hex("hello world"));
}

TEST(Sha256Test, BinaryData)
{
    std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0x03};
    Sha256 hasher;
    hasher.update(data);
    std::string hash = hasher.finalize_hex();
    EXPECT_EQ(hash.length(), 64u);
}

TEST(ParseSha256TokenTest, ValidToken)
{
    std::string hex;
    EXPECT_TRUE(parse_sha256_token("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex));
    EXPECT_EQ(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(ParseSha256TokenTest, UppercaseToken)
{
    std::string hex;
    EXPECT_TRUE(parse_sha256_token("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", hex));
    EXPECT_EQ(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(ParseSha256TokenTest, WithWhitespace)
{
    std::string hex;
    EXPECT_TRUE(parse_sha256_token("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b9"
                                   "34ca495991b7852b855  filename.txt",
                                   hex));
    EXPECT_EQ(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(ParseSha256TokenTest, TooShort)
{
    std::string hex;
    EXPECT_FALSE(parse_sha256_token("e3b0c44298fc1c149afbf4c8996fb924", hex));
}

TEST(ParseSha256TokenTest, InvalidCharacters)
{
    std::string hex;
    EXPECT_FALSE(parse_sha256_token("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85g", hex));
}

TEST(ParseSha256TokenTest, EmptyString)
{
    std::string hex;
    EXPECT_FALSE(parse_sha256_token("", hex));
}

} // namespace
} // namespace aegis
