// cppcheck-suppress-file missingIncludeSystem
// End-to-end tests for the node-local control socket (SocketApiServer).
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <string>
#include <thread>

#include "socket_api.hpp"

namespace {

std::string test_socket_path()
{
    return "/tmp/aegis-api-test-" + std::to_string(getpid()) + ".sock";
}

// Connect, send one request line, read the reply up to the "\n\n" delimiter.
std::string round_trip(const std::string& path, const std::string& request)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    EXPECT_GE(fd, 0);
    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return "<connect-failed>";
    }
    std::string line = request + "\n";
    send(fd, line.c_str(), line.size(), 0);

    std::string reply;
    char buf[512];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0)
            break;
        reply.append(buf, static_cast<size_t>(n));
        if (reply.find("\n\n") != std::string::npos)
            break;
    }
    close(fd);
    return reply;
}

class SocketApiTest : public ::testing::Test {
  protected:
    void SetUp() override
    {
        cfg_.socket_path = test_socket_path();
        // Authorize this test process's own uid so control ops are exercisable
        // without running the suite as root.
        cfg_.control_uid = getuid();
    }
    void TearDown() override
    {
        if (server_)
            server_->stop();
        unlink(cfg_.socket_path.c_str());
    }
    aegis::SocketApiServer::Config cfg_;
    std::unique_ptr<aegis::SocketApiServer> server_;
};

TEST_F(SocketApiTest, HealthIsAlwaysAvailable)
{
    server_ = std::make_unique<aegis::SocketApiServer>(cfg_);
    ASSERT_TRUE(server_->start());
    std::string reply = round_trip(cfg_.socket_path, "GET /health");
    EXPECT_NE(reply.find("\"status\":\"ok\""), std::string::npos);
}

TEST_F(SocketApiTest, ControlRoutesVerbAndArgToCallback)
{
    std::string got_verb, got_arg;
    server_ = std::make_unique<aegis::SocketApiServer>(cfg_);
    server_->set_control_callback([&](const std::string& verb, const std::string& arg) {
        got_verb = verb;
        got_arg = arg;
        return R"({"status":"ok"})";
    });
    ASSERT_TRUE(server_->start());

    std::string reply = round_trip(cfg_.socket_path, "POST /block/add /var/tmp/evil bin");
    EXPECT_EQ(got_verb, "/block/add");
    EXPECT_EQ(got_arg, "/var/tmp/evil bin"); // argument may contain spaces (paths)
    EXPECT_NE(reply.find("\"status\":\"ok\""), std::string::npos);
}

TEST_F(SocketApiTest, ControlDisabledWhenNoCallbackSet)
{
    server_ = std::make_unique<aegis::SocketApiServer>(cfg_);
    ASSERT_TRUE(server_->start()); // no control callback registered
    std::string reply = round_trip(cfg_.socket_path, "POST /block/clear");
    EXPECT_NE(reply.find("control not enabled"), std::string::npos);
}

TEST_F(SocketApiTest, ControlRejectedForUnauthorizedPeerUid)
{
    bool called = false;
    cfg_.control_uid = getuid() + 1; // a uid this process does NOT have
    server_ = std::make_unique<aegis::SocketApiServer>(cfg_);
    server_->set_control_callback([&](const std::string&, const std::string&) {
        called = true;
        return R"({"status":"ok"})";
    });
    ASSERT_TRUE(server_->start());

    std::string reply = round_trip(cfg_.socket_path, "POST /block/add /etc/shadow");
    EXPECT_NE(reply.find("forbidden"), std::string::npos);
    EXPECT_FALSE(called); // callback must not run for an unauthorized peer
}

TEST_F(SocketApiTest, UnknownVerbReturnsError)
{
    server_ = std::make_unique<aegis::SocketApiServer>(cfg_);
    server_->set_control_callback([&](const std::string& verb, const std::string&) {
        if (verb == "/block/add")
            return std::string(R"({"status":"ok"})");
        return std::string(R"({"error":"unknown control verb"})");
    });
    ASSERT_TRUE(server_->start());
    std::string reply = round_trip(cfg_.socket_path, "POST /bogus/verb x");
    EXPECT_NE(reply.find("unknown control verb"), std::string::npos);
}

} // namespace
