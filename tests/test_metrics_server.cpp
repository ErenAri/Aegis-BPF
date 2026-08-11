// Tests for the optional Prometheus metrics HTTP endpoint. The server layer is
// exercised with a stub callback over a real loopback socket — no BPF/kernel.
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <string>

#include "metrics_server.hpp"

using namespace aegis;

namespace {

// Minimal blocking HTTP/1.0 GET against 127.0.0.1:port; returns the full response.
std::string http_get(uint16_t port, const std::string& path)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return "";
    }
    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return "";
    }
    const std::string req = "GET " + path + " HTTP/1.0\r\n\r\n";
    send(fd, req.c_str(), req.size(), 0);

    std::string resp;
    char buf[1024];
    ssize_t n;
    while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) {
        resp.append(buf, static_cast<size_t>(n));
    }
    close(fd);
    return resp;
}

// Bind an ephemeral port, then hand it to the server via SO_REUSEADDR.
uint16_t pick_free_port()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(fd);
        return 0;
    }
    socklen_t len = sizeof(addr);
    if (getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr), &len) != 0) {
        close(fd);
        return 0;
    }
    uint16_t port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

} // namespace

TEST(MetricsServer, ParseBindAddr)
{
    std::string host;
    uint16_t port = 0;

    ASSERT_TRUE(MetricsServer::parse_bind_addr("127.0.0.1:9635", host, port));
    EXPECT_EQ(host, "127.0.0.1");
    EXPECT_EQ(port, 9635);

    ASSERT_TRUE(MetricsServer::parse_bind_addr(":8080", host, port));
    EXPECT_TRUE(host.empty()); // all interfaces
    EXPECT_EQ(port, 8080);

    EXPECT_FALSE(MetricsServer::parse_bind_addr("no-port", host, port));
    EXPECT_FALSE(MetricsServer::parse_bind_addr("127.0.0.1:", host, port));
    EXPECT_FALSE(MetricsServer::parse_bind_addr("127.0.0.1:0", host, port));
    EXPECT_FALSE(MetricsServer::parse_bind_addr("127.0.0.1:70000", host, port));
    EXPECT_FALSE(MetricsServer::parse_bind_addr("127.0.0.1:abc", host, port));
}

TEST(MetricsServer, ServesMetricsHealthAnd404)
{
    const uint16_t port = pick_free_port();
    MetricsServer::Config cfg;
    cfg.bind_addr = "127.0.0.1:" + std::to_string(port);
    MetricsServer server(cfg);
    server.set_metrics_callback([]() { return "aegisbpf_up 1\n"; });
    ASSERT_TRUE(server.start());

    // /metrics
    std::string m = http_get(port, "/metrics");
    EXPECT_NE(m.find("200 OK"), std::string::npos);
    EXPECT_NE(m.find("text/plain; version=0.0.4"), std::string::npos);
    EXPECT_NE(m.find("aegisbpf_up 1"), std::string::npos);

    // /healthz
    std::string h = http_get(port, "/healthz");
    EXPECT_NE(h.find("200 OK"), std::string::npos);
    EXPECT_NE(h.find("ok"), std::string::npos);

    // unknown path
    std::string nf = http_get(port, "/nope");
    EXPECT_NE(nf.find("404 Not Found"), std::string::npos);

    server.stop();
}

TEST(MetricsServer, MetricsUnavailableWithoutCallback)
{
    const uint16_t port = pick_free_port();
    MetricsServer::Config cfg;
    cfg.bind_addr = "127.0.0.1:" + std::to_string(port);
    MetricsServer server(cfg);
    // no callback set
    ASSERT_TRUE(server.start());

    std::string m = http_get(port, "/metrics");
    EXPECT_NE(m.find("503"), std::string::npos);

    server.stop();
}

TEST(MetricsServer, RejectsNonGet)
{
    const uint16_t port = pick_free_port();
    MetricsServer::Config cfg;
    cfg.bind_addr = "127.0.0.1:" + std::to_string(port);
    MetricsServer server(cfg);
    server.set_metrics_callback([]() { return "x 1\n"; });
    ASSERT_TRUE(server.start());

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    ASSERT_EQ(connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)), 0);
    const std::string req = "POST /metrics HTTP/1.0\r\n\r\n";
    send(fd, req.c_str(), req.size(), 0);
    std::string resp;
    char buf[512];
    ssize_t n;
    while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) {
        resp.append(buf, static_cast<size_t>(n));
    }
    close(fd);
    EXPECT_NE(resp.find("405"), std::string::npos);

    server.stop();
}
