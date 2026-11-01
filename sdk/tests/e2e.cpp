#include "secureauth/client.hpp"
#include <cstdlib>
#include <iostream>
#include <stdexcept>
using namespace secureauth;
void check(bool value) { if (!value) throw std::runtime_error("TLS integration test failed"); }
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    auto tls = std::make_shared<CurlTransport>(argv[2]);
    Client client(argv[1], "", tls);
    check(client.Initialize());
    const std::string password = "correct horse battery staple";
    check(!client.Login("alice", "incorrect password").success);
    check(!client.DownloadFile("protected-file").success);
    check(!client.Register("alice", password).success);
    check(client.GetState() == State::Unauthenticated);
    check(client.Register("cpp-created", password).success);
    check(client.GetState() == State::Unauthenticated);
    check(client.Login("alice", password).success);
    check(client.IsSessionValid());
    auto variable = client.GetVariable("premium_feature");
    check(variable.success && variable.value == "enabled");
    check(!client.GetVariable("secret").success);
    check(!client.DownloadFile("secret-file").success);
    auto file = client.DownloadFile("protected-file");
    check(file.success && std::string(file.bytes.begin(), file.bytes.end()) == std::string("private\0payload", 15));
    check(client.RefreshSession().success);
    check(client.IsSessionValid());
    check(client.Logout().success);
    check(!client.GetVariable("premium_feature").success);
    // An untrusted self-signed server must be rejected by the default transport.
    Client untrusted(argv[1]);
    check(untrusted.Initialize());
    check(untrusted.Login("alice", password).error == Error::NetworkFailure);
    std::cout << "C++ SDK to FastAPI TLS integration passed\n";
}
