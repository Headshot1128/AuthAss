#include "secureauth/client.hpp"
#include <deque>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <iostream>
#include <stdexcept>
using namespace secureauth;
struct Fake final : Transport {
    std::deque<HttpResponse> replies;
    int calls = 0;
    std::string last_url;
    HttpResponse Send(const std::string&, const std::string& url, const std::string&, const std::string&, const std::string&) override {
        last_url=url;
        ++calls;
        if (replies.empty()) throw std::runtime_error("Unexpected request");
        auto reply = replies.front(); replies.pop_front(); return reply;
    }
};
void check(bool value) { if (!value) throw std::runtime_error("Test failed"); }
HttpResponse token() {
    return {true, 200, "application/json", nlohmann::json({{"success", true},
        {"access_token", std::string(43, 'a')}, {"refresh_token", std::string(64, 'b')},
        {"expires_at", 9999999999LL}}).dump()};
}
int main() {
    {
        auto scoped = std::make_shared<Fake>();
        const std::string app = "00000000-0000-4000-8000-000000000002";
        Client application("https://auth.example.test","",scoped,app);
        check(application.Initialize());check(!application.SelectApplication(app));
        scoped->replies.push_back(token()); // Old servers cannot silently use the default app.
        check(application.Login("user","password").error == Error::InvalidResponse);
        check(scoped->last_url == "https://auth.example.test/v1/login?application_id="+app);
        auto reply=token();auto body=nlohmann::json::parse(reply.body);body["application_id"]=app;reply.body=body.dump();
        scoped->replies.push_back(reply);check(application.Login("user","password").success);
        Client bad("https://auth.example.test","",scoped,"bad\r\napplication");check(!bad.Initialize());
    }
    auto fake = std::make_shared<Fake>();
    Client client("https://auth.example.test", "", fake);
    check(!client.Login("user", "password").success);
    check(client.Initialize());
    check(!client.DownloadFile("file").success && fake->calls == 0);
    fake->replies.push_back({true, 401, "application/json", R"({"success":false,"error":"invalid_credentials"})"});
    check(!client.Login("user", "wrong password").success);
    check(client.GetState() == State::Unauthenticated);
    fake->replies.push_back({true, 409, "application/json", R"({"success":false})"});
    check(!client.Register("user", "password").success);
    check(!client.GetVariable("private").success);
    fake->replies.push_back({true, 201, "application/json", R"({"success":true})"});
    check(client.Register("user", "password").success);
    check(client.GetState() == State::Unauthenticated);
    fake->replies.push_back(token());
    check(client.Login("user", "password").success);
    fake->replies.push_back({true, 403, "application/json", R"({"success":false})"});
    check(client.DownloadFile("file").error == Error::PermissionDenied);
    fake->replies.push_back({true, 403, "application/json", R"({"success":false})"});
    check(!client.GetVariable("private").success);
    fake->replies.push_back({true, 401, "application/json", R"({"success":false,"error":"expired"})"});
    check(client.GetVariable("private").error == Error::Expired);
    check(client.GetState() == State::SessionExpired);
    fake->replies.push_back(token());
    check(client.RefreshSession().success);
    fake->replies.push_back({true, 401, "application/json", R"({"success":false,"error":"revoked"})"});
    check(!client.IsSessionValid() && client.GetState() == State::Revoked);
    for (auto response : {HttpResponse{}, HttpResponse{true,200,"application/json","garbage"},
                          HttpResponse{true,200,"application/json",R"({"success":true})"},
                          HttpResponse{true,200,"application/json",R"({"success":"true"})"}}) {
        fake->replies.push_back(response);
        check(!client.Login("user", "password").success);
        check(client.GetState() == State::Unauthenticated);
    }
    fake->replies.push_back(token()); check(client.Login("user", "password").success);
    const auto path = std::filesystem::temp_directory_path() / "secureauth-download-test.bin";
    const std::string original("MZ\0\r\n\x1a\xffsigned-content", 22);
    fake->replies.push_back({true, 200, "application/octet-stream", original});
    check(client.downloadfile("file", path.u8string()).success);
    {
        std::ifstream input(path, std::ios::binary);
        check(std::string(std::istreambuf_iterator<char>(input), {}) == original);
    }
    fake->replies.push_back({true, 403, "application/json", R"({"success":false})"});
    check(client.downloadfile("file", path.u8string()).error == Error::PermissionDenied);
    {
        std::ifstream input(path, std::ios::binary);
        check(std::string(std::istreambuf_iterator<char>(input), {}) == original);
    }
    fake->replies.push_back({true, 200, "application/octet-stream", original});
    check(client.downloadfile("file", path.u8string() + "/missing").error == Error::FileWriteFailure);
    std::filesystem::remove(path);
    fake->replies.push_back({});
    auto download = client.downloadfile("file");
    check(!download.success && download.bytes.empty());
    check(client.GetState() == State::Unauthenticated);
    // Exercise the actual curl transport: unreachable loopback TLS endpoint must fail closed.
    Client offline("https://127.0.0.1:1");
    check(offline.Initialize());
    check(offline.Login("user", "wrong password").error == Error::NetworkFailure);
    check(!offline.DownloadFile("file").success);
    Client insecure("http://localhost"); check(!insecure.Initialize());
    std::cout << "SDK failure and state tests passed\n";
}
