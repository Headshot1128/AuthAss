#pragma once
#include <cstddef>
#include <memory>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace secureauth {
enum class State { Uninitialized, Unauthenticated, Authenticated, SessionExpired, Revoked };
enum class Error { None, NotInitialized, AuthenticationFailed, Expired, Revoked,
                   PermissionDenied, NetworkFailure, InvalidResponse, ServerError,
                   InvalidInput, RateLimited, FileWriteFailure };
struct Result {
    bool success = false;
    Error error = Error::AuthenticationFailed;
};
using AuthResult = Result;
struct VariableResult : Result { std::string value; };
struct DownloadResult : Result { std::vector<unsigned char> bytes; };
struct HttpResponse {
    bool network_ok = false;
    long status = 0;
    std::string content_type;
    std::string body;
};
// Injection is intended for tests. Production callers should use the default TLS transport.
class Transport {
public:
    virtual ~Transport() = default;
    virtual HttpResponse Send(const std::string& method, const std::string& url,
        const std::string& body, const std::string& bearer, const std::string& hardware) = 0;
};
class CurlTransport final : public Transport {
public:
    explicit CurlTransport(std::string ca_bundle = {});
    HttpResponse Send(const std::string&, const std::string&, const std::string&,
                      const std::string&, const std::string&) override;
private:
    std::string ca_bundle_;
};

// One instance per thread; tokens remain in memory. No implicit offline authorization.
class Client {
public:
    explicit Client(std::string base_url, std::string hardware_id = {},
                    std::shared_ptr<Transport> transport = std::make_shared<CurlTransport>(),
                    std::string application_id = {});
    ~Client();
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    bool Initialize();
    bool SelectApplication(std::string application_id);
    AuthResult Register(const std::string& username, const std::string& password);
    AuthResult RegisterWithLicense(const std::string& username, const std::string& password,
                                  const std::string& license_key);
    AuthResult Login(const std::string& username, const std::string& password);
    AuthResult RefreshSession();
    bool IsSessionValid();
    VariableResult GetVariable(const std::string& name);
    DownloadResult DownloadFile(const std::string& file_id);
    DownloadResult downloadfile(const std::string& file_id) { return DownloadFile(file_id); }
    // Saves the original binary content unchanged; no caller-side byte conversion.
    Result DownloadFile(const std::string& file_id, const std::string& path);
    Result downloadfile(const std::string& file_id, const std::string& path) { return DownloadFile(file_id, path); }
    Result ActivateLicense(const std::string& key);
    Result Logout();
    State GetState() const { return state_; }
private:
    std::string base_, hardware_, access_, refresh_, application_id_;
    std::shared_ptr<Transport> transport_;
    State state_ = State::Uninitialized;
    void Clear(State state);
    HttpResponse Request(const std::string& method, const std::string& path,
                         const nlohmann::json& body = nullptr);
    Result Check(const HttpResponse& response, bool json_required = true);
    Result AcceptTokens(const HttpResponse& response);
    Result RequireSession();
};
}
