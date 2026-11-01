#include "secureauth/client.hpp"
#include <curl/curl.h>
#include <algorithm>
#include <cctype>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <utility>

namespace secureauth {
namespace {
constexpr std::size_t kMaxResponse = 64 * 1024 * 1024;
bool InitCurl() {
    static const bool initialized = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
    return initialized;
}
void Wipe(std::string& value) {
    // Best effort only: allocator/library copies cannot be reliably erased here.
    volatile char* p = value.empty() ? nullptr : &value[0];
    for (std::size_t i = 0; i < value.size(); ++i) p[i] = 0;
    value.clear();
}
bool SafeHeader(const std::string& value) {
    return value.find_first_of("\r\n") == std::string::npos && value.find('\0') == std::string::npos;
}
std::size_t Write(char* data, std::size_t size, std::size_t count, void* context) {
    auto& body = *static_cast<std::string*>(context);
    if (size && count > kMaxResponse / size) return 0;
    auto bytes = size * count;
    if (body.size() > kMaxResponse - bytes) return 0;
    try { body.append(data, bytes); } catch (...) { return 0; }
    return bytes;
}
std::string Encode(const std::string& value) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : value) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-') out += char(c);
        else { out += '%'; out += hex[c >> 4]; out += hex[c & 15]; }
    }
    return out;
}
bool JsonType(const std::string& type) {
    return type == "application/json" || type.rfind("application/json;", 0) == 0;
}
}

CurlTransport::CurlTransport(std::string ca) : ca_bundle_(std::move(ca)) {}
HttpResponse CurlTransport::Send(const std::string& method, const std::string& url,
        const std::string& body, const std::string& bearer, const std::string& hardware) {
    HttpResponse response;
    if (!InitCurl() || !SafeHeader(bearer) || !SafeHeader(hardware)) return response;
    auto* curl = curl_easy_init();
    if (!curl) return response;
    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json, application/octet-stream");
    if (!bearer.empty()) headers = curl_slist_append(headers, ("Authorization: Bearer " + bearer).c_str());
    if (!hardware.empty()) headers = curl_slist_append(headers, ("X-Hardware-ID: " + hardware).c_str());
    bool configured = true;
    auto set = [&](CURLoption opt, auto value) { if (curl_easy_setopt(curl, opt, value) != CURLE_OK) configured = false; };
    set(CURLOPT_URL, url.c_str());
    set(CURLOPT_PROTOCOLS_STR, "https");
    set(CURLOPT_REDIR_PROTOCOLS_STR, "https");
    set(CURLOPT_FOLLOWLOCATION, 0L);
    set(CURLOPT_SSL_VERIFYPEER, 1L);
    set(CURLOPT_SSL_VERIFYHOST, 2L);
    set(CURLOPT_SSLVERSION, long(CURL_SSLVERSION_TLSv1_2));
    set(CURLOPT_PROXY_SSL_VERIFYPEER, 1L);
    set(CURLOPT_PROXY_SSL_VERIFYHOST, 2L);
    set(CURLOPT_NOSIGNAL, 1L);
    set(CURLOPT_CONNECTTIMEOUT, 5L);
    set(CURLOPT_TIMEOUT, 120L);
    set(CURLOPT_LOW_SPEED_LIMIT, 128L);
    set(CURLOPT_LOW_SPEED_TIME, 15L);
    set(CURLOPT_HTTPHEADER, headers);
    set(CURLOPT_CUSTOMREQUEST, method.c_str());
    set(CURLOPT_WRITEFUNCTION, &Write);
    set(CURLOPT_WRITEDATA, &response.body);
    if (!ca_bundle_.empty()) set(CURLOPT_CAINFO, ca_bundle_.c_str());
    if (method != "GET") {
        set(CURLOPT_POSTFIELDS, body.c_str());
        set(CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
    }
    if (configured && curl_easy_perform(curl) == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);
        char* type = nullptr;
        curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &type);
        if (type) response.content_type = type;
        response.network_ok = true;
    } else response.body.clear();
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
}

Client::Client(std::string base, std::string hardware, std::shared_ptr<Transport> transport, std::string application)
    : base_(std::move(base)), hardware_(std::move(hardware)), application_id_(std::move(application)), transport_(std::move(transport)) {}
bool Client::SelectApplication(std::string application) {
    if(state_ != State::Uninitialized) return false;
    if(!application.empty()) {
        if(application.size()!=36) return false;
        for(std::size_t i=0;i<application.size();++i)
            if(i==8||i==13||i==18||i==23) { if(application[i]!='-')return false; }
            else if(!std::isxdigit(static_cast<unsigned char>(application[i])))return false;
    }
    std::transform(application.begin(),application.end(),application.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
    application_id_=std::move(application);return true;
}
Client::~Client() { Clear(State::Uninitialized); }
void Client::Clear(State state) { Wipe(access_); Wipe(refresh_); state_ = state; }
bool Client::Initialize() {
    Clear(State::Uninitialized);
    if(!SelectApplication(application_id_)) return false;
    if (!InitCurl() || !transport_ || !SafeHeader(hardware_) || hardware_.size() > 256) return false;
    if (!hardware_.empty() && hardware_.size() < 16) return false;
    auto* url = curl_url();
    if (!url) return false;
    bool valid = curl_url_set(url, CURLUPART_URL, base_.c_str(), 0) == CURLUE_OK;
    char *scheme = nullptr, *host = nullptr, *user = nullptr, *query = nullptr, *fragment = nullptr, *path = nullptr;
    curl_url_get(url, CURLUPART_SCHEME, &scheme, 0);
    curl_url_get(url, CURLUPART_HOST, &host, 0);
    curl_url_get(url, CURLUPART_USER, &user, 0);
    curl_url_get(url, CURLUPART_QUERY, &query, 0);
    curl_url_get(url, CURLUPART_FRAGMENT, &fragment, 0);
    curl_url_get(url, CURLUPART_PATH, &path, 0);
    valid = valid && scheme && std::string(scheme) == "https" && host && *host && !user && !query && !fragment
            && path && std::string(path) == "/" && base_.find('\0') == std::string::npos;
    for (auto* p : {scheme, host, user, query, fragment, path}) curl_free(p);
    curl_url_cleanup(url);
    if (!valid) return false;
    while (!base_.empty() && base_.back() == '/') base_.pop_back();
    state_ = State::Unauthenticated;
    return true;
}
HttpResponse Client::Request(const std::string& method, const std::string& path, const nlohmann::json& body) {
    const auto scoped_path = application_id_.empty() ? path : path + (path.find('?') == std::string::npos ? "?" : "&") + "application_id=" + Encode(application_id_);
    try { return transport_->Send(method, base_ + scoped_path, body.is_null() ? "" : body.dump(), access_, hardware_); }
    catch (...) { return {}; }
}
Result Client::Check(const HttpResponse& response, bool json_required) {
    if (!response.network_ok) { Clear(State::Unauthenticated); return {false, Error::NetworkFailure}; }
    nlohmann::json json;
    if (JsonType(response.content_type)) json = nlohmann::json::parse(response.body, nullptr, false);
    std::string error;
    if (json.is_object() && json.contains("error") && json["error"].is_string()) error = json["error"].get<std::string>();
    if (response.status == 401) {
        auto state = error == "expired" ? State::SessionExpired : error == "revoked" ? State::Revoked : State::Unauthenticated;
        // Retain refresh only on access expiration, for explicit refresh.
        if (state == State::SessionExpired) { Wipe(access_); state_ = state; }
        else Clear(state);
        return {false, state == State::SessionExpired ? Error::Expired : state == State::Revoked ? Error::Revoked : Error::AuthenticationFailed};
    }
    if (response.status == 403) return {false, Error::PermissionDenied};
    if (response.status == 429) return {false, Error::RateLimited};
    if (response.status >= 500) { Clear(State::Unauthenticated); return {false, Error::ServerError}; }
    if (response.status < 200 || response.status >= 300) return {false, Error::InvalidInput};
    if (json_required && (!json.is_object() || !json.contains("success") || !json["success"].is_boolean() || !json["success"].get<bool>())) {
        Clear(State::Unauthenticated); return {false, Error::InvalidResponse};
    }
    return {true, Error::None};
}
Result Client::AcceptTokens(const HttpResponse& response) {
    auto result = Check(response);
    if (!result.success) return result;
    auto json = nlohmann::json::parse(response.body, nullptr, false);
    if (!application_id_.empty() && (!json.contains("application_id") ||
        !json["application_id"].is_string() || json["application_id"] != application_id_)) {
        Clear(State::Unauthenticated); return {false, Error::InvalidResponse};
    }
    auto valid_token = [&](const char* key) {
        if (!json.contains(key) || !json[key].is_string()) return false;
        auto s = json[key].get<std::string>();
        return s.size() >= 32 && s.size() <= 256 && std::all_of(s.begin(), s.end(), [](unsigned char c) {
            return std::isalnum(c) || c == '-' || c == '_';
        });
    };
    if (!valid_token("access_token") || !valid_token("refresh_token") ||
        !json.contains("expires_at") || !json["expires_at"].is_number_integer() ||
        json["expires_at"] <= static_cast<long long>(std::time(nullptr))) {
        Clear(State::Unauthenticated); return {false, Error::InvalidResponse};
    }
    access_ = json["access_token"].get<std::string>();
    refresh_ = json["refresh_token"].get<std::string>();
    state_ = State::Authenticated;
    return result;
}
AuthResult Client::Register(const std::string& username, const std::string& password) {
    if (state_ == State::Uninitialized) return {false, Error::NotInitialized};
    Clear(State::Unauthenticated);
    return Check(Request("POST", "/v1/register", {{"username", username}, {"password", password}}));
}
AuthResult Client::RegisterWithLicense(const std::string& username, const std::string& password,
                                    const std::string& license_key) {
    if (state_ == State::Uninitialized) return {false, Error::NotInitialized};
    Clear(State::Unauthenticated);
    if (hardware_.empty() || license_key.empty()) return {false, Error::InvalidInput};
    return Check(Request("POST", "/v1/register", {{"username", username}, {"password", password},
                 {"license_key", license_key}, {"hardware_id", hardware_}}));
}
AuthResult Client::Login(const std::string& username, const std::string& password) {
    if (state_ == State::Uninitialized) return {false, Error::NotInitialized};
    Clear(State::Unauthenticated);
    nlohmann::json body = {{"username", username}, {"password", password}};
    if (!hardware_.empty()) body["hardware_id"] = hardware_;
    return AcceptTokens(Request("POST", "/v1/login", body));
}
AuthResult Client::RefreshSession() {
    if (state_ == State::Uninitialized) return {false, Error::NotInitialized};
    if (refresh_.empty()) return {false, Error::AuthenticationFailed};
    nlohmann::json body = {{"refresh_token", refresh_}};
    if (!hardware_.empty()) body["hardware_id"] = hardware_;
    auto response = Request("POST", "/v1/refresh", body);
    auto result = AcceptTokens(response);
    if (!result.success) Clear(State::Unauthenticated);
    return result;
}
Result Client::RequireSession() {
    if (state_ == State::Uninitialized) return {false, Error::NotInitialized};
    if (state_ != State::Authenticated || access_.empty())
        return {false, state_ == State::SessionExpired ? Error::Expired : state_ == State::Revoked ? Error::Revoked : Error::AuthenticationFailed};
    return {true, Error::None};
}
bool Client::IsSessionValid() {
    if (!RequireSession().success) return false;
    return Check(Request("GET", "/v1/session")).success;
}
VariableResult Client::GetVariable(const std::string& name) {
    VariableResult out;
    auto result = RequireSession();
    if (result.success) {
        auto response = Request("GET", "/v1/variables/" + Encode(name));
        result = Check(response);
        if (result.success) {
            auto json = nlohmann::json::parse(response.body, nullptr, false);
            if (json.contains("value") && json["value"].is_string()) out.value = json["value"].get<std::string>();
            else { Clear(State::Unauthenticated); result = {false, Error::InvalidResponse}; }
        }
    }
    static_cast<Result&>(out) = result;
    return out;
}
DownloadResult Client::DownloadFile(const std::string& id) {
    DownloadResult out;
    auto result = RequireSession();
    if (result.success) {
        auto response = Request("GET", "/v1/files/" + Encode(id) + "/content");
        result = Check(response, false);
        if (result.success) {
            if (response.status != 200 || response.content_type != "application/octet-stream") {
                Clear(State::Unauthenticated); result = {false, Error::InvalidResponse};
            } else out.bytes.assign(response.body.begin(), response.body.end());
        }
    }
    static_cast<Result&>(out) = result;
    return out;
}
Result Client::DownloadFile(const std::string& id, const std::string& path) {
    auto result = RequireSession();
    if (!result.success) return result;
    if (id.empty() || path.empty() || path.find('\0') != std::string::npos)
        return {false, Error::InvalidInput};
    auto response = Request("GET", "/v1/files/" + Encode(id) + "/content");
    result = Check(response, false);
    if (!result.success) return result;
    if (response.status != 200 || response.content_type != "application/octet-stream") {
        Clear(State::Unauthenticated);
        return {false, Error::InvalidResponse};
    }
    try {
        std::ofstream output(std::filesystem::u8path(path), std::ios::binary | std::ios::trunc);
        if (!output) return {false, Error::FileWriteFailure};
        output.write(response.body.data(), static_cast<std::streamsize>(response.body.size()));
        output.close();
        if (!output) return {false, Error::FileWriteFailure};
    } catch (...) { return {false, Error::FileWriteFailure}; }
    return {true, Error::None};
}
Result Client::ActivateLicense(const std::string& key) {
    auto result = RequireSession();
    return result.success ? Check(Request("POST", "/v1/licenses/activate", {{"key", key}})) : result;
}
Result Client::Logout() {
    auto result = RequireSession();
    if (result.success) result = Check(Request("POST", "/v1/logout", nlohmann::json::object()));
    Clear(state_ == State::Uninitialized ? State::Uninitialized : State::Unauthenticated);
    return result;
}
}
