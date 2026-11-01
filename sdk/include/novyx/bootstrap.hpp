#pragma once
#ifndef _WIN64
#error The NOVYX bootstrap SDK currently requires 64-bit Windows.
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cstring>
#include <string>
#include <vector>
#include "abi.h"
#include "hardware.hpp"

namespace novyx {
enum class Error { None, NotInitialized, AuthenticationFailed, Expired, Revoked,
    PermissionDenied, NetworkFailure, InvalidResponse, ServerError, InvalidInput,
    RateLimited, FileWriteFailure };
struct Result { bool success = false; Error error = Error::NotInitialized; };
struct VariableResult : Result { std::string value; };
struct DownloadResult : Result { std::vector<unsigned char> bytes; };

// Build marker used by the panel to reject EXEs built against the static SDK.
inline volatile const char bootstrap_sdk_marker[] = "NOVYX_DLL_SDK_V1";

class Client {
    HMODULE module_ = nullptr;
    const novyx_api_v1* api_ = nullptr;
    void* context_ = nullptr;

    novyx_reply_v1 Invoke(int operation, const std::string& a = {},
                         const std::string& b = {}, const std::string& c = {}) {
        if (!context_) return {0, static_cast<int>(Error::NotInitialized), nullptr, 0, nullptr};
        return api_->invoke(context_, operation, a.c_str(), b.c_str(), c.c_str());
    }
    void Release(novyx_reply_v1& reply) { if (api_) api_->release(&reply); }
    Result Call(int operation, const std::string& a = {}, const std::string& b = {},
                const std::string& c = {}) {
        auto reply = Invoke(operation, a, b, c);
        Result result{reply.success != 0, static_cast<Error>(reply.error)};
        Release(reply);
        return result;
    }
public:
    explicit Client(const std::string& server, const std::string& hardware = {},
                    const std::string& ca_bundle = {}, const std::string& application_id = {}) {
        // Volatile read preserves the SDK marker even in optimized builds.
        if (bootstrap_sdk_marker[0] != 'N') return;
        wchar_t executable[32768] = {};
        DWORD length = GetModuleFileNameW(nullptr, executable, 32768);
        if (!length || length >= 32768) return;
        std::wstring path(executable, length);
        auto slash = path.find_last_of(L"\\/");
        if (slash == std::wstring::npos) return;
        path.resize(slash + 1);
        path += L"novyx_auth.dll";
        module_ = LoadLibraryExW(path.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module_) return;
        using Getter = const novyx_api_v1* (*)();
        auto address = GetProcAddress(module_, "novyx_get_api_v1");
        Getter getter = nullptr;
        static_assert(sizeof(getter) == sizeof(address));
        std::memcpy(&getter, &address, sizeof(getter));
        if (!getter) return;
        auto table = getter();
        if (!table || table->version != 1 || table->size != sizeof(novyx_api_v1) ||
            !table->create || !table->destroy || !table->invoke || !table->release) return;
        api_ = table;
        context_ = api_->create(server.c_str(), hardware.c_str(), ca_bundle.c_str());
        if (context_ && !application_id.empty() && !Call(NOVYX_SELECT_APPLICATION,application_id).success) {
            api_->destroy(context_); context_ = nullptr;
        }
    }
    ~Client() {
        if (context_) api_->destroy(context_);
        if (module_) FreeLibrary(module_);
    }
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    bool Initialize() { return Call(NOVYX_INITIALIZE).success; }
    Result Register(const std::string& u, const std::string& p) { return Call(NOVYX_REGISTER,u,p); }
    Result RegisterWithLicense(const std::string& u, const std::string& p, const std::string& k) { return Call(NOVYX_REGISTER_LICENSE,u,p,k); }
    Result Login(const std::string& u, const std::string& p) { return Call(NOVYX_LOGIN,u,p); }
    Result RefreshSession() { return Call(NOVYX_REFRESH); }
    bool IsSessionValid() { return Call(NOVYX_SESSION).success; }
    Result ActivateLicense(const std::string& key) { return Call(NOVYX_ACTIVATE,key); }
    Result Logout() { return Call(NOVYX_LOGOUT); }
    Result DownloadFile(const std::string& id, const std::string& path) { return Call(NOVYX_DOWNLOAD_DISK,id,path); }
    Result downloadfile(const std::string& id, const std::string& path) { return DownloadFile(id,path); }
    VariableResult GetVariable(const std::string& name) {
        auto reply = Invoke(NOVYX_VARIABLE,name);
        // Always release DLL-owned memory, including when a local allocation throws.
        struct Guard { Client* client; novyx_reply_v1* reply; ~Guard(){client->Release(*reply);} } guard{this,&reply};
        VariableResult result;
        result.success = reply.success != 0; result.error = static_cast<Error>(reply.error);
        if (reply.data && reply.size) result.value.assign(reinterpret_cast<const char*>(reply.data),reply.size);
        return result;
    }
    DownloadResult DownloadFile(const std::string& id) {
        auto reply = Invoke(NOVYX_DOWNLOAD,id);
        struct Guard { Client* client; novyx_reply_v1* reply; ~Guard(){client->Release(*reply);} } guard{this,&reply};
        DownloadResult result;
        result.success = reply.success != 0; result.error = static_cast<Error>(reply.error);
        if (reply.data && reply.size) result.bytes.assign(reply.data,reply.data+reply.size);
        return result;
    }
    DownloadResult downloadfile(const std::string& id) { return DownloadFile(id); }
};
}
