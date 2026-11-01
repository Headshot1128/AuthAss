// Keep the example's UI and authentication implementation inside the DLL.
#define main novyx_example_main
#include "../examples/main.cpp"
#undef main
#include "novyx/abi.h"

namespace {
using secureauth::Client;
using secureauth::Error;
using secureauth::Result;
void* Create(const char* server, const char* hardware, const char* ca) noexcept {
    try {
        return new Client(server,hardware,std::make_shared<secureauth::CurlTransport>(ca));
    } catch (...) { return nullptr; }
}
void Destroy(void* context) noexcept { delete static_cast<Client*>(context); }
novyx_reply_v1 Invoke(void* context, int operation, const char* a, const char* b, const char* c) noexcept {
    try {
        if (!context || !a || !b || !c) return {0,static_cast<int>(Error::InvalidInput),nullptr,0,nullptr};
        auto& client = *static_cast<Client*>(context);
        Result result;
        std::vector<unsigned char> data;
        switch (operation) {
        case NOVYX_SELECT_APPLICATION: result={client.SelectApplication(a),Error::InvalidInput};if(result.success)result.error=Error::None;break;
        case NOVYX_INITIALIZE: result = {client.Initialize(),Error::InvalidInput}; if(result.success)result.error=Error::None; break;
        case NOVYX_REGISTER: result = client.Register(a,b); break;
        case NOVYX_REGISTER_LICENSE: result = client.RegisterWithLicense(a,b,c); break;
        case NOVYX_LOGIN: result = client.Login(a,b); break;
        case NOVYX_REFRESH: result = client.RefreshSession(); break;
        case NOVYX_SESSION: result = {client.IsSessionValid(),Error::AuthenticationFailed}; if(result.success)result.error=Error::None; break;
        case NOVYX_VARIABLE: { auto value=client.GetVariable(a); result=value; if(value.success)data.assign(value.value.begin(),value.value.end()); break; }
        case NOVYX_DOWNLOAD: { auto file=client.DownloadFile(a); result=file; if(file.success)data=std::move(file.bytes); break; }
        case NOVYX_DOWNLOAD_DISK: result=client.DownloadFile(a,b); break;
        case NOVYX_ACTIVATE: result=client.ActivateLicense(a); break;
        case NOVYX_LOGOUT: result=client.Logout(); break;
        default: return {0,static_cast<int>(Error::InvalidInput),nullptr,0,nullptr};
        }
        if (data.empty()) return {result.success,static_cast<int>(result.error),nullptr,0,nullptr};
        auto owned = new std::vector<unsigned char>(std::move(data));
        return {result.success,static_cast<int>(result.error),owned->data(),owned->size(),owned};
    } catch (...) { return {0,static_cast<int>(Error::ServerError),nullptr,0,nullptr}; }
}
void Release(novyx_reply_v1* reply) noexcept {
    if (!reply) return;
    delete static_cast<std::vector<unsigned char>*>(reply->owner);
    *reply = {};
}
const novyx_api_v1 api{1,sizeof(novyx_api_v1),Create,Destroy,Invoke,Release};
}

extern "C" __declspec(dllexport) const novyx_api_v1* novyx_get_api_v1() noexcept { return &api; }

extern "C" __declspec(dllexport) int novyx_auth_run(int argc, char** argv) noexcept {
    try {
        return novyx_example_main(argc, argv);
    } catch (...) {
        std::cerr << "Authentication module failed.\n";
        return 1;
    }
}
