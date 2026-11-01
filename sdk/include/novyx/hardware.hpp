#pragma once
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#include <string>
#include <vector>
namespace novyx {
inline std::string CurrentUserSid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) return {};
    DWORD size = 0;
    GetTokenInformation(token,TokenUser,nullptr,0,&size);
    std::vector<unsigned char> buffer(size);
    const bool ok = size && GetTokenInformation(token,TokenUser,buffer.data(),size,&size);
    CloseHandle(token);
    if (!ok) return {};
    LPSTR text = nullptr;
    if (!ConvertSidToStringSidA(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid,&text)) return {};
    std::string sid(text); LocalFree(text); return sid;
}
}
#endif
