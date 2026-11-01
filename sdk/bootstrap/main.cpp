#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <filesystem>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <vector>
#include <iostream>
#include <stdexcept>
#include "embedded_payloads.hpp"

namespace {
struct PayloadDirectory {
    std::filesystem::path path;
    ~PayloadDirectory() {
        if (!path.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
        }
    }
};

void WritePayload(const std::filesystem::path& path, const unsigned char* data, DWORD size) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot create embedded DLL.");
    DWORD written = 0;
    const bool ok = WriteFile(file, data, size, &written, nullptr) && written == size;
    CloseHandle(file);
    if (!ok) throw std::runtime_error("Cannot write embedded DLL.");
}

std::vector<unsigned char> ReadApplication() {
    wchar_t executable[32768] = {};
    DWORD length = GetModuleFileNameW(nullptr, executable, 32768);
    if (!length || length >= 32768) throw std::runtime_error("Cannot locate bootstrap executable.");
    std::ifstream input(std::filesystem::path(executable), std::ios::binary | std::ios::ate);
    if (!input) throw std::runtime_error("Cannot open bootstrap executable.");
    const auto total = static_cast<std::uint64_t>(input.tellg());
    if (total < 24) return {};
    unsigned char footer[24] = {};
    input.seekg(static_cast<std::streamoff>(total - 24));
    if (!input.read(reinterpret_cast<char*>(footer), sizeof(footer)))
        throw std::runtime_error("Cannot read bootstrap footer.");
    if (std::memcmp(footer,"NVXPKG01",8) != 0) return {};
    std::uint64_t size = 0, stub = 0;
    std::memcpy(&size,footer+8,8); std::memcpy(&stub,footer+16,8);
    if (size < 64 || size > 64*1024*1024 || stub < 64 || stub > total-24 || size != total-24-stub)
        throw std::runtime_error("Invalid application package size.");
    std::vector<unsigned char> application(static_cast<std::size_t>(size));
    input.seekg(static_cast<std::streamoff>(stub));
    if (!input.read(reinterpret_cast<char*>(application.data()),static_cast<std::streamsize>(size)) ||
        application[0] != 'M' || application[1] != 'Z')
        throw std::runtime_error("Invalid embedded application.");
    return application;
}

int LaunchApplication(const std::filesystem::path& path) {
    // Preserve the original argument tail exactly, including Unicode and quoting.
    const wchar_t* tail = GetCommandLineW();
    if (*tail == L'"') { ++tail; while (*tail && *tail != L'"') ++tail; if (*tail) ++tail; }
    else { while (*tail && *tail != L' ' && *tail != L'\t') ++tail; }
    std::wstring command = L"\"" + path.wstring() + L"\"" + tail;
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(path.c_str(),command.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&startup,&process))
        throw std::runtime_error("Cannot start embedded application.");
    CloseHandle(process.hThread);
    const DWORD waited = WaitForSingleObject(process.hProcess,INFINITE);
    DWORD code = 1;
    const bool ok = waited == WAIT_OBJECT_0 && GetExitCodeProcess(process.hProcess,&code);
    CloseHandle(process.hProcess);
    if (!ok) throw std::runtime_error("Cannot read embedded application exit status.");
    return static_cast<int>(code);
}
}

int main(int argc, char** argv) {
    PayloadDirectory directory;
    try {
        auto application = ReadApplication();
        wchar_t temp[MAX_PATH + 1] = {};
        const DWORD length = GetTempPathW(MAX_PATH + 1, temp);
        if (!length || length > MAX_PATH) throw std::runtime_error("Cannot locate temporary directory.");
        GUID guid;
        wchar_t identifier[40] = {};
        if (FAILED(CoCreateGuid(&guid)) || !StringFromGUID2(guid, identifier, 40))
            throw std::runtime_error("Cannot allocate bootstrap directory.");
        const auto candidate = std::filesystem::path(temp) / (std::wstring(L"novyx-") + identifier);
        if (!CreateDirectoryW(candidate.c_str(), nullptr))
            throw std::runtime_error("Cannot create bootstrap directory.");
        directory.path = candidate;
        WritePayload(directory.path / L"libcurl-x64.dll", curl_payload, sizeof(curl_payload));
        const auto module_path = directory.path / L"novyx_auth.dll";
        WritePayload(module_path, auth_payload, sizeof(auth_payload));
        if (!application.empty()) {
            const auto application_path = directory.path / L"application.exe";
            WritePayload(application_path,application.data(),static_cast<DWORD>(application.size()));
            return LaunchApplication(application_path);
        }
        HMODULE module = LoadLibraryExW(module_path.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module) throw std::runtime_error("Cannot load authentication module.");
        using Run = int (*)(int, char**);
        auto address = GetProcAddress(module, "novyx_auth_run");
        Run run = nullptr;
        static_assert(sizeof(run) == sizeof(address));
        std::memcpy(&run,&address,sizeof(run));
        if (!run) {
            FreeLibrary(module);
            throw std::runtime_error("Authentication module entry point is missing.");
        }
        const int result = run(argc, argv);
        FreeLibrary(module);
        return result;
    } catch (const std::exception& error) {
        std::cerr << "NOVYX bootstrap: " << error.what() << '\n';
        return 1;
    }
}
