#pragma once
#include <stddef.h>
#include <stdint.h>

// Versioned C ABI: no C++ objects or allocation ownership cross the DLL boundary.
struct novyx_reply_v1 {
    int success;
    int error;
    const unsigned char* data;
    size_t size;
    void* owner;
};
enum novyx_operation_v1 {
    NOVYX_INITIALIZE, NOVYX_REGISTER, NOVYX_REGISTER_LICENSE, NOVYX_LOGIN,
    NOVYX_REFRESH, NOVYX_SESSION, NOVYX_VARIABLE, NOVYX_DOWNLOAD,
    NOVYX_DOWNLOAD_DISK, NOVYX_ACTIVATE, NOVYX_LOGOUT, NOVYX_SELECT_APPLICATION
};
struct novyx_api_v1 {
    uint32_t version;
    uint32_t size;
    void* (*create)(const char*, const char*, const char*);
    void (*destroy)(void*);
    novyx_reply_v1 (*invoke)(void*, int, const char*, const char*, const char*);
    void (*release)(novyx_reply_v1*);
};
