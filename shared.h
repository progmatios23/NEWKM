#pragma once

#define REQUEST_VERSION 0x01
#define REQUEST_MAGIC 0x44524B4E

#define MAX_TRANSFER_SIZE (16 * 1024 * 1024)
#define MAX_MODULE_NAME_LEN 64

typedef enum _DRIVER_COMMAND {
    CMD_NONE          = 0,
    CMD_READ          = 1,
    CMD_WRITE         = 2,
    CMD_MODULE_BASE   = 3,
    CMD_ALLOC         = 4,
    CMD_FREE          = 5,
    CMD_PROTECT       = 6,
    CMD_READ64        = 7,
    CMD_WRITE64       = 8,
    CMD_PING          = 99,
    CMD_VERIFY_PTE    = 100,
    CMD_VERIFY_SPOOF  = 101,
} DRIVER_COMMAND;

typedef struct _REQUEST_DATA {
    unsigned int    magic;
    unsigned int    version;
    unsigned int    command;
    unsigned int    flags;

    unsigned __int64 pid;
    unsigned __int64 address;
    unsigned __int64 buffer;
    unsigned __int64 size;
    unsigned __int64 result;

    unsigned int    protect;
    unsigned int    reserved;

    wchar_t         module_name[MAX_MODULE_NAME_LEN];

    unsigned __int64 checksum;
} REQUEST_DATA, *PREQUEST_DATA;

#define RESPONSE_SUCCESS  0x50544548
#define RESPONSE_FALLBACK 0x4B524E4C
#define RESPONSE_ERROR    0xFFFFFFFF
