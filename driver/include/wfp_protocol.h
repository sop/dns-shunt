#pragma once

#include <ntddk.h>

#define DNS_SHUNT_PROTOCOL_MAGIC 0x31504657u /* "WFP1" little-endian */
#define DNS_SHUNT_PROTOCOL_VERSION 1u
#define DNS_SHUNT_MAX_PENDING 4096u
#define DNS_SHUNT_MAX_DNS_PAYLOAD 65507u

#define IOCTL_DNS_SHUNT_RESOLVE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_DNS_SHUNT_SHUTDOWN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define DNS_SHUNT_COMMAND_REINJECT 1u
#define DNS_SHUNT_COMMAND_RESPONSE 2u

#pragma pack(push, 1)
typedef struct _DNS_SHUNT_CAPTURE_HEADER {
    UINT32 Magic;
    UINT16 Version;
    UINT16 HeaderLength;
    UINT32 TotalLength;
    UINT32 PayloadLength;
    UINT64 Token;
    UCHAR SourceAddress[4];
    UCHAR DestinationAddress[4];
    UINT16 SourcePort;
    UINT16 DestinationPort;
} DNS_SHUNT_CAPTURE_HEADER;

typedef struct _DNS_SHUNT_COMMAND_HEADER {
    UINT32 Magic;
    UINT16 Version;
    UINT16 Command;
    UINT32 TotalLength;
    UINT64 Token;
    UINT32 PayloadLength;
} DNS_SHUNT_COMMAND_HEADER;
#pragma pack(pop)

C_ASSERT(sizeof(DNS_SHUNT_CAPTURE_HEADER) == 36);
C_ASSERT(sizeof(DNS_SHUNT_COMMAND_HEADER) == 24);
