#pragma once

#include <ntddk.h>

#define logmsg(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_MASK | DPFLTR_INFO_LEVEL, "[" __FUNCTION__ "] " ##__VA_ARGS__)

#pragma warning(disable: 4201)
#pragma warning(disable: 4100)

//0xa0 bytes (sizeof)
struct _KLDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;             //0x0
    VOID *ExceptionTable;                            //0x10
    ULONG ExceptionTableSize;                        //0x18
    VOID *GpValue;                                   //0x20
    struct _NON_PAGED_DEBUG_INFO *NonPagedDebugInfo; //0x28
    VOID *DllBase;                                   //0x30
    VOID *EntryPoint;                                //0x38
    ULONG SizeOfImage;                               //0x40
    struct _UNICODE_STRING FullDllName;              //0x48
    struct _UNICODE_STRING BaseDllName;              //0x58
    ULONG Flags;                                     //0x68
    USHORT LoadCount;                                //0x6c
    union
    {
        USHORT SignatureLevel : 4; //0x6e
        USHORT SignatureType : 3;  //0x6e
        USHORT Unused : 9;         //0x6e
        USHORT EntireField;        //0x6e
    } u1;                          //0x6e
    VOID *SectionPointer;          //0x70
    ULONG CheckSum;                //0x78
    ULONG CoverageSectionSize;     //0x7c
    VOID *CoverageSection;         //0x80
    VOID *LoadedImports;           //0x88
    VOID *Spare;                   //0x90
    ULONG SizeOfImageNotRounded;   //0x98
    ULONG TimeDateStamp;           //0x9c
};

typedef struct MOUSE_INPUT_DATA
{
    USHORT UnitId;
    USHORT Flags;

    union
    {
        ULONG Buttons;

        struct
        {
            USHORT ButtonFlags;
            USHORT ButtonData;
        };
    };

    ULONG RawButtons;
    LONG LastX;
    LONG LastY;
    ULONG ExtraInformation;
} MOUSE_INPUT_DATA, *PMOUSE_INPUT_DATA;

using mouse_service_callback_t = void( * )(
    PDEVICE_OBJECT,
    PMOUSE_INPUT_DATA,
    PMOUSE_INPUT_DATA,
    PULONG );

using mouobj_t = struct
{
    PDEVICE_OBJECT mouse_device;
    mouse_service_callback_t cb;
    mouse_service_callback_t *cb_addr;
    bool use_mouse;
};

namespace mouhook
{
    mouobj_t *get_mouobj( );
}


using u64 = unsigned long long;
using i64 = long long;
using u32 = unsigned long;
using i32 = long;
using u8 = unsigned char;
using i8 = char;

using unicode_string = UNICODE_STRING;
