#include "mouhook.h"

#include <intrin.h>

#pragma warning(disable: 4311)
#pragma warning(disable: 4302)

namespace
{
    UNICODE_STRING g_device_name = RTL_CONSTANT_STRING( L"\\Device\\MouHook" );
    UNICODE_STRING g_symlink_name = RTL_CONSTANT_STRING( L"\\??\\MouHook" );

    enum class msr_t : int
    {
        ia32_debugctl    = 0x1d9,
        ia32_ler_from_ip = 0x1db,
        ia32_ler_to_ip   = 0x1dc,
    };

    union debugctl_t
    {
        struct
        {
            u64 lbr : 1;
            u64 btf : 1;
            u64 reserved : 62;
        };

        u64 msr;
    };

    union l2_cache_info_t
    {
        struct
        {
            u64 l2_line_size : 7;
            u64 l2_lines_per_tag : 3;
            u64 l2_assoc : 3;
            u64 l2_size : 15;
        };

        u64 field;
    };

    struct branchinfo_t
    {
        u64 ler_from_ip; // origin of branching instruction
        u64 ler_to_ip;   // destination of branching instruction

        explicit operator bool( ) const
        {
            return ler_from_ip && ler_to_ip;
        }
    };

    struct driver_info_t
    {
        u64 base;
        u32 size;

        explicit operator bool( ) const
        {
            return base && size;
        }
    };

    struct mouhook_device_ext_t
    {
        DEVICE_OBJECT *device_obj;
        KEVENT exit_event;
        HANDLE worker_thread_handle;
        MDL *mdl;
        u64 *cb_map;
        mouobj_t *mouobj;
        branchinfo_t bi;
        i64 use_count;
        bool locked_mdl;
    };

    mouhook_device_ext_t *ext = nullptr;

    constexpr auto detour_target_offset = 21ull;
    constexpr auto kbase_addr_offset = detour_target_offset + 8;

    u64 post_detour_call_addr = 0ull;

    u8 detour_original_fn_contents[ 34 ] = { };

    i32 frozen_processor_count = 0;

    extern "C" void stack_fix( DEVICE_OBJECT *device_obj,
                               MOUSE_INPUT_DATA *mid_in,
                               MOUSE_INPUT_DATA *mid_end,
                               u32 *out,
                               bool unk,
                               u64 always_zero_1,
                               u64 ret_addr,
                               u64 always_zero_2 );

    extern "C" void retpol_spoof( u64 retpol,
                                  u64 jmp_dst );
}


extern "C" {
extern u64 resume_addr;
}

NTSTATUS mouhook_create( PDEVICE_OBJECT device_obj,
                         PIRP irp )
{
    irp->IoStatus.Information = 0;
    irp->IoStatus.Status = STATUS_SUCCESS;

    IoCompleteRequest( irp,
                       IO_NO_INCREMENT );

    return STATUS_SUCCESS;
}

driver_info_t get_info_for_address( const mouhook_device_ext_t *e,
                                    const u64 address )
{
    const auto ldr = static_cast< _KLDR_DATA_TABLE_ENTRY* >(
        e->device_obj->DriverObject->DriverSection
    );

    const auto head = &ldr->InLoadOrderLinks;

    if ( IsListEmpty( head ) )
        return { };

    for ( auto curr = head->Flink; curr != head; curr = curr->Flink )
    {
        const auto entry = CONTAINING_RECORD(
            curr,
            _KLDR_DATA_TABLE_ENTRY,
            InLoadOrderLinks
        );

        const auto start = reinterpret_cast< u64 >( entry->DllBase );
        const auto end = reinterpret_cast< u64 >( entry->DllBase ) + entry->SizeOfImage;

        if ( address >= start && address <= end )
        {
            return {
                .base = reinterpret_cast< u64 >( entry->DllBase ),
                .size = entry->SizeOfImage,
            };
        }
    }

    return { };
}

void mouhook_service_callback( PDEVICE_OBJECT device_obj,
                               PMOUSE_INPUT_DATA mou_in_start,
                               PMOUSE_INPUT_DATA mou_in_end,
                               PULONG count )
{
    /*
     * LBR was disabled before jumping into this handler, hence the values inside
     * IA32_LER_FROM_IP and IA32_LER_TO_IP reflect the branch information for the
     * previous function, instead of this one.
     */

    InterlockedIncrement64( &ext->use_count );

    ext->bi = branchinfo_t {
        .ler_from_ip = __readmsr( static_cast< u32 >( msr_t::ia32_ler_from_ip ) ),
        .ler_to_ip = ( 0xffllu << 0x38 ) | __readmsr( static_cast< u32 >( msr_t::ia32_ler_to_ip ) )
    };

    bool spoofed = false;

    const auto ret_addr = reinterpret_cast< u64 >( _ReturnAddress ( ) );

    if ( ext->bi && ext->bi.ler_to_ip != reinterpret_cast< u64 >( ext->mouobj->cb ) )
    {
        logmsg( "last entry record origin: 0x%p last entry target: 0x%p (ret: %p)\n",
                ext->bi.ler_from_ip,
                ext->bi.ler_to_ip,
                ret_addr
        );

        logmsg( "call originated from unexpected location, return address %p\n",
                ret_addr
        );

        spoofed = true;
    }

    const auto di = get_info_for_address(
        ext,
        reinterpret_cast< u64 >( _ReturnAddress ( ) )
    );

    if ( di && spoofed )
    {
        logmsg( "driver base: %p driver size: %lx | process: %llx thread id: %llx prio: 0x%lx\n",
                di.base,
                di.size,
                PsGetCurrentProcessId(),
                PsGetCurrentThreadId(),
                KeGetCurrentIrql()
        );
    }

    resume_addr = post_detour_call_addr;

    auto debugctl = debugctl_t {
        .msr = __readmsr( static_cast< u32 >( msr_t::ia32_debugctl ) )
    };

    /* re-enable branch recording */
    debugctl.lbr = true;

    __writemsr(
        static_cast< u32 >( msr_t::ia32_debugctl ),
        debugctl.msr
    );

    InterlockedDecrement64(
        &ext->use_count
    );

    stack_fix( device_obj,
               mou_in_start,
               mou_in_end,
               count,
               false,
               ( u64 )mou_in_start,
               ret_addr,
               0 );
}

void mouhook_worker( void *context )
{
    ext = static_cast< mouhook_device_ext_t* >( context );

    ext->mouobj = mouhook::get_mouobj ( );

    u8 detour[ ] = {
        "\x50"                             // push    rax
        "\x51"                             // push    rcx
        "\x52"                             // push    rdx
        "\xb9\xd9\x01\x00\x00"             // mov     ecx,1D9h
        "\x0f\x32"                         // rdmsr
        "\x25\xfe\xff\xff\xff"             // and     eax,0FFFFFFFEh
        "\x0f\x30"                         // wrmsr
        "\x5a"                             // pop     rdx
        "\x59"                             // pop     rcx
        "\x58"                             // pop     rax
        "\x68\x00\x00\x00\x00"             // push    [hook target address]
        "\xc7\x44\x24\x04\x00\x00\x00\x00" // mov     dword ptr [rsp+4],0FFFFF807h
        "\xc3"                             // ret
    };

    constexpr auto detour_hook_size = sizeof( detour ) - 1;
    post_detour_call_addr = reinterpret_cast< u64 >( ext->mouobj->cb ) + ( detour_hook_size + 1 );

    const auto hook_fn_addr = reinterpret_cast< u64 >( mouhook_service_callback );

    *reinterpret_cast< u32* >( &detour[ detour_target_offset ] ) = static_cast< u32 >( hook_fn_addr & 0xffffffff );
    *reinterpret_cast< u32* >( &detour[ kbase_addr_offset ] ) = static_cast< u32 >( hook_fn_addr >> 32 );

    logmsg( "detour: %p (%p)\n",
            detour,
            (u64)mouhook_service_callback );

    ext->mdl = IoAllocateMdl(
        ( void* )ext->mouobj->cb,
        PAGE_SIZE,
        false,
        false,
        nullptr
    );

    __try
    {
        MmProbeAndLockPages(
            ext->mdl,
            KernelMode,
            IoModifyAccess
        );
        logmsg( "mapping: %p backup: %p\n",
                ext->cb_map,
                detour_original_fn_contents
        );

        // save original contents
        memcpy(
            detour_original_fn_contents,
            ext->cb_map,
            detour_hook_size
        );

        // replace with hook prologue
        memcpy(
            ext->cb_map,
            detour,
            detour_hook_size
        );

        logmsg( "post detour address: %p\n",
                post_detour_call_addr
        );

        ext->cb_map = static_cast< u64* >(
            MmMapLockedPagesSpecifyCache(
                ext->mdl,
                KernelMode,
                MmCached,
                nullptr,
                false,
                NormalPagePriority
            )
        );
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
        logmsg( "unable to probe page\n" );
    }
}

void mouhook_unload( PDRIVER_OBJECT driver_obj )
{
    const auto mouhook_ext = static_cast< mouhook_device_ext_t* >( driver_obj->DeviceObject->DeviceExtension );

    KeSetEvent(
        &mouhook_ext->exit_event,
        0,
        false
    );


    if ( ext->locked_mdl )
    {
        memcpy(
            ext->cb_map,
            detour_original_fn_contents,
            sizeof( detour_original_fn_contents )
        );

        MmUnmapLockedPages(
            ext->cb_map,
            ext->mdl
        );

        MmUnlockPages( ext->mdl );
    }

    if ( ext->mdl )
        IoFreeMdl( ext->mdl );

    IoDeleteSymbolicLink( &g_symlink_name );
    IoDeleteDevice( driver_obj->DeviceObject );

    logmsg( "unloaded\n" );
}

extern "C" NTSTATUS DriverEntry( PDRIVER_OBJECT driver_obj,
                                 PUNICODE_STRING reg_path )
{
    auto status = STATUS_SUCCESS;

    PDEVICE_OBJECT device_object = nullptr;

    status = IoCreateDevice(
        driver_obj,
        sizeof( mouhook_device_ext_t ),
        &g_device_name,
        0,
        0,
        false,
        &device_object
    );

    if ( !NT_SUCCESS( status ) )
    {
        logmsg( "unable to create device: 0x%08x\n",
                status );

        return status;
    }

    status = IoCreateSymbolicLink( &g_symlink_name,
                                   &g_device_name );

    if ( !NT_SUCCESS( status ) )
    {
        logmsg( "unable to create symbolic link: 0x%08x\n",
                status );
        IoDeleteDevice( device_object );
        return status;
    }

    for ( auto &irp : driver_obj->MajorFunction )
        irp = nullptr;

    driver_obj->DriverUnload = mouhook_unload;
    driver_obj->MajorFunction[ IRP_MJ_CREATE ] =
            driver_obj->MajorFunction[ IRP_MJ_CLOSE ] = mouhook_create;

    memset(
        device_object->DeviceExtension,
        0,
        sizeof( mouhook_device_ext_t )
    );

    device_object->Flags &= ~DO_DEVICE_INITIALIZING;


    const auto mouhook_device_ext = static_cast< mouhook_device_ext_t* >( device_object->DeviceExtension );

    mouhook_device_ext->device_obj = device_object;

    KeInitializeEvent(
        &mouhook_device_ext->exit_event,
        NotificationEvent,
        false
    );

    PsCreateSystemThread(
        &mouhook_device_ext->worker_thread_handle,
        THREAD_ALL_ACCESS,
        nullptr,
        NtCurrentProcess ( ),
        nullptr,
        mouhook_worker,
        mouhook_device_ext
    );

    return status;
}
