#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>

namespace hook {
    KSPIN_LOCK hook_spinlock;
    void initialize_spinlock() {
        KeInitializeSpinLock(&hook_spinlock);
    }

#if _M_IX86
    const unsigned char jmp_code[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
    const size_t jmp_size = sizeof(jmp_code);
#elif _M_X64
    const unsigned char jmp_code[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
    const size_t jmp_size = sizeof(jmp_code);
#endif

    inline bool RtlForceCopyMemory(void* address, const void* buffer, size_t size) {
        PHYSICAL_ADDRESS physical_address = MmGetPhysicalAddress(address);
        if (!physical_address.QuadPart)
            return false;

        void* mapped = MmMapIoSpaceEx(physical_address, size, PAGE_EXECUTE_READWRITE);
        if (!mapped)
            return false;

        RtlCopyMemory(mapped, buffer, size);
        MmUnmapIoSpace(mapped, size);
        return true;
    }

    struct hook_data {
        void* function;
        void* target;
        unsigned char original_bytes[16];
        bool enabled;

        bool is_empty() const {
            return !function && !target && original_bytes[0] == 0;
        }
    };

    const __int32 max_hook_entries = 64;
    hook_data hooks[max_hook_entries] = {};

    hook_data* get_hook(void* address) {
        KIRQL irql;
        KeAcquireSpinLock(&hook_spinlock, &irql);

        hook_data* result = nullptr;
        for (__int32 idx = 0; idx < max_hook_entries; idx++) {
            hook_data* entry = &hooks[idx];
            if (entry->function == address || entry->target == address) {
                result = entry;
                break;
            }
        }

        KeReleaseSpinLock(&hook_spinlock, irql);
        return result;
    }

    bool is_hooked(void* address) {
        KIRQL irql;
        KeAcquireSpinLock(&hook_spinlock, &irql);

        hook_data* entry = get_hook(address);
        bool hooked = entry && entry->enabled;

        KeReleaseSpinLock(&hook_spinlock, irql);
        return hooked;
    }

    bool add_hook(void* function, void* target) {
        KIRQL irql;
        KeAcquireSpinLock(&hook_spinlock, &irql);

        bool success = false;
        for (__int32 idx = 0; idx < max_hook_entries; idx++) {
            hook_data* entry = &hooks[idx];
            if (!entry->is_empty())
                continue;

            RtlCopyMemory(entry->original_bytes, function, jmp_size);
            entry->function = function;
            entry->target = target;
            entry->enabled = false;
            success = true;
            break;
        }

        KeReleaseSpinLock(&hook_spinlock, irql);
        return success;
    }

    bool enable_hook(void* address) {
        KIRQL irql;
        KeAcquireSpinLock(&hook_spinlock, &irql);

        hook_data* entry = get_hook(address);
        if (!entry || entry->enabled) {
            KeReleaseSpinLock(&hook_spinlock, irql);
            return false;
        }

        unsigned char jump_buffer[jmp_size];
        RtlCopyMemory(jump_buffer, jmp_code, jmp_size);
#if _M_IX86
        * (void**)(jump_buffer + 1) = entry->target;
#elif _M_X64
        * (void**)(jump_buffer + 2) = entry->target;
#endif

        bool success = RtlForceCopyMemory(entry->function, jump_buffer, jmp_size);
        if (success)
            entry->enabled = true;

        KeReleaseSpinLock(&hook_spinlock, irql);
        return success;
    }

    bool disable_hook(void* address) {
        KIRQL irql;
        KeAcquireSpinLock(&hook_spinlock, &irql);

        hook_data* entry = get_hook(address);
        if (!entry || !entry->enabled) {
            KeReleaseSpinLock(&hook_spinlock, irql);
            return false;
        }

        bool success = RtlForceCopyMemory(entry->function, entry->original_bytes, jmp_size);
        if (success)
            entry->enabled = false;

        KeReleaseSpinLock(&hook_spinlock, irql);
        return success;
    }

    void remove_hook(void* address) {
        KIRQL irql;
        KeAcquireSpinLock(&hook_spinlock, &irql);

        hook_data* entry = get_hook(address);
        if (!entry) {
            KeReleaseSpinLock(&hook_spinlock, irql);
            return;
        }

        if (entry->enabled)
            disable_hook(address);

        RtlZeroMemory(entry, sizeof(hook_data));

        KeReleaseSpinLock(&hook_spinlock, irql);
    }

    void enable_all_hooks() {
        KIRQL irql;
        KeAcquireSpinLock(&hook_spinlock, &irql);

        for (__int32 idx = 0; idx < max_hook_entries; idx++) {
            hook_data* entry = &hooks[idx];
            if (!entry->is_empty() && !entry->enabled)
                enable_hook(entry->function);
        }

        KeReleaseSpinLock(&hook_spinlock, irql);
    }

    void disable_all_hooks() {
        KIRQL irql;
        KeAcquireSpinLock(&hook_spinlock, &irql);

        for (__int32 idx = 0; idx < max_hook_entries; idx++) {
            hook_data* entry = &hooks[idx];
            if (!entry->is_empty() && entry->enabled)
                disable_hook(entry->function);
        }

        KeReleaseSpinLock(&hook_spinlock, irql);
    }
}
