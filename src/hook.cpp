#include "hook.h"

#include "config.h"
#include "log.h"
#include "theme.h"
#include "lde.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>

namespace hook {

    void* findExport(const wchar_t* moduleName, const char* procName) {
        HMODULE module = GetModuleHandleW(moduleName);
        if (!module) return nullptr;
        return reinterpret_cast<void*>(GetProcAddress(module, procName));
    }

}

namespace {

    constexpr uint32_t PATCH_SIZE = 14;
    constexpr uint32_t MAX_STOLEN = 64;
    constexpr uint32_t TRAMPOLINE_SIZE = MAX_STOLEN + PATCH_SIZE;
    constexpr int MAX_HOOKS = 64;

    struct HookEntry {
        void* target = nullptr;
        void* trampoline = nullptr;
        uint8_t original[MAX_STOLEN] = {};
        uint32_t stolenLength = 0;
        bool active = false;
    };

    HookEntry hookEntries[MAX_HOOKS];

    HookEntry* findHookEntry(void* target) {
        for (HookEntry& entry : hookEntries) {
            if (entry.active && entry.target == target) return &entry;
        }
        return nullptr;
    }

    HookEntry* findFreeEntry() {
        for (HookEntry& entry : hookEntries) {
            if (!entry.active) return &entry;
        }
        return nullptr;
    }

    // has to stay within 2GB so jump can reach, scan up first, windows is top-down
    void* allocateNear(void* origin) {
        SYSTEM_INFO systemInfo;
        GetSystemInfo(&systemInfo);

        const uintptr_t center = reinterpret_cast<uintptr_t>(origin);
        const uintptr_t reach = 0x70000000ull;
        const uintptr_t lowest = reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);
        const uintptr_t highest = reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress);

        const uintptr_t low = center > reach ? center - reach : lowest;
        const uintptr_t high = center + reach < highest ? center + reach : highest;

        const uintptr_t step = 0x10000ull;
        for (uintptr_t offset = 0; offset <= reach + step; offset += step) {
            const uintptr_t up = center + offset;
            if (up <= high && up >= center) {
                void* allocation = VirtualAlloc(
                    reinterpret_cast<void*>(up),
                    TRAMPOLINE_SIZE,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE);
                if (allocation) return allocation;
            }
            if (offset == 0) continue;

            const uintptr_t down = center >= offset ? center - offset : 0;
            if (down >= low && down >= lowest && down <= center) {
                void* allocation = VirtualAlloc(
                    reinterpret_cast<void*>(down),
                    TRAMPOLINE_SIZE,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE);
                if (allocation) return allocation;
            }
            if (up > high && down < low) return nullptr;
        }
        return nullptr;
    }

    // freeze others while patching, can't fully fix mid-patch race in user-mode
    struct FrozenThreads {
        std::vector<HANDLE> handles;

        ~FrozenThreads() {
            for (HANDLE thread : handles) {
                ResumeThread(thread);
                CloseHandle(thread);
            }
        }
    };

    void freezeOthers(FrozenThreads* frozen, void* patchStart, void* patchEnd) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            logLine("WARN", "thread snapshot failed, patching without freeze protection");
            return;
        }

        const DWORD currentId = GetCurrentThreadId();
        const DWORD processId = GetCurrentProcessId();

        THREADENTRY32 threadEntry;
        threadEntry.dwSize = sizeof(threadEntry);

        if (Thread32First(snapshot, &threadEntry)) {
            do {
                if (threadEntry.th32OwnerProcessID != processId) continue;
                if (threadEntry.th32ThreadID == currentId) continue;

                HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                    THREAD_QUERY_INFORMATION, FALSE, threadEntry.th32ThreadID);
                if (!thread) continue;
                if (SuspendThread(thread) == (DWORD)-1) {
                    CloseHandle(thread);
                    continue;
                }

                CONTEXT context;
                context.ContextFlags = CONTEXT_CONTROL;
                if (GetThreadContext(thread, &context)) {
                    if (context.Rip >= reinterpret_cast<uintptr_t>(patchStart) &&
                        context.Rip < reinterpret_cast<uintptr_t>(patchEnd)) {
                        logLine("WARN", "a thread was inside the patch region during install");
                    }
                }
                frozen->handles.push_back(thread);
            } while (Thread32Next(snapshot, &threadEntry));
        }

        CloseHandle(snapshot);
    }

    bool writeJump(void* targetAddress, void* destination) {
        DWORD oldProtect;
        if (!VirtualProtect(targetAddress, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;

        uint8_t jump[PATCH_SIZE];
        jump[0] = 0xFF;
        jump[1] = 0x25;
        memset(jump + 2, 0, 4);
        memcpy(jump + 6, &destination, sizeof(destination));
        memcpy(targetAddress, jump, PATCH_SIZE);
        FlushInstructionCache(GetCurrentProcess(), targetAddress, PATCH_SIZE);

        VirtualProtect(targetAddress, PATCH_SIZE, oldProtect, &oldProtect);
        return true;
    }

    bool buildTrampoline(HookEntry* entry) {
        void* buffer = allocateNear(entry->target);
        if (!buffer) {
            logLine("ERROR", "no executable memory within 2GB of the target");
            return false;
        }

        uint8_t* trampolineCursor = reinterpret_cast<uint8_t*>(buffer);
        uint32_t stolenOffset = 0;

        while (stolenOffset < PATCH_SIZE) {
            const uint8_t* sourceInstruction =
                reinterpret_cast<const uint8_t*>(entry->target) + stolenOffset;

            lde::Decoded decoded;
            if (!lde::decode(sourceInstruction, &decoded)) {
                logLine("ERROR", "target prologue uses an instruction the decoder does not know");
                VirtualFree(buffer, 0, MEM_RELEASE);
                return false;
            }

            if (stolenOffset + decoded.length > MAX_STOLEN) {
                logLine("ERROR", "prologue too large to relocate");
                VirtualFree(buffer, 0, MEM_RELEASE);
                return false;
            }

            if (cfg::debugMode) {
                const std::string debugMessage =
                    "stolen instruction length: " + std::to_string(decoded.length);
                logDebug(debugMessage.c_str());
            }
            memcpy(trampolineCursor + stolenOffset, sourceInstruction, decoded.length);

            if (decoded.ripRelative) {
                int32_t oldDisp;
                memcpy(&oldDisp, sourceInstruction + decoded.dispOffset, sizeof(oldDisp));

                const int64_t oldNext =
                    reinterpret_cast<int64_t>(sourceInstruction) + decoded.length;
                const int64_t newNext =
                    reinterpret_cast<int64_t>(trampolineCursor + stolenOffset) + decoded.length;
                const int64_t newDisp = (oldNext + oldDisp) - newNext;

                if (newDisp < INT32_MIN || newDisp > INT32_MAX) {
                    logLine("ERROR", "rip relative displacement cannot be relocated");
                    VirtualFree(buffer, 0, MEM_RELEASE);
                    return false;
                }
                memcpy(
                    trampolineCursor + stolenOffset + decoded.dispOffset,
                    &newDisp,
                    sizeof(newDisp));
            }

            stolenOffset += decoded.length;
        }

        if (stolenOffset > MAX_STOLEN) {
            logLine("ERROR", "prologue too large to relocate");
            VirtualFree(buffer, 0, MEM_RELEASE);
            return false;
        }

        memcpy(entry->original, entry->target, stolenOffset);
        entry->stolenLength = stolenOffset;

        trampolineCursor[stolenOffset + 0] = 0xFF;
        trampolineCursor[stolenOffset + 1] = 0x25;
        memset(trampolineCursor + stolenOffset + 2, 0, 4);
        const uintptr_t back = reinterpret_cast<uintptr_t>(entry->target) + stolenOffset;
        memcpy(trampolineCursor + stolenOffset + 6, &back, sizeof(back));

        entry->trampoline = buffer;
        return true;
    }

}

namespace hook {

    bool create(void* target, void* detour, void** original) {
        if (!target || !detour || !original) return false;
        *original = nullptr;

        if (findHookEntry(target)) {
            logLine("ERROR", "target is already hooked");
            return false;
        }

        HookEntry* entry = findFreeEntry();
        if (!entry) {
            logLine("ERROR", "hook table is full");
            return false;
        }

        entry->target = target;
        if (!buildTrampoline(entry)) {
            entry->target = nullptr;
            return false;
        }

        FrozenThreads frozen;
        freezeOthers(&frozen, target, reinterpret_cast<uint8_t*>(target) + PATCH_SIZE);

        if (!writeJump(target, detour)) {
            logLine("ERROR", "VirtualProtect failed on the target");
            VirtualFree(entry->trampoline, 0, MEM_RELEASE);
            entry->target = nullptr;
            return false;
        }

        *original = entry->trampoline;
        entry->active = true;
        return true;
    }

    bool remove(void* target) {
        HookEntry* entry = findHookEntry(target);
        if (!entry) return false;

        FrozenThreads frozen;
        freezeOthers(&frozen, target, reinterpret_cast<uint8_t*>(target) + PATCH_SIZE);

        const uint32_t restoreSize = entry->stolenLength > PATCH_SIZE ? entry->stolenLength : PATCH_SIZE;
        DWORD oldProtect;
        if (!VirtualProtect(target, restoreSize, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;
        memcpy(target, entry->original, entry->stolenLength);
        FlushInstructionCache(GetCurrentProcess(), target, entry->stolenLength);
        VirtualProtect(target, restoreSize, oldProtect, &oldProtect);

        VirtualFree(entry->trampoline, 0, MEM_RELEASE);
        ZeroMemory(entry, sizeof(*entry));
        return true;
    }

}