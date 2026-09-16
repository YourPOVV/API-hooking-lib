#pragma once

// hook with findExport + create, undo with remove
namespace hook {
    void* findExport(const wchar_t* moduleName, const char* procName);
    bool create(void* target, void* detour, void** original);
    bool remove(void* target);
}
