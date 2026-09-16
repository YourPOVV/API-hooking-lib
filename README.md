# api-hook-lib

x64 inline hooking library for Windows

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)](https://github.com/yourpov/api-hook)
[![Language](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus&logoColor=white)](https://isocpp.org/)

## Build

needs [visual studio 2022](https://visualstudio.microsoft.com/) with the desktop development with c++ workload

```bash
git clone https://github.com/yourpov/api-hook.git
cd api-hook
build.bat
```

## Example

```cpp
#include "hook.h"

void (__stdcall* realSleep)(unsigned long) = nullptr;
void __stdcall hookedSleep(unsigned long ms) {
    // runs before the real sleep
    realSleep(ms);
}

void* target = hook::findExport(L"kernel32.dll", "Sleep");
if (hook::create(target, (void*)&hookedSleep, (void**)&realSleep)) {
    Sleep(1000); // goes through hookedSleep first
    hook::remove(target);
}
```

## Limits

- x64 processes only
- always hook `findExport` results, not `&FunctionName`, which is often a local thunk in your own binary
- thread freezing narrows but can't fully close the window where another thread executes the patch mid-write

## License

[MIT](LICENSE) © [YourPOV](https://github.com/yourpov)
