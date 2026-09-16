#include "hook.h"

#include "config.h"
#include "log.h"
#include "theme.h"

#include <cstdio>
#include <string>
#include <windows.h>

static void pressEnter(const char* prompt) {
    std::printf("\n");
    std::printf(WHITE "%s" RESET, prompt);
    int inputChar;
    while ((inputChar = getchar()) != '\n' && inputChar != EOF) {}
}

static void (__stdcall* realSleep)(unsigned long milliseconds) = nullptr;

static void __stdcall hookedSleep(unsigned long milliseconds) {
    logAction("HOOK", ("Sleep(" + std::to_string(milliseconds) + ") intercepted").c_str());
    realSleep(milliseconds);
}

__declspec(noinline) static unsigned long slowTarget(unsigned long input) {
    volatile unsigned long value = input;
    return value * 2;
}

static unsigned long (*realSlowTarget)(unsigned long) = nullptr;

static unsigned long hookedSlowTarget(unsigned long input) {
    logAction("HOOK", ("slowTarget(" + std::to_string(input) + ") intercepted").c_str());
    return realSlowTarget(input);
}

int main() {
    std::printf("\n");
    logInfo("api-hook demo");

    // some builds make Sleep a jmp thunk, failing here is normal
    void* sleepAddress = hook::findExport(L"kernel32.dll", "Sleep");
    if (sleepAddress && hook::create(sleepAddress, (void*)&hookedSleep, (void**)&realSleep)) {
        logAction("OK", "kernel32!Sleep hooked");
        Sleep(20);
        hook::remove(sleepAddress);
        logInfo("Sleep unhooked");
    } else {
        logLine("WARN", "kernel32!Sleep could not be hooked on this build");
    }

    Sleep(20);

    // local func is always clean, proves engine works even if Sleep was a thunk
    if (hook::create((void*)&slowTarget, (void*)&hookedSlowTarget, (void**)&realSlowTarget)) {
        logAction("OK", "slowTarget hooked");
        slowTarget(21);
        hook::remove((void*)&slowTarget);
        logInfo("slowTarget unhooked");
    }

    pressEnter("Press Enter to exit...");
    return 0;
}