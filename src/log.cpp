#include "log.h"

#include "config.h"
#include "theme.h"

#include <cstdio>
#include <string.h>

static const char* colorFor(const char* tag) {
    if (_stricmp(tag, "ERROR") == 0) return RED;
    if (_stricmp(tag, "WARN") == 0) return YELLOW;
    if (_stricmp(tag, "OK") == 0) return GREEN;
    if (_stricmp(tag, "DBG") == 0) return GREY;
    return WHITE;
}

void logLine(const char* tag, const char* message) {
    std::printf("%s[%s]%s %s\n", colorFor(tag), tag, RESET, message);
}

void logInfo(const char* message) {
    logLine("INFO", message);
}

void logAction(const char* tag, const char* message) {
    logLine(tag, message);
}

void logDebug(const char* message) {
    if (!cfg::debugMode) return;
    logLine("DBG", message);
}
