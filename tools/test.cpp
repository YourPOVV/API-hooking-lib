#include "check.h"
#include "lde.h"

static void checkRegisterForms() {
    using lde::Decoded;
    Decoded d;
    check(lde::decode((const uint8_t*)"\x55", &d) && d.length == 1);
    check(lde::decode((const uint8_t*)"\x48\x89\xE5", &d) && d.length == 3);
    check(lde::decode((const uint8_t*)"\x48\x83\xEC\x28", &d) && d.length == 4);
    check(lde::decode((const uint8_t*)"\x90", &d) && d.length == 1);
    check(lde::decode((const uint8_t*)"\xC3", &d) && d.length == 1);
}

static void checkImmediateEncodings() {
    using lde::Decoded;
    Decoded d;
    check(lde::decode((const uint8_t*)"\xB8\x01\x02\x03\x04", &d) && d.length == 5);
    check(lde::decode((const uint8_t*)"\x48\xB8\x01\x02\x03\x04\x05\x06\x07\x08", &d) && d.length == 10);
    check(lde::decode((const uint8_t*)"\x48\x81\xEC\x10\x20\x30\x40", &d) && d.length == 7);
    check(lde::decode((const uint8_t*)"\x69\xC9\x78\x56\x34\x12", &d) && d.length == 6);
    check(lde::decode((const uint8_t*)"\xC8\x00\x08\x00", &d) && d.length == 4);
    check(lde::decode((const uint8_t*)"\xA1\x01\x02\x03\x04\x05\x06\x07\x08", &d) && d.length == 9);
}

static void checkRipRelativeFlag() {
    using lde::Decoded;
    Decoded d;
    check(lde::decode((const uint8_t*)"\x48\x8B\x05\x10\x20\x30\x40", &d)
        && d.length == 7 && d.ripRelative && d.dispOffset == 3);
    check(lde::decode((const uint8_t*)"\x48\x89\x0D\x10\x20\x30\x40", &d)
        && d.length == 7 && d.ripRelative && d.dispOffset == 3);
    check(lde::decode((const uint8_t*)"\x0F\x11\x05\x10\x20\x30\x40", &d)
        && d.length == 7 && d.ripRelative && d.dispOffset == 3);
    check(lde::decode((const uint8_t*)"\x48\x8B\x44\x24\x08", &d)
        && d.length == 5 && !d.ripRelative);
}

static void checkEndbrDecoding() {
    using lde::Decoded;
    Decoded d;
    check(lde::decode((const uint8_t*)"\xF3\x0F\x1E\xFA", &d) && d.length == 4);
}

static void checkRefusedEncodings() {
    using lde::Decoded;
    Decoded d;
    check(!lde::decode((const uint8_t*)"\xE9\x10\x20\x30\x40", &d));
    check(!lde::decode((const uint8_t*)"\xE8\x10\x20\x30\x40", &d));
    check(!lde::decode((const uint8_t*)"\x74\x10", &d));
    check(!lde::decode((const uint8_t*)"\xEB\x10", &d));
    check(!lde::decode((const uint8_t*)"\x0F\x84\x10\x20\x30\x40", &d));
    check(!lde::decode((const uint8_t*)"\xC5\xF8\x77", &d));
    check(!lde::decode((const uint8_t*)"\xC4\xe2\x7d\x00\x00", &d));
    check(!lde::decode((const uint8_t*)"\x0F\x38\x00\x00", &d));
    check(!lde::decode((const uint8_t*)"\x67\x48\x8B\x00", &d));
}

int main() {
    checkRegisterForms();
    checkImmediateEncodings();
    checkRipRelativeFlag();
    checkEndbrDecoding();
    checkRefusedEncodings();

    printf(testFailures ? "%d failed\n" : "all passed\n", testFailures);
    return testFailures ? 1 : 0;
}
