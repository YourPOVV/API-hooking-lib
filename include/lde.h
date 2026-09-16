#pragma once

#include <cstdint>

namespace lde {

    struct Decoded {
        uint32_t length = 0;
        bool ripRelative = false;
        uint32_t dispOffset = 0;
    };

    // decode one x64 instr, returns false if it's weird and shouldn't be moved
    bool decode(const uint8_t* code, Decoded* result);

}
