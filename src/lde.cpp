#include "lde.h"

namespace lde {

    bool decode(const uint8_t* code, Decoded* result) {
        result->length = 0;
        result->ripRelative = false;
        result->dispOffset = 0;

        size_t prefixIndex = 0;
        bool operandSize = false;
        uint8_t rexPrefix = 0;

        for (;;) {
            const uint8_t prefixByte = code[prefixIndex];
            if (prefixByte == 0x66) { operandSize = true; prefixIndex++; continue; }
            if (prefixByte == 0x67) return false;
            if (prefixByte == 0x2E || prefixByte == 0x3E || prefixByte == 0x26 || prefixByte == 0x36 ||
                prefixByte == 0x64 || prefixByte == 0x65 || prefixByte == 0xF0 ||
                prefixByte == 0xF2 || prefixByte == 0xF3) {
                prefixIndex++;
                continue;
            }
            break;
        }

        if ((code[prefixIndex] & 0xF0) == 0x40) {
            rexPrefix = code[prefixIndex];
            prefixIndex++;
        }

        const uint8_t opcode = code[prefixIndex++];
        size_t instructionLength = prefixIndex;

        auto finish = [&]() -> bool {
            result->length = static_cast<uint32_t>(instructionLength);
            return true;
        };

        auto imm8 = [&]() -> bool { instructionLength += 1; return finish(); };
        auto imm = [&]() -> bool {
            instructionLength += operandSize ? 2 : 4;
            return finish();
        };
        auto none = [&]() -> bool { return finish(); };

        auto readModrm = [&](bool trailingImm8, bool trailingImm) -> void {
            const uint8_t modrmByte = code[instructionLength];
            const uint8_t modField = modrmByte >> 6;
            const uint8_t rmField = modrmByte & 7;
            instructionLength++;

            if (modField == 0 && rmField == 5 && !(rexPrefix & 1)) {
                result->ripRelative = true;
                result->dispOffset = static_cast<uint32_t>(instructionLength);
                instructionLength += 4;
            } else if (modField != 3 && rmField == 4) {
                const uint8_t sibByte = code[instructionLength++];
                if (modField == 1) instructionLength += 1;
                else if (modField == 2) instructionLength += 4;
                else if ((sibByte & 7) == 5) instructionLength += 4;
            } else if (modField == 1) {
                instructionLength += 1;
            } else if (modField == 2) {
                instructionLength += 4;
            }

            if (trailingImm8) instructionLength += 1;
            if (trailingImm) instructionLength += operandSize ? 2 : 4;
        };

        auto modrm = [&]() -> bool { readModrm(false, false); return finish(); };
        auto modrmImm8 = [&]() -> bool { readModrm(true, false); return finish(); };
        auto modrmImm = [&]() -> bool { readModrm(false, true); return finish(); };

        if (opcode == 0x0F) {
            const uint8_t secondOpcode = code[instructionLength];
            switch (secondOpcode) {
                case 0x38: case 0x3A: case 0xFF: return false;
                case 0x80 + 0: case 0x80 + 1: case 0x80 + 2: case 0x80 + 3:
                case 0x80 + 4: case 0x80 + 5: case 0x80 + 6: case 0x80 + 7:
                case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8C: case 0x8D:
                case 0x8E: case 0x8F:
                    return false;

                case 0x05: case 0x06: case 0x07: case 0x08: case 0x09: case 0x0A: case 0x0B:
                case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35: case 0x36:
                case 0x37: case 0x77:
                case 0xA0: case 0xA1: case 0xA2: case 0xA8: case 0xA9: case 0xAA:
                case 0xC8: case 0xC9: case 0xCA: case 0xCB: case 0xCC: case 0xCD:
                case 0xCE: case 0xCF:
                    instructionLength++; return finish();

                case 0x70: case 0x71: case 0x72: case 0x73:
                case 0xAC: case 0xAD: case 0xBA: case 0xC2: case 0xC4: case 0xC5: case 0xC6:
                    instructionLength++; return modrmImm8();

                default:
                    instructionLength++; return modrm();
            }
        }

        switch (opcode) {
            case 0xE8: case 0xE9: case 0xEB:
            case 0xE0: case 0xE1: case 0xE2: case 0xE3:
            case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
            case 0x76: case 0x77: case 0x78: case 0x79: case 0x7A: case 0x7B:
            case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            case 0xC2: case 0xCA: case 0xCB: case 0x9A: case 0xEA:
            case 0x60: case 0x61: case 0x62:
            case 0xC4: case 0xC5:
            case 0xCE: case 0xCF: case 0xD4: case 0xD5: case 0xD6:
            case 0x27: case 0x2F: case 0x37: case 0x3F:
            case 0x06: case 0x07: case 0x0E: case 0x16: case 0x17:
            case 0x1E: case 0x1F:
            case 0xF1: case 0xF4: case 0x82:
                return false;

            case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
            case 0x56: case 0x57: case 0x58: case 0x59: case 0x5A: case 0x5B:
            case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            case 0x6C: case 0x6D: case 0x6E: case 0x6F:
            case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
            case 0x96: case 0x97: case 0x98: case 0x99: case 0x9B: case 0x9C:
            case 0x9D: case 0x9E: case 0x9F:
            case 0xA4: case 0xA5: case 0xA6: case 0xA7:
            case 0xAA: case 0xAB: case 0xAC: case 0xAD: case 0xAE: case 0xAF:
            case 0xC3: case 0xC9: case 0xCC: case 0xD7:
            case 0xEC: case 0xED: case 0xEE: case 0xEF:
            case 0xF5: case 0xF8: case 0xF9: case 0xFA: case 0xFB: case 0xFC: case 0xFD:
                return none();

            case 0xA0: case 0xA1: case 0xA2: case 0xA3:
                instructionLength += 8;
                return finish();

            case 0x04: case 0x0C: case 0x14: case 0x1C: case 0x24: case 0x2C:
            case 0x34: case 0x3C: case 0x6A: case 0xA8: case 0xB0: case 0xB1:
            case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            case 0xCD: case 0xE4: case 0xE5: case 0xE6: case 0xE7:
                return imm8();

            case 0x05: case 0x0D: case 0x15: case 0x1D: case 0x25: case 0x2D:
            case 0x35: case 0x3D: case 0x68:
                return imm();

            case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                instructionLength += (rexPrefix & 8) ? 8 : (operandSize ? 2 : 4);
                return finish();

            case 0x80: case 0x83: case 0xC0: case 0xC1: case 0xC6: case 0x6B:
                return modrmImm8();

            case 0x81: case 0x69: case 0xC7:
                return modrmImm();

            case 0xF6: {
                const uint8_t modrmByte = code[instructionLength];
                readModrm(((modrmByte >> 3) & 7) <= 1, false);
                return finish();
            }

            case 0xF7: {
                const uint8_t modrmByte = code[instructionLength];
                readModrm(false, ((modrmByte >> 3) & 7) <= 1);
                return finish();
            }

            case 0xC8:
                instructionLength += 3;
                return finish();

            default:
                return modrm();
        }
    }

}
