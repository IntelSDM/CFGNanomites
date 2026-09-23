#pragma once

#include <cstdint>

class NanoLayout
{
public:
    static constexpr uint32_t NanoBytes = 0x1000;
    static constexpr uint32_t OffShellcode = 0x0000;
    static constexpr uint32_t OffTlsCb = 0x0100;
    static constexpr uint32_t OffCount = 0x0168;
    static constexpr uint32_t OffBuildKey = 0x016C;
    static constexpr uint32_t OffTable = 0x0170;
    static constexpr uint32_t TableEntrySize = 12;
    static constexpr uint32_t MaxTableEntries = 310;
    static constexpr uint32_t OffFakeSlot = 0x0000;
};