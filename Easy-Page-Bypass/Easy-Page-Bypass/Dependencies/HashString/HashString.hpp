#pragma once

#include <cstdint>

namespace Hash
{
    constexpr __forceinline uint32_t String(const char* input)
    {
        if (!input)
        {
            return 0x00;
        }

        uint32_t hash = 5381, c = 0;
        while (c = *input++)
            hash = hash * 33 + c;
        return hash;
    }
}


#define HASH(x) [](){ constexpr uint32_t stringhash = Hash::String(x); return stringhash; }()