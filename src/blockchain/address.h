#pragma once

#include <string>
#include "hash.h"

namespace ICONation::SDK::Blockchain
{
    // Constants
    const size_t T_ADDR_SIZE = 40;
    const Hash::Prefix T_ADDR_EOA_PREFIX = "hx";
    const Hash::Prefix T_ADDR_SCORE_PREFIX = "cx";
    const std::vector<Hash::Prefix> T_ADDR_PREFIX = {"hx", "cx"};

    // An Address is nothing more than a Hash
    class Address : public Hash
    {
        // Allocators
        public:
            Address (const std::string &input) : Hash (input, T_ADDR_PREFIX, T_ADDR_SIZE) {}
            Address (const char *input) : Address (std::string (input)) {}
            // Need to call the consistency check externally
            Address (void)
            :   Hash (T_ADDR_PREFIX, T_ADDR_SIZE) {}
            virtual ~Address (void) = default;
    };
}