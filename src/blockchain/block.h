#pragma once

#include "transaction.h"
#include "hash.h"
#include <cstdint>
#include <string>
#include <memory>
#include <vector>

namespace ICONation::SDK::Blockchain
{
    // Constants
    const size_t BLOCK_HASH_SIZE = 64;
    const Hash::Prefix BLOCK_HASH_PREFIX = "0x";

    class Block
    {
        // Block specific types
        public:
            typedef uint64_t Height;
            typedef uint64_t Timestamp;

            class Hash : public Blockchain::Hash
            {
                // Allocators
                public:
                    Hash (const std::string &input)
                    :   Blockchain::Hash (input, BLOCK_HASH_PREFIX, BLOCK_HASH_SIZE) {}
                    Hash (const char *input)
                    :   Block::Hash (std::string (input)) {}
                    // Need to call the consistency check externally
                    Hash (void)
                    :   Blockchain::Hash (BLOCK_HASH_PREFIX, BLOCK_HASH_SIZE) {}
                    ~Hash (void) = default;
            };

        // Block allocators
        public:
            Block (void) = default;
            Block (
                const Height &height, 
                const Block::Hash &hash,
                const Block::Hash &previous,
                const Timestamp &timestamp
            );
            virtual ~Block (void) = default;

        // Consistency checks
        public:
            void check_consistency (void) const;

        // Block height
        private:
            Height m_height;
        public:
            const Height &height (void) const { return m_height; }

        // Block hash
        private:
            Block::Hash m_hash;
        public:
            const Block::Hash &hash (void) const { return m_hash; }

        // Previous block
        public:
            const Block::Hash &hashPreviousBlock (void) const { return m_hashPreviousBlock; }
        private:
            Block::Hash m_hashPreviousBlock;

        // Block timestamp
        public:
            const Timestamp &timestamp (void) const { return m_timestamp; }
        private:
            Timestamp m_timestamp;

        // Transaction
        public:
            const std::vector<Transaction> &transactions (void) const { return m_transactions; }
            std::vector<Transaction> &transactions (void) { return m_transactions; }
        private:
            std::vector<Transaction> m_transactions;

        // Function for debug purposes
        public:
            std::string to_string (void) const;
        public:
            friend std::ostream &operator << (std::ostream &stream, const Block &block);
    };
}