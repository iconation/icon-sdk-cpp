#pragma once

#include "address.h"
#include "block.h"
#include "transaction.h"
#include "token.h"

namespace ICONation::SDK::Blockchain
{
    class TransactionResult
    {
        // Allocator
        public:
            TransactionResult (
                const Address &to,
                const Block::Height &height,
                const Block::Hash &blockHash,
                const Transaction::Hash &txHash,
                const ICX::Step &stepUsed,
                const ICX::Loop &stepPrice,
                const nlohmann::json &eventLogs
            );

            ~TransactionResult (void) = default;

        // Address destination
        public:
            const Address &to (void) const { return m_to; }
        private:
            Address m_to;

        // Block height
        public:
            const Block::Height &height (void) const { return m_height; }
        private:
            Block::Height m_height;

        // Block hash
        public:
            const Block::Hash &blockHash (void) const { return m_blockHash; }
        private:
            Block::Hash m_blockHash;

        // Transaction hash
        public:
            const Transaction::Hash &txHash (void) const { return m_txHash; }
        private:
            Transaction::Hash m_txHash;

        // Steps
        public:
            const ICX::Step &stepUsed (void) const { return m_stepUsed; }
            const ICX::Loop &stepPrice (void) const { return m_stepPrice; }
        private:
            ICX::Step m_stepUsed;
            ICX::Loop m_stepPrice;

        // Event logs
        public:
            const nlohmann::json &eventLogs (void) const { return m_eventLogs; }
        private:
            nlohmann::json m_eventLogs;

        // Function for debug purposes
        public:
            std::string to_string (void) const;
        public:
            friend std::ostream &operator << (std::ostream &stream, const TransactionResult &block);
    };
}