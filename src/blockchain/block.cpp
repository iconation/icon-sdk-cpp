#include "block.h"
#include "exception.h"
#include "common/exception/exception.h"
#include <fmt/format.h>

namespace ICONation::SDK::Blockchain
{
    Block::Block (const Height &height, const Block::Hash &hash, const Block::Hash &previousHash, const Timestamp &timestamp)
    :   m_height (height),
        m_hash (hash),
        m_timestamp (timestamp),
        m_hashPreviousBlock (previousHash)
    {
        check_consistency();
    }

    void Block::check_consistency (void) const
    {
        m_hash.check_consistency();
        m_hashPreviousBlock.check_consistency();

        for (const auto &tx : m_transactions) {
            tx.check_consistency();
        }
    }

    std::string Block::to_string (void) const
    {
        return fmt::format ("Height = {} | Hash = {} | {} transactions", m_height, m_hash.to_string(), m_transactions.size());
    }

    std::ostream &operator << (std::ostream &stream, const Block &block) {
        stream << block.to_string();
        return stream;
    }
}