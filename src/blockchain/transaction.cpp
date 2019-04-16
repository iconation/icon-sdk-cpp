#include "transaction.h"
#include "exception.h"
#include "common/exception/exception.h"
#include "common/dbg/dbg.h"
#include <fmt/format.h>

namespace ICONation::SDK::Blockchain
{
    Transaction::Transaction (void)
    :   m_amount (0)
    {
    }

    Transaction::Transaction (
        const Transaction::Hash &hash, 
        const Address &from, 
        const Address &to,
        const ICX::Loop &amount
    )
    :   m_hash (hash),
        m_from (from),
        m_to (to),
        m_amount (amount)
    {
        check_consistency();
    }

    void Transaction::check_consistency (void) const
    {
        m_hash.check_consistency();
        m_from.check_consistency();
        m_to.check_consistency();
    }

    std::string Transaction::to_string (void) const
    {
        return m_hash.to_string();
    }

    std::ostream &operator << (std::ostream &stream, const Transaction &tx) {
        stream << tx.to_string();
        return stream;
    }
}