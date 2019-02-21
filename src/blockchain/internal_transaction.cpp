#include "internal_transaction.h"

namespace ICONation::SDK::Blockchain
{
    InternalTransaction::InternalTransaction (const Address &from, const Address &to, const std::shared_ptr<Token> &token, const Token::Unit &amount)
    :   m_from (from),
        m_to (to),
        m_token (token),
        m_amount (amount)
    {
    }
}