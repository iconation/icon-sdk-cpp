#include "token.h"
#include "exception.h"
#include "common/exception/exception.h"

namespace ICONation::SDK::Blockchain
{
// 1 ICX = 10 ** 18 Loop
const ICX::Loop ICX::TO_LOOP = 1000000000000000000;

Token::Token(const Type &type, const Name &name, const Symbol &symbol, const Unit &totalSupply, const Decimal &decimals)
    : m_type(type),
      m_name(name),
      m_symbol(symbol),
      m_totalSupply(totalSupply),
      m_decimals(decimals)
{
}

ICX::ICX(const Name &name, const Symbol &symbol, const Unit &totalSupply, const Decimal &decimals)
    : Token(Token::Type::ICX, name, symbol, totalSupply, decimals)
{
}

IRC2::IRC2(const Address &score, const Name &name, const Symbol &symbol, const Unit &totalSupply, const Decimal &decimals)
    : Token(Token::Type::IRC2, name, symbol, totalSupply, decimals),
      m_score(score)
{
}

std::string Token::to_string(void) const
{
    return fmt::format("{} ({}) | {} | {}", m_name, m_symbol, m_totalSupply, m_decimals);
}

std::ostream &operator<<(std::ostream &stream, const Token &token)
{
    stream << token.to_string();
    return stream;
}
} // namespace ICONation::SDK::Blockchain