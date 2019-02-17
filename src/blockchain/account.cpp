#include "account.h"
#include "exception.h"
#include <fmt/format.h>

namespace ICONation::SDK::Blockchain
{
    Account::Account (const Address &address)
    :   m_address (address),
        m_balance (0)
    {
        check_consistency();
    }

    Account::Account (const Address &address, const ICX::Loop &balance)
    :   m_address (address),
        m_balance (balance)
    {
        check_consistency();
    }

    void Account::check_consistency (void) const
    {
        m_address.check_consistency();
    }

    void Account::transfer (Account &dest, const ICX::Loop &amount)
    {
        withdraw (amount);
        dest.deposit (amount);
    }

    void Account::withdraw (const ICX::Loop &amount)
    {
        if (m_balance < amount) {
            throw Blockchain::Exception::NotEnoughFunds (*this, amount);
        }

        m_balance -= amount;
    }

    void Account::deposit (const ICX::Loop &amount)
    {
        m_balance += amount;
    }

    std::string Account::to_string (void) const
    {
        return fmt::format ("'{}' | Balance : {} loops", m_address.to_string(), m_balance);
    }

    std::ostream &operator << (std::ostream &stream, const Account &account)
    {
        stream << account.to_string();
        return stream;
    }
}