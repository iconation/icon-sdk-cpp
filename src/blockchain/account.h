#pragma once

#include "address.h"
#include "token.h"

namespace ICONation::SDK::Blockchain
{
const std::string ZERO_ADDRESS_EOA = "hx0000000000000000000000000000000000000000";
class Account
{
    // Allocators
public:
    Account(const Address &Address);
    Account(const Address &Address, const ICX::Loop &balance);
    ~Account(void) = default;

    // Consistency
public:
    void check_consistency(void) const;

    // Address
public:
    const Address &address(void) const { return m_address; }

private:
    Address m_address;

    // ICX Amount
private:
    ICX::Loop m_balance;

public:
    void transfer(Account &dest, const ICX::Loop &amount);
    void withdraw(const ICX::Loop &amount);
    void deposit(const ICX::Loop &amount);
    const ICX::Loop &balance(void) const { return m_balance; }

    // Function for debug purposes
public:
    std::string to_string(void) const;

public:
    friend std::ostream &operator<<(std::ostream &stream, const Account &pubkey);
};
} // namespace ICONation::SDK::Blockchain