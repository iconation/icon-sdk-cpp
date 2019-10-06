#pragma once

#include "account.h"
#include "token.h"
#include "internal_transaction.h"
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace ICONation::SDK::Blockchain
{
// Constants
const size_t TX_HASH_SIZE = 64;
const Hash::Prefix TX_HASH_PREFIX = "0x";

class Transaction
{
    // Transaction specific types
public:
    typedef uint64_t Timestamp;

    class Hash : public Blockchain::Hash
    {
        // Allocators
    public:
        Hash(const std::string &input)
            : Blockchain::Hash(input, TX_HASH_PREFIX, TX_HASH_SIZE) {}
        Hash(const char *input)
            : Transaction::Hash(std::string(input)) {}
        // Need to call the consistency check externally
        Hash(void)
            : Blockchain::Hash(TX_HASH_PREFIX, TX_HASH_SIZE) {}
        ~Hash(void) = default;
    };

    // Allocator
public:
    // Empty transaction - consistency checks must be done manually
    // Should be used only for building a transaction
    Transaction(void);

    // Create a consistent transaction
    Transaction(
        const Transaction::Hash &hash,
        const Address &from,
        const Address &to,
        const ICX::Loop &amount);

    ~Transaction(void) = default;

    // Consistency checks
public:
    void check_consistency(void) const;

    // Hash
public:
    const Transaction::Hash &hash(void) const { return m_hash; }
    Transaction::Hash &hash(void) { return m_hash; }

private:
    Transaction::Hash m_hash;

    // Sender & Receiver
public:
    const Address &to(void) const { return m_to; }
    Address &to(void) { return m_to; }

private:
    Address m_from;

public:
    const Address &from(void) const { return m_from; }
    Address &from(void) { return m_from; }

private:
    Address m_to;

    // ICX Amount
public:
    const ICX::Loop &amount(void) const { return m_amount; }
    ICX::Loop &amount(void) { return m_amount; }

private:
    ICX::Loop m_amount;

    // Transaction message
public:
    const std::string &message(void) const { return m_message; }
    std::string &message(void) { return m_message; }

private:
    std::string m_message;

    // Steps
public:
    const ICX::Step &stepUsed(void) const { return m_stepUsed; }
    ICX::Step &stepUsed(void) { return m_stepUsed; }

private:
    ICX::Step m_stepUsed;

public:
    const ICX::Step &stepLimit(void) const { return m_stepLimit; }
    ICX::Step &stepLimit(void) { return m_stepLimit; }

private:
    ICX::Step m_stepLimit;

public:
    const ICX::Loop &stepPrice(void) const { return m_stepPrice; }
    ICX::Loop &stepPrice(void) { return m_stepPrice; }

private:
    ICX::Loop m_stepPrice;

    // Internal transactions
public:
    std::vector<InternalTransaction> &internalTransactions(void) { return m_internalTransactions; }
    const std::vector<InternalTransaction> &internalTransactions(void) const { return m_internalTransactions; }

private:
    std::vector<InternalTransaction> m_internalTransactions;

    // Function for debug purposes
public:
    std::string to_string(void) const;

public:
    friend std::ostream &operator<<(std::ostream &stream, const Transaction &block);
};
} // namespace ICONation::SDK::Blockchain