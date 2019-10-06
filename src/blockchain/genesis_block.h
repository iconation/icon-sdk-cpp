#pragma once

#include "block.h"

namespace ICONation::SDK::Blockchain
{
const Block::Hash GENESIS_PREVIOUS_HASH = "0x0000000000000000000000000000000000000000000000000000000000000000";
const Block::Height GENESIS_BLOCK_HEIGHT = 0;

class GenesisBlock : public Block
{
    // Allocators
public:
    GenesisBlock(void) = default;
    GenesisBlock(const Block::Hash &hash, const Timestamp &timestamp);
    ~GenesisBlock(void) = default;

    // Accounts
private:
    std::vector<Account> m_accounts;

public:
    std::vector<Account> &accounts(void) { return m_accounts; }
    const std::vector<Account> &accounts(void) const { return m_accounts; }
};
} // namespace ICONation::SDK::Blockchain