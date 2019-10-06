#include "genesis_block.h"
#include "exception.h"
#include "common/exception/exception.h"
#include <fmt/format.h>

namespace ICONation::SDK::Blockchain
{
GenesisBlock::GenesisBlock(const Block::Hash &hash, const Timestamp &timestamp)
    : Block::Block(GENESIS_BLOCK_HEIGHT, hash, GENESIS_PREVIOUS_HASH, timestamp)
{
    check_consistency();
}
} // namespace ICONation::SDK::Blockchain