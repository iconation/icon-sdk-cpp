#include "transaction_result.h"
#include <fmt/format.h>
#include <fmt/ostream.h>

namespace ICONation::SDK::Blockchain
{
TransactionResult::TransactionResult(
    const Address &to,
    const Block::Height &height,
    const Block::Hash &blockHash,
    const Transaction::Hash &txHash,
    const ICX::Step &stepUsed,
    const ICX::Loop &stepPrice,
    const nlohmann::json &eventLogs)
    : m_to(to),
      m_height(height),
      m_blockHash(blockHash),
      m_txHash(txHash),
      m_stepUsed(stepUsed),
      m_stepPrice(stepPrice),
      m_eventLogs(eventLogs)
{
}

std::string TransactionResult::to_string(void) const
{
    return fmt::format(
        "to = {} | "
        "height = {} | "
        "Block::Hash = {} | "
        "txHash = {} | "
        "stepUsed = {} | "
        "stepPrice = {} | ",
        m_to,
        m_height,
        m_blockHash,
        m_txHash,
        m_stepUsed,
        m_stepPrice);
}

std::ostream &operator<<(std::ostream &stream, const TransactionResult &tx)
{
    stream << tx.to_string();
    return stream;
}
} // namespace ICONation::SDK::Blockchain
