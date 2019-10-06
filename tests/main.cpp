#include <gtest/gtest.h>
#include "sdk/sdk.h"
#include "sdk/exception.h"
#include "blockchain/exception.h"
#include "common/exception/exception.h"
#include "common/dbg/dbg.h"
#include "common/http/http.h"
#include <chrono>
#include <thread>

using namespace ICONation::Common;
using namespace ICONation::SDK::Blockchain;

#define DEBUG_TRY_CATCH(_x)                                \
    try                                                    \
    {                                                      \
        _x;                                                \
    }                                                      \
    catch (const std::exception &e)                        \
    {                                                      \
        Dbg::error("Application exception :");             \
        Dbg::error("    - Type   : {}", typeid(e).name()); \
        Dbg::error("    - Reason : {}", e.what());         \
    }

namespace ICONation::SDK::Tests
{
// Global variables
// ICONation Testnet citizen node
SDK::Client client("http://iconation.team:9000/api/v3", EULJIRO);
// SDK::Client client ("https://testwallet.icon.foundation/api/v3", EULJIRO);
// I wonder how much time it will last until someone steal our testnet ICX :D
// hx520707648aff4291e9686304acacbd82396ecefa
const Wallet wallet = client.wallet_load(
    "\xB7\x94\x3E\x8C\xE2\x1B\x73\x27"
    "\x3A\x4E\xFB\x18\x65\x49\x44\xB7"
    "\x29\xCD\xBA\xFD\xF3\x22\xBE\xC1"
    "\xCD\xAD\xF8\xD5\x38\xD3\x26\x6B");

// Usable objects
Block::Hash emptyBlockHash("0x0000000000000000000000000000000000000000000000000000000000000000");
Address emptyAddress("hx0000000000000000000000000000000000000000");
Transaction::Hash emptyTxHash("0x0000000000000000000000000000000000000000000000000000000000000000");
Transaction emptyTx(emptyTxHash, emptyAddress, emptyAddress, 0);
TransactionResult emptyTxResult(emptyAddress, 0, emptyBlockHash.value(), emptyTx.hash().value(), 0, 0, {});

TEST(Hash, BlockHash)
{
    // OK
    EXPECT_NO_THROW(Block::Hash("0x0000000000000000000000000000000000000000000000000000000000000000"));
    EXPECT_NO_THROW(Block::Hash("0000000000000000000000000000000000000000000000000000000000000000"));
    // Wrong prefix
    EXPECT_THROW(Block::Hash("hx0000000000000000000000000000000000000000000000000000000000000000"), Blockchain::Exception::InvalidHexOnly);
    EXPECT_THROW(Block::Hash("cx0000000000000000000000000000000000000000000000000000000000000000"), Blockchain::Exception::InvalidHexOnly);
    // Wrong size
    EXPECT_THROW(Block::Hash("0x000000000000000000000000000000000000000000000000000000000000000"), Common::Exception::InvalidSize);
    // Hex only
    EXPECT_THROW(Block::Hash("0xZZZZZZZZZZZ"), Blockchain::Exception::InvalidHexOnly);
}

TEST(Hash, TransactionHash)
{
    // OK
    EXPECT_NO_THROW(Transaction::Hash("0x0000000000000000000000000000000000000000000000000000000000000000"));
    EXPECT_NO_THROW(Transaction::Hash("0000000000000000000000000000000000000000000000000000000000000000"));
    // Wrong prefix
    EXPECT_THROW(Transaction::Hash("hx0000000000000000000000000000000000000000000000000000000000000000"), Blockchain::Exception::InvalidHexOnly);
    EXPECT_THROW(Transaction::Hash("cx0000000000000000000000000000000000000000000000000000000000000000"), Blockchain::Exception::InvalidHexOnly);
    // Wrong size
    EXPECT_THROW(Transaction::Hash("0x000000000000000000000000000000000000000000000000000000000000000"), Common::Exception::InvalidSize);
    // Hex only
    EXPECT_THROW(Transaction::Hash("0xZZZZZZZZZZZ"), Blockchain::Exception::InvalidHexOnly);
}

TEST(Hash, Address)
{
    // OK
    EXPECT_NO_THROW(Address("hx0000000000000000000000000000000000000000"));
    EXPECT_NO_THROW(Address("cx0000000000000000000000000000000000000000"));
    EXPECT_NO_THROW(Address("0000000000000000000000000000000000000000"));
    // Wrong prefix
    EXPECT_THROW(Address("0x0000000000000000000000000000000000000000000000000000000000000000"), Blockchain::Exception::InvalidHexOnly);
    // Wrong size
    EXPECT_THROW(Address("hx000000000000000000000000000000000000000000000000000000000000000"), Common::Exception::InvalidSize);
    // Hex only
    EXPECT_THROW(Address("hxZZZZZZZZZZZ"), Blockchain::Exception::InvalidHexOnly);
}

TEST(RPC, ICX_GetLastBlock)
{
    // Check success
    EXPECT_NO_THROW(client.get_last_block());
}

TEST(RPC, ICX_GetBlockByHeight)
{
    Block block1, block2;

    EXPECT_NO_THROW(
        block1 = client.get_last_block();
        block2 = client.get_block_by_height(block1.height()););

    // Check success
    EXPECT_TRUE(block1.height() == block2.height());
    EXPECT_TRUE(block1.hash().to_string() == block2.hash().to_string());
    EXPECT_TRUE(block1.timestamp() == block2.timestamp());
    EXPECT_TRUE(block1.transactions().size() == block2.transactions().size());
    EXPECT_NO_THROW(block1.check_consistency());
    EXPECT_NO_THROW(block2.check_consistency());

    // Check errors
    EXPECT_THROW(client.get_block_by_height(-1), SDK::Exception::RPCError);
}

TEST(RPC, ICX_ReadTransactionData)
{
    Block block;

    EXPECT_NO_THROW(block = client.get_block_by_height(56189));
    EXPECT_EQ(block.transactions().size(), 1);
    const auto &transaction = block.transactions()[0];
    EXPECT_STREQ(transaction.hash().to_string().c_str(), "0xd5d298eb694c46d5485579bc56efa1548d09a9940dd82f74b0638082248da473");
    EXPECT_EQ(transaction.message().size(), 1381);
}

TEST(RPC, ICX_GetGenesisBlock)
{
    GenesisBlock genesis;

    // get_block_by_height (GENESIS_BLOCK_HEIGHT) shouldn't be called
    EXPECT_THROW(client.get_block_by_height(GENESIS_BLOCK_HEIGHT), Blockchain::Exception::InvalidBlockHeight);

    EXPECT_NO_THROW(genesis = client.get_genesis_block());

    // Check success
    EXPECT_TRUE(genesis.height() == GENESIS_BLOCK_HEIGHT);
    EXPECT_NO_THROW(genesis.check_consistency());
}

TEST(RPC, ICX_GetBlockByHash)
{
    Block block1, block2;

    EXPECT_NO_THROW(
        block1 = client.get_last_block();
        block2 = client.get_block_by_hash(block1.hash()););

    // Check success
    EXPECT_TRUE(block1.height() == block2.height());
    EXPECT_TRUE(block1.hash().to_string() == block2.hash().to_string());
    EXPECT_TRUE(block1.timestamp() == block2.timestamp());
    EXPECT_TRUE(block1.transactions().size() == block2.transactions().size());
}

TEST(RPC, ICX_GetScoreApi)
{
    EXPECT_NO_THROW(client.get_score_api(GOVERNANCE_SCORE_ADDRESS));
}

TEST(RPC, ICX_GetTotalSupply)
{
    ICX::Loop loops;

    EXPECT_NO_THROW(loops = client.get_total_supply());
    // On testnet, total supply is 800,460,000 ICX
    EXPECT_TRUE(loops == (800460000 * ICX::TO_LOOP));
}

TEST(RPC, ICX_GetTransactionResult)
{
    TransactionResult result = emptyTxResult;
    Transaction::Hash hash = emptyTxHash;

    // Let's make sure we have a balance
    while (client.get_balance(wallet.get_address()) == 0)
    {
        Dbg::warn("The wallet balance is zero. Retrying...");
    }

    EXPECT_NO_THROW(hash = client.wallet_send_icx(wallet, GOVERNANCE_SCORE_ADDRESS, 0, 1000000));

    // Wait
    Dbg::info("Waiting for 2 seconds...");
    std::this_thread::sleep_for(std::chrono::milliseconds(2 * 1000));

    EXPECT_NO_THROW(result = client.get_transaction_result(hash));

    EXPECT_TRUE(result.txHash().to_string() == hash.to_string());
}

TEST(RPC, ICX_GetTransactionByHash)
{
    Transaction tx = emptyTx;
    Transaction::Hash hash = emptyTxHash;

    // Let's make sure we have a balance
    while (client.get_balance(wallet.get_address()) == 0)
    {
        Dbg::warn("The wallet balance is zero. Retrying...");
    }

    EXPECT_NO_THROW(hash = client.wallet_send_icx(wallet, GOVERNANCE_SCORE_ADDRESS, 0, 1000000));

    // Wait
    Dbg::info("Waiting for 2 seconds...");
    std::this_thread::sleep_for(std::chrono::milliseconds(2 * 1000));

    EXPECT_NO_THROW(tx = client.get_transaction_by_hash(hash););

    EXPECT_TRUE(tx.hash().to_string() == hash.to_string());
}

TEST(RPC, ICX_CallScoreReadOnly)
{
    nlohmann::json result;
    ICX::Loop price;

    EXPECT_NO_THROW(
        result = client.call_score_readonly(GOVERNANCE_SCORE_ADDRESS, "getStepPrice", {});
        price = ICX::Loop(result.get<std::string>()););

    result = client.call_score_readonly(GOVERNANCE_SCORE_ADDRESS, "getScoreStatus", {{"address", GOVERNANCE_SCORE_ADDRESS.to_string()}});

    EXPECT_GT(price, 0);
}

TEST(RPC, ICX_GetBalance)
{
    ICX::Loop loops = client.get_balance(wallet.get_address());

    // May fail if someone steal everything in the wallet, or if the balance goes to zero
    // due to transactions fees
    EXPECT_GE(loops, (1 * ICX::TO_LOOP));
}

TEST(RPC, ICX_WalletSendICX)
{
    // Let's send 0 ICX to the governance wallet
    EXPECT_NO_THROW(
        client.wallet_send_icx(wallet, GOVERNANCE_SCORE_ADDRESS, 0, 1000000););
}

TEST(RPC, ICX_WalletCallScore)
{
    // Random score contract - it should still return an error, but the rpc call is OK
    EXPECT_NO_THROW(
        client.wallet_call_score(wallet, "cxb2c9ebf66cae9dc46dd2c79a192ca2213035d159",
                                 "unlock", {{"account", "hx37b0ae56424d50f791500530c094903f3604f988"}, {"amount", "0x1"}}, 1000000, 100));
}

TEST(RPC, ICX_WalletDeploy)
{
    // As there is no faucet on EULJIRO, keep the wallet deploy
    // for YEOUIDO only.
    if (client.network() == YEOUIDO)
    {
        // Assume 1 ICX = 100 millions steps
        ICX::Loop ICX_TO_STEP = ICX::TO_LOOP / client.get_step_price();

        // Hello world ZIP contract
        std::vector<unsigned char> zip = {
            0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0D, 0x2D, 0x2F, 0x4E, 0xB9, 0x9F,
            0x5B, 0x10, 0x32, 0x01, 0x00, 0x00, 0xD7, 0x02, 0x00, 0x00, 0x1A, 0x00, 0x00, 0x00, 0x68, 0x65,
            0x6C, 0x6C, 0x6F, 0x5F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x2F, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x5F,
            0x77, 0x6F, 0x72, 0x6C, 0x64, 0x2E, 0x70, 0x79, 0x8D, 0x92, 0xCB, 0x6E, 0xC2, 0x30, 0x10, 0x45,
            0xF7, 0xFE, 0x8A, 0x29, 0x1B, 0x92, 0x2A, 0xE5, 0x03, 0x22, 0x51, 0x95, 0xAA, 0xEA, 0x43, 0xAA,
            0xBA, 0x29, 0x52, 0x97, 0xD1, 0x38, 0x9E, 0x50, 0x0B, 0xC7, 0x8E, 0xC6, 0x0E, 0x2D, 0x7F, 0x5F,
            0x27, 0x94, 0x04, 0x24, 0x40, 0x78, 0x61, 0xF9, 0x71, 0xEF, 0xB9, 0xF6, 0xD8, 0x15, 0xBB, 0x1A,
            0x74, 0xE9, 0xAC, 0x27, 0xDE, 0xE8, 0x92, 0x40, 0xD7, 0x8D, 0xE3, 0x00, 0xB7, 0x42, 0x2C, 0x17,
            0x2F, 0x30, 0x87, 0xE9, 0x2B, 0x19, 0xE3, 0xBE, 0x1C, 0x1B, 0x35, 0x15, 0xA2, 0x34, 0xE8, 0x3D,
            0x8C, 0x4B, 0xC9, 0x5B, 0xB4, 0x7E, 0x96, 0x8E, 0xE9, 0x11, 0x3D, 0xA5, 0xB9, 0x10, 0x10, 0x9B,
            0xA2, 0x0A, 0x8A, 0x42, 0x5B, 0x1D, 0x8A, 0x22, 0xF1, 0x64, 0xAA, 0x0C, 0x94, 0xCC, 0x61, 0xD0,
            0x3E, 0x61, 0x40, 0xD9, 0xE9, 0xE1, 0xEE, 0x1E, 0x3E, 0x9C, 0xA5, 0xBC, 0xB7, 0x75, 0xCD, 0xB7,
            0x0D, 0x71, 0x92, 0xCE, 0x06, 0xBB, 0x92, 0xE9, 0x08, 0x75, 0x36, 0x2E, 0xFB, 0x80, 0xC6, 0xF4,
            0xD8, 0x0B, 0xFE, 0x03, 0xE5, 0xB1, 0xBF, 0x6D, 0x14, 0x06, 0xBA, 0xC2, 0xFE, 0x2F, 0x4C, 0xFB,
            0xBD, 0xBE, 0x7B, 0xA0, 0xDF, 0x40, 0x6C, 0xD1, 0x24, 0x4C, 0xA8, 0x9C, 0x35, 0xDB, 0xF9, 0x92,
            0x5B, 0x4A, 0x07, 0xBC, 0xC5, 0xFA, 0x80, 0xEC, 0x03, 0x8F, 0x60, 0xA6, 0xD0, 0xB2, 0x85, 0xC9,
            0x58, 0xBA, 0x89, 0xB8, 0x0E, 0xFA, 0xDD, 0x39, 0xCE, 0x50, 0xDF, 0xDD, 0x6A, 0x45, 0x3C, 0xD3,
            0xB6, 0x72, 0xC9, 0xEE, 0xA1, 0x32, 0xF8, 0xE9, 0xE0, 0x37, 0xD3, 0x0C, 0xE2, 0xFB, 0xA5, 0xA7,
            0xF3, 0xF7, 0xD1, 0x0D, 0x6E, 0x51, 0x1A, 0x1A, 0xA2, 0xAA, 0x58, 0x2E, 0x89, 0xE5, 0x7A, 0x97,
            0x76, 0x26, 0x66, 0x2F, 0x02, 0xED, 0xA1, 0x8C, 0x63, 0x52, 0xFB, 0xAC, 0xE3, 0xFB, 0x0C, 0xD4,
            0xE0, 0xD6, 0x64, 0x9F, 0x0F, 0xD1, 0x19, 0x14, 0x55, 0xFC, 0x77, 0x39, 0x2C, 0x94, 0x62, 0xF2,
            0x3E, 0xCE, 0x37, 0x68, 0x5A, 0xCA, 0x41, 0xDB, 0x10, 0x27, 0xB1, 0xF0, 0x98, 0x83, 0xDC, 0x06,
            0xF2, 0xE7, 0x4E, 0x31, 0x40, 0x51, 0x9E, 0x3A, 0xCA, 0x1F, 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00,
            0x00, 0x00, 0x08, 0x00, 0x0D, 0x2D, 0x2F, 0x4E, 0x7E, 0x80, 0x86, 0xE3, 0x42, 0x00, 0x00, 0x00,
            0x5B, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x5F, 0x77, 0x6F,
            0x72, 0x6C, 0x64, 0x2F, 0x70, 0x61, 0x63, 0x6B, 0x61, 0x67, 0x65, 0x2E, 0x6A, 0x73, 0x6F, 0x6E,
            0xAB, 0xE6, 0x52, 0x00, 0x02, 0xA5, 0xB2, 0xD4, 0xA2, 0xE2, 0xCC, 0xFC, 0x3C, 0x25, 0x2B, 0x05,
            0x25, 0x03, 0x3D, 0x03, 0x3D, 0x43, 0x25, 0x1D, 0x88, 0x78, 0x6E, 0x62, 0x66, 0x5E, 0x7C, 0x5A,
            0x66, 0x4E, 0x2A, 0x48, 0x26, 0x23, 0x35, 0x27, 0x27, 0x3F, 0xBE, 0x3C, 0xBF, 0x28, 0x27, 0x05,
            0x45, 0xBE, 0x38, 0x39, 0xBF, 0x08, 0xAC, 0xC0, 0x03, 0xA4, 0x20, 0x1C, 0x2C, 0xCF, 0x55, 0xCB,
            0x05, 0x00, 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0D, 0x2D, 0x2F, 0x4E,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00,
            0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x5F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x2F, 0x5F, 0x5F, 0x69, 0x6E,
            0x69, 0x74, 0x5F, 0x5F, 0x2E, 0x70, 0x79, 0x03, 0x00, 0x50, 0x4B, 0x01, 0x02, 0x14, 0x03, 0x14,
            0x00, 0x00, 0x00, 0x08, 0x00, 0x0D, 0x2D, 0x2F, 0x4E, 0xB9, 0x9F, 0x5B, 0x10, 0x32, 0x01, 0x00,
            0x00, 0xD7, 0x02, 0x00, 0x00, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0xFF, 0x81, 0x00, 0x00, 0x00, 0x00, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x5F, 0x77, 0x6F, 0x72,
            0x6C, 0x64, 0x2F, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x5F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x2E, 0x70,
            0x79, 0x50, 0x4B, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0D, 0x2D, 0x2F,
            0x4E, 0x7E, 0x80, 0x86, 0xE3, 0x42, 0x00, 0x00, 0x00, 0x5B, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x81, 0x6A, 0x01, 0x00, 0x00, 0x68,
            0x65, 0x6C, 0x6C, 0x6F, 0x5F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x2F, 0x70, 0x61, 0x63, 0x6B, 0x61,
            0x67, 0x65, 0x2E, 0x6A, 0x73, 0x6F, 0x6E, 0x50, 0x4B, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00, 0x00,
            0x00, 0x08, 0x00, 0x0D, 0x2D, 0x2F, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
            0x81, 0xE2, 0x01, 0x00, 0x00, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x5F, 0x77, 0x6F, 0x72, 0x6C, 0x64,
            0x2F, 0x5F, 0x5F, 0x69, 0x6E, 0x69, 0x74, 0x5F, 0x5F, 0x2E, 0x70, 0x79, 0x50, 0x4B, 0x05, 0x06,
            0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00, 0xD3, 0x00, 0x00, 0x00, 0x19, 0x02, 0x00, 0x00,
            0x00, 0x00};

        ICX::Loop before, after;
        Transaction::Hash hash = emptyTxHash;

        EXPECT_NO_THROW(before = client.get_balance(wallet.get_address()));
        EXPECT_NO_THROW(
            hash = client.wallet_deploy(wallet, "cx0000000000000000000000000000000000000000",
                                        "application/zip", zip, {}, 15 * ICX_TO_STEP, 100));
        EXPECT_NO_THROW(after = client.get_balance(wallet.get_address()));

        // It should have cost ~10 ICX
        EXPECT_GT(before, after);
    }
}

TEST(RPC, ISE_GetStatus)
{
    nlohmann::json result;
    EXPECT_NO_THROW(result = client.ise_getStatus({"lastBlock"}));
    EXPECT_TRUE(!result["lastBlock"].empty());
}

TEST(RPC, ICX_IsIRC2Compliant)
{
    // Check if a SCORE address hosts an IRC2 Token
    EXPECT_NO_THROW(client.irc2_token_compliant("cxb2c9ebf66cae9dc46dd2c79a192ca2213035d159"));
    EXPECT_NO_THROW(client.get_irc2_token("cxb2c9ebf66cae9dc46dd2c79a192ca2213035d159"));
}
} // namespace ICONation::SDK::Tests

void get_icx_from_faucet(const Address &address)
{
    Dbg::warn("Getting some ICX for address {} ...", address);

    // Get some testnet ICX from faucet
    std::string result = Http::Client().post("http://52.88.70.222/result",
                                             fmt::format("Address={}", address));

    // OK
    if (result.find("Successfully sent"))
    {
        Dbg::info("{} received 20 ICX !", address);
    }

    // Let's wait for a little bit
    Dbg::info("Sleeping for 2 seconds so we got time for a new block");
    std::this_thread::sleep_for(std::chrono::milliseconds(2 * 1000));
}

int main(int argc, char **argv)
{
    using ICONation::SDK::Tests::client;
    using ICONation::SDK::Tests::wallet;

    try
    {
        Dbg::info("Preparing tests...");

        // Get some ICX from the YEOUIDO faucet
        if (client.network() == YEOUIDO)
        {
            get_icx_from_faucet(wallet.get_address());
        }

        testing::InitGoogleTest(&argc, argv);
        return RUN_ALL_TESTS();
    }
    catch (const std::exception &e)
    {
        Dbg::error("Application exception :");
        Dbg::error("    - Type   : {}", typeid(e).name());
        Dbg::error("    - Reason : {}", e.what());
    }

    return 0;
}