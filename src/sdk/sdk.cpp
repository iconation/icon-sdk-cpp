#include "sdk.h"
#include "common/dbg/dbg.h"
#include "blockchain/exception.h"
#include "common/exception/exception.h"
#include "exception.h"
#include <ios>
#include <sstream>

using json = nlohmann::json;
using namespace ICONation::SDK::Blockchain;

namespace ICONation::SDK
{
Client::Client(const std::string &endpoint, const Network &nid)
    : m_client(endpoint),
      m_nid(nid)
{
    // Get ICX properties
    ICX::Loop icxSupply = get_total_supply();
    m_icx = std::make_shared<ICX>("ICX", "ICX", icxSupply, 18);
}

json Client::call(const std::string &method, const json &params)
{
    json reply = m_client.call(method, params);

    if (reply.find("error") != reply.end())
    {
        throw SDK::Exception::RPCError(
            reply["error"]["code"].get<int>(),
            reply["error"]["message"].get<std::string>());
    }

    return reply["result"];
}

static void read_transaction_icx_transfer(Transaction &transaction, const json &transactionJson)
{
    transaction.amount() = ICX::Loop(transactionJson["value"].get<std::string>());
}

static void read_transaction_message(Transaction &transaction, const json &transactionJson)
{
    // The transaction message is hex-encoded
    transaction.message() = transactionJson["data"].get<std::string>();
}

static void read_transaction_data(Transaction &transaction, const json &transactionJson)
{
    const std::string &dataType = transactionJson["dataType"].get<std::string>();

    // SCORE Method call transaction
    if (dataType == "call")
    {
        // read_transaction_call (transaction, transactionJson);
    }
    // SCORE Deploy transaction
    else if (dataType == "deploy")
    {
        // read_transaction_deploy (transaction, transactionJson);
    }
    // Message transaction
    else if (dataType == "message")
    {
        read_transaction_message(transaction, transactionJson);
    }
    else
    {
        throw Common::Exception::Unimplemented(fmt::format("Invalid transaction dataType : {}", transactionJson.dump(4)));
    }
}

static void read_transaction_v3(Transaction &transaction, const json &transactionJson)
{
    transaction.from() = Address(transactionJson["from"].get<std::string>());
    transaction.to() = Address(transactionJson["to"].get<std::string>());
    transaction.hash() = Transaction::Hash(transactionJson["txHash"].get<std::string>());
    transaction.stepLimit() = ICX::Step(transactionJson["stepLimit"].get<std::string>());

    if (transactionJson.find("value") != transactionJson.end())
    {
        // ICX transfer transaction
        read_transaction_icx_transfer(transaction, transactionJson);
    }

    if (transactionJson.find("dataType") != transactionJson.end())
    {
        read_transaction_data(transaction, transactionJson);
    }
}

static void read_transaction_v2(Transaction &transaction, const json &transactionJson)
{
    // Fee = stepPrice * stepUsed
    ICX::Loop fee(transactionJson["fee"].get<std::string>());

    // For transaction v2, the step price was fixed to 10 GLoops
    const ICX::Loop stepPrice = (ICX::Loop)10 * 1000 * 1000 * 1000;
    const ICX::Step stepUsed = fee / stepPrice;

    transaction.from() = Address(transactionJson["from"].get<std::string>());
    transaction.to() = Address(transactionJson["to"].get<std::string>());
    transaction.hash() = Transaction::Hash(transactionJson["tx_hash"].get<std::string>());
    transaction.amount() = ICX::Loop(transactionJson["value"].get<std::string>());
    transaction.stepLimit() = 0;
    transaction.stepPrice() = stepPrice;
    transaction.stepUsed() = stepUsed;
}

static void read_transaction_content(Transaction &transaction, const json &transactionJson)
{
    // Determine transaction version
    if (transactionJson.find("version") != transactionJson.end())
    {
        // Get transaction version
        uint64_t version = std::stoull(transactionJson["version"].get<std::string>(), nullptr, 16);

        switch (version)
        {
        case 3:
            read_transaction_v3(transaction, transactionJson);
            break;
        default:
            throw Blockchain::Exception::InvalidTransactionVersion(version);
            break;
        }
    }
    else
    {
        // Field "version" hasn't been found, assume it is a transaction v2
        read_transaction_v2(transaction, transactionJson);
    }
}

void Client::read_event_logs(Transaction &transaction, const json &eventLogs)
{
    // IRC2 Token cache, so we don't need to query the SCORE API for every token internal transaction
    std::map<Address::Hash::Value, std::shared_ptr<IRC2>> irc2Cache;

    for (auto &event : eventLogs)
    {
        if (event["indexed"][0] == "ICXTransfer(Address,Address,int)")
        {
            // Detect ICX transfer internal transaction event log :
            /*
                    "ICXTransfer(Address,Address,int)",
                    "cxe8d1653afd4b475db63cc608948f4d87e2513e57",
                    "hx7547c5e1e837c842b74b6772131c0d3f5d1a1931",
                    "0x6c6b935b8bbd400000"
                */
            Address from(event["indexed"][1].get<std::string>());
            Address to(event["indexed"][2].get<std::string>());
            Token::Unit amount(event["indexed"][3].get<std::string>());

            InternalTransaction internalTx(from, to, m_icx, amount);
            transaction.internalTransactions().emplace_back(internalTx);
        }
        else if (event["indexed"][0] == "Transfer(Address,Address,int,bytes)")
        {
            // Detect IRC2 token transfer internal transaction event log :
            /*
                    "scoreAddress": "cxc86092b996a57f9fdddd8dcb1055d6e0063d75cf",
                    "indexed": [
                        "Transfer(Address,Address,int,bytes)",
                        "cxc86092b996a57f9fdddd8dcb1055d6e0063d75cf",
                        "hxfc08af599f5d3efae34b8aaead15cd848d0857b8",
                        "0x1bc16d674ec80000"
                    ]
                */
            Address from(event["indexed"][1].get<std::string>());
            Address to(event["indexed"][2].get<std::string>());
            Token::Unit amount(event["indexed"][3].get<std::string>());

            // Get IRC2 token properties
            std::shared_ptr<IRC2> irc2;
            Address scoreAddress(event["scoreAddress"].get<std::string>());

            // Try to get the token from the cache
            if (irc2Cache.find(scoreAddress.value()) != irc2Cache.end())
            {
                // Hit
                irc2 = irc2Cache[scoreAddress.value()];
            }
            else
            {
                // Miss
                irc2 = std::make_shared<IRC2>(get_irc2_token(scoreAddress));
                irc2Cache[scoreAddress.value()] = irc2;
            }

            InternalTransaction internalTx(from, to, irc2, amount);
            transaction.internalTransactions().emplace_back(internalTx);
        }
    }
}

bool Client::irc2_token_compliant(const Address &score)
{
    std::vector<std::string> methods = {"name", "symbol", "decimals", "totalSupply", "balanceOf", "transfer"};
    size_t match = 0;

    json apis = get_score_api(score);

    for (const auto &api : apis)
    {
        if (std::find(methods.begin(), methods.end(), api["name"]) != methods.end())
        {
            match += 1;
        }
    }

    return match == methods.size();
}

IRC2 Client::get_irc2_token(const Address &score)
{
    // Check IRC2 standard compliance
    if (!irc2_token_compliant(score))
    {
        throw Blockchain::Exception::InvalidIRC2Token(score);
    }

    Token::Name name(call_score_readonly(score, "name").get<Token::Name>());
    Token::Symbol symbol(call_score_readonly(score, "symbol").get<Token::Symbol>());
    Token::Unit totalSupply(call_score_readonly(score, "totalSupply").get<std::string>());
    Token::Decimal decimals(std::stoi(call_score_readonly(score, "decimals").get<std::string>(), nullptr, 16));

    return IRC2(score, name, symbol, totalSupply, decimals);
}

Transaction Client::read_transaction(const json &transactionJson)
{
    Transaction transaction;

    read_transaction_content(transaction, transactionJson);

    // Get the additionnal data from icx_getTransactionResult
    TransactionResult result = get_transaction_result(transaction.hash());
    transaction.stepPrice() = result.stepPrice();
    transaction.stepUsed() = result.stepUsed();
    if (!result.eventLogs().empty())
    {
        read_event_logs(transaction, result.eventLogs());
    }

    transaction.check_consistency();
    return transaction;
}

static Block read_block_information(const json &result)
{
    Block::Height height = result["height"].get<Block::Height>();

    // If it is genesis block, SDK should return a GenesisBlock to the user
    if (height == GENESIS_BLOCK_HEIGHT)
    {
        throw Blockchain::Exception::InvalidBlockHeight(GENESIS_BLOCK_HEIGHT, "Call get_genesis_block() for the genesis block");
    }

    Block::Hash blockHash = Block::Hash(result["block_hash"].get<std::string>());
    Block::Timestamp timestamp = result["time_stamp"].get<Block::Timestamp>();
    Block::Hash previousBlockHash = Block::Hash(result["prev_block_hash"].get<std::string>());

    return Block(height, blockHash, previousBlockHash, timestamp);
}

void Client::read_block_transactions(Block &block, const json &result)
{
    for (auto &transactionJson : result["confirmed_transaction_list"])
    {
        Transaction transaction = read_transaction(transactionJson);
        block.transactions().push_back(transaction);
    }
}

Block Client::read_block(const json &result)
{
    Block block = read_block_information(result);

    // Add transactions
    if (result.find("confirmed_transaction_list") != result.end())
    {
        read_block_transactions(block, result);
    }

    return block;
}

Block Client::get_last_block(void)
{
    // Build params
    json params;

    // RPC Call
    json result = call("icx_getLastBlock", params);

    // Read result
    return read_block(result);
}

// ====================================================================================================
// == Genesis Block ===================================================================================
// ====================================================================================================

static Account read_genesis_account(const json &accountJson)
{
    Address address(accountJson["address"].get<std::string>());
    ICX::Loop amount(accountJson["balance"].get<std::string>());
    return Account(address, amount);
}

static std::vector<Account> read_genesis_accounts(const json &transactionJson)
{
    std::vector<Account> accounts;

    for (auto &accountJson : transactionJson["accounts"])
    {
        accounts.emplace_back(read_genesis_account(accountJson));
    }

    return accounts;
}

static GenesisBlock read_genesis_block_information(const json &result)
{
    Block::Height height = result["height"].get<Block::Height>();

    // If it is genesis block, SDK should return a GenesisBlock to the user
    if (height != GENESIS_BLOCK_HEIGHT)
    {
        throw Blockchain::Exception::InvalidBlockHeight(GENESIS_BLOCK_HEIGHT,
                                                        "read_genesis_block_information() should be called only for the genesis block");
    }

    Block::Hash blockHash = Block::Hash(result["block_hash"].get<std::string>());
    Block::Timestamp timestamp = result["time_stamp"].get<Block::Timestamp>();

    return GenesisBlock(blockHash, timestamp);
}

static void read_genesis_block_transactions(GenesisBlock &genesis, const json &result)
{
    for (auto &transactionJson : result["confirmed_transaction_list"])
    {
        std::vector<Account> accounts = read_genesis_accounts(transactionJson);

        // Append accounts to the genesis block
        genesis.accounts().insert(
            std::end(genesis.accounts()),
            std::begin(accounts),
            std::end(accounts));
    }
}

static GenesisBlock read_genesis_block(const json &result)
{
    GenesisBlock genesis = read_genesis_block_information(result);

    // Add transactions
    if (result.find("confirmed_transaction_list") != result.end())
    {
        read_genesis_block_transactions(genesis, result);
    }

    return genesis;
}

GenesisBlock Client::get_genesis_block(void)
{
    // Build params
    json params;
    params["height"] = fmt::format("{:#x}", GENESIS_BLOCK_HEIGHT);

    // RPC Call
    json result = call("icx_getBlockByHeight", params);

    // Read result
    return read_genesis_block(result);
}

Block Client::get_block_by_height(const Block::Height &height)
{
    // Build params
    json params;
    params["height"] = fmt::format("{:#x}", height);

    // RPC Call
    json result = call("icx_getBlockByHeight", params);

    // Read result
    return read_block(result);
}

Block Client::get_block_by_hash(const Block::Hash &hash)
{
    // Build params
    json params;
    params["hash"] = hash.to_string();

    // RPC Call
    json result = call("icx_getBlockByHash", params);

    // Read result
    return read_block(result);
}

ICX::Loop Client::get_balance(const Address &address)
{
    // Build params
    json params;
    params["address"] = address.to_string();

    // RPC Call
    json result = call("icx_getBalance", params);

    // Read result
    return ICX::Loop(result.get<std::string>());
}

json Client::get_score_api(const Address &address)
{
    // Build params
    json params;
    params["address"] = address.to_string();

    // RPC Call
    json result = call("icx_getScoreApi", params);

    // Read result
    return result;
}

ICX::Loop Client::get_total_supply(void)
{
    // Build params
    json params;

    // RPC Call
    json result = call("icx_getTotalSupply", params);

    // Read result
    return ICX::Loop(result.get<std::string>());
}

Transaction Client::get_transaction_by_hash(const Transaction::Hash &hash)
{
    // Build params
    json params;
    params["txHash"] = hash.to_string();

    // RPC Call
    json result = call("icx_getTransactionByHash", params);

    // Read result
    return read_transaction(result);
}

TransactionResult Client::get_transaction_result(const Transaction::Hash &hash)
{
    // Build params
    json params;
    params["txHash"] = hash.to_string();

    // RPC Call
    json result = call("icx_getTransactionResult", params);

    // Read result
    Address to = Address(result["to"].get<std::string>());
    Block::Height height = std::stoull(result["blockHeight"].get<std::string>(), nullptr, 16);
    Block::Hash blockHash = Block::Hash(result["blockHash"].get<std::string>());
    Transaction::Hash txHash = Transaction::Hash(result["txHash"].get<std::string>());
    ICX::Step stepUsed = ICX::Step(result["stepUsed"].get<std::string>());
    ICX::Step stepPrice = ICX::Step(result["stepPrice"].get<std::string>());
    json eventLogs = result["eventLogs"];

    return TransactionResult(to, height, blockHash, txHash, stepUsed, stepPrice, eventLogs);
}

SDK::Blockchain::Wallet Client::wallet_create(void)
{
    return Wallet::create();
}

SDK::Blockchain::Wallet Client::wallet_load(const std::vector<unsigned char> &privateKey)
{
    return Wallet::load(privateKey);
}

SDK::Blockchain::Wallet Client::wallet_load(const void *privateKeyBytes)
{
    std::vector<unsigned char> privateKey(PRIVATE_KEY_SIZE);
    memcpy(&privateKey[0], privateKeyBytes, PRIVATE_KEY_SIZE);
    return Wallet::load(privateKey);
}

SDK::Blockchain::Wallet Client::wallet_load(const std::experimental::filesystem::path &keystore, const std::string &password)
{
    return Wallet::load(keystore, password);
}

Transaction::Hash Client::wallet_send_icx(
    const SDK::Blockchain::Wallet &wallet,
    const Address &to,
    const ICX::Loop &value,
    const ICX::Step &stepLimit,
    const int &nonce)
{
    // Build params
    json params = wallet.get_signed_icx_transaction(to, value, stepLimit, m_nid, nonce);

    // RPC Call
    json result = call("icx_sendTransaction", params);

    return result.get<std::string>();
}

json Client::call_score_readonly(const Address &score, const std::string &method, const json &callParams)
{
    // Build params
    json params;

    params["dataType"] = "call";
    params["to"] = score.to_string();
    params["data"]["method"] = method;

    if (!callParams.empty())
    {
        params["data"]["params"] = callParams;
    }

    // RPC Call
    json result = call("icx_call", params);

    // Read result
    return result;
}

Transaction::Hash Client::wallet_call_score(
    const SDK::Blockchain::Wallet &wallet,
    const Address &score,
    const std::string &method, const json &callParams,
    const ICX::Step &stepLimit,
    const int &nonce)
{
    // Build params
    json params = wallet.get_signed_call_transaction(score, method, callParams, stepLimit, m_nid, nonce);

    // RPC Call
    json result = call("icx_sendTransaction", params);

    return result.get<std::string>();
}

Blockchain::Transaction::Hash Client::wallet_deploy(
    const Blockchain::Wallet &wallet,
    const Blockchain::Address &score,
    const std::string &contentType, const std::vector<unsigned char> &content, const nlohmann::json &callParams,
    const Blockchain::ICX::Step &stepLimit,
    const int &nonce)
{
    // Build params
    json params = wallet.get_signed_deploy_transaction(score, contentType, content, callParams, stepLimit, m_nid, nonce);

    // RPC Call
    json result = call("icx_sendTransaction", params);

    return result.get<std::string>();
}

ICX::Loop Client::get_step_price(void)
{
    return ICX::Loop(call_score_readonly(GOVERNANCE_SCORE_ADDRESS, "getStepPrice", {}).get<std::string>());
}

json Client::ise_getStatus(const std::vector<std::string> &filters)
{
    // Build params
    json params;

    if (!filters.empty())
    {
        params["filter"] = filters;
    }

    // RPC Call
    json result = call("ise_getStatus", params);

    // Read result
    return result;
}
} // namespace ICONation::SDK