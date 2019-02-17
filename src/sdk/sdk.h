#pragma once

#include "blockchain/block.h"
#include "blockchain/genesis_block.h"
#include "blockchain/account.h"
#include "blockchain/wallet.h"
#include "blockchain/token.h"
#include "blockchain/transaction.h"
#include "blockchain/transaction_result.h"
#include "common/jsonrpc/jsonrpc.h"

namespace ICONation::SDK
{
    const Blockchain::Address GOVERNANCE_SCORE_ADDRESS = "cx0000000000000000000000000000000000000001";

    class Client
    {
        // Allocators
        public:
            Client (const std::string &endpoint);
            ~Client (void) = default;

        // RPC Methods
        public:
            // Returns the last block information.
            // https://github.com/icon-project/icon-rpc-server/blob/develop/docs/icon-json-rpc-v3.md#icx_getlastblock
            Blockchain::Block get_last_block (void);

            // Returns the first block (genesis) information
            Blockchain::GenesisBlock get_genesis_block (void);

            // Returns block information by block height
            // https://github.com/icon-project/icon-rpc-server/blob/develop/docs/icon-json-rpc-v3.md#icx_getblockbyheight
            Blockchain::Block get_block_by_height (const Blockchain::Block::Height &height);

            // Returns block information by block hash
            // https://github.com/icon-project/icon-rpc-server/blob/develop/docs/icon-json-rpc-v3.md#icx_getblockbyhash
            Blockchain::Block get_block_by_hash (const Blockchain::Block::Hash &hash);

            // Returns the ICX balance of the given EOA or SCORE
            // https://github.com/icon-project/icon-rpc-server/blob/develop/docs/icon-json-rpc-v3.md#icx_getbalance
            Blockchain::ICX::Loop get_balance (const Blockchain::Address &address);

            // Returns SCORE's external API list
            // https://github.com/icon-project/icon-rpc-server/blob/develop/docs/icon-json-rpc-v3.md#icx_getscoreapi
            nlohmann::json get_score_api (const Blockchain::Address &address);

            // Calls SCORE's external function
            // Does not make state transition (i.e., read-only).
            // https://github.com/icon-project/icon-rpc-server/blob/develop/docs/icon-json-rpc-v3.md#icx_call
            nlohmann::json call_score_readonly (
                const Blockchain::Address &score, 
                const std::string &method, 
                const nlohmann::json &params = {}
            );

            // Returns total ICX coin supply that has been issued
            // https://github.com/icon-project/icon-rpc-server/blob/develop/docs/icon-json-rpc-v3.md#icx_gettotalsupply
            Blockchain::ICX::Loop get_total_supply (void);

            // Returns the transaction result requested by transaction hash
            // https://github.com/icon-project/icon-rpc-server/blob/develop/docs/icon-json-rpc-v3.md#icx_gettransactionresult
            Blockchain::TransactionResult get_transaction_result (const Blockchain::Transaction::Hash &hash);

            // Returns the transaction information requested by transaction hash
            // https://github.com/icon-project/icon-rpc-server/blob/develop/docs/icon-json-rpc-v3.md#icx_gettransactionbyhash
            Blockchain::Transaction get_transaction_by_hash (const Blockchain::Transaction::Hash &hash);

            // Transfer designated amount of ICX coins from a wallet to 'to' address
            // https://github.com/icon-project/icon-rpc-server/blob/develop/docs/icon-json-rpc-v3.md#coin-transfer
            Blockchain::Transaction::Hash wallet_send_icx (
                const Blockchain::Wallet &wallet, 
                const Blockchain::Address &to, 
                const Blockchain::ICX::Loop &value,
                const Blockchain::ICX::Step &stepLimit,
                const int &nonce = 0
            );

            // Invoke a function of the SCORE in the 'score' address
            // https://github.com/icon-project/icon-rpc-server/blob/develop/docs/icon-json-rpc-v3.md#score-function-call
            Blockchain::Transaction::Hash wallet_call_score (
                const Blockchain::Wallet &wallet, 
                const Blockchain::Address &score,
                const std::string &method, const nlohmann::json &callParams,
                const Blockchain::ICX::Step &stepLimit, 
                const int &nonce = 0
            );

            // Install a new SCORE
            // https://github.com/icon-project/icon-rpc-server/blob/develop/docs/icon-json-rpc-v3.md#datatype--deploy
            Blockchain::Transaction::Hash wallet_deploy (
                const Blockchain::Wallet &wallet, 
                const Blockchain::Address &score,
                const std::string &contentType, 
                const std::vector<unsigned char> &content, 
                const nlohmann::json &callParams,
                const Blockchain::ICX::Step &stepLimit, 
                const int &nonce = 0
            );

            // IRC2 Token
            // https://icondev.readme.io/docs/audit-checklist#section-irc2-token-standard-compliance
            // Check if the SCORE is compliant to IRC2 standards
            bool irc2_token_compliant (const Blockchain::Address &score);
            // Get information about an IRC2 token from a SCORE address
            Blockchain::IRC2 get_irc2_token (const Blockchain::Address &score);

            // Generate a new wallet
            Blockchain::Wallet wallet_create (void);

            // Load a wallet from a private key
            Blockchain::Wallet wallet_load (const std::vector<unsigned char> &privateKey);
            Blockchain::Wallet wallet_load (void *privateKeyBytes); // must be 32 bytes

            // Load from keystore + password
            Blockchain::Wallet wallet_load (
                const std::experimental::filesystem::path &keystore, 
                const std::string &password
            );

            // Get governance step price
            Blockchain::ICX::Loop get_step_price (void);

        private:
            nlohmann::json call (const std::string &method, const nlohmann::json &params);
            Blockchain::Block read_block (const nlohmann::json &result);
            void read_block_transactions (Blockchain::Block &block, const nlohmann::json &result);
            Blockchain::Transaction read_transaction (const nlohmann::json &transactionJson);
            void read_event_logs (Blockchain::Transaction &transaction, const nlohmann::json &eventLogs);

        // JSON-RPC client
        private:
            Common::JsonRPC::Client m_client;

        // ICX native token definition
        public:
            const Blockchain::ICX &icx (void) const { return *m_icx; }
        private:
            std::shared_ptr<Blockchain::ICX> m_icx;
    };
}