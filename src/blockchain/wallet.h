#pragma once

#include "address.h"
#include "transaction.h"
#include <vector>
#include <secp256k1.h>
#include <experimental/filesystem>
#include <nlohmann/json.hpp>

namespace ICONation::SDK::Blockchain
{
    const int PRIVATE_KEY_SIZE = 32;
    const int ECDSA_MESSAGE_HASH_SIZE = 32;
    const int UNCOMPRESSED_PUBKEY_SIZE = 65;
    const int ECDSA_RECOVERABLE_SIGNATURE_SIZE = 64;
    
    class Wallet
    {
        // Allocators
        private:
            Wallet (void);
            Wallet (const std::vector<unsigned char> &privateKey);
        public:
            ~Wallet (void) = default;
            // Create a new wallet with a cryptographic random private key
            static Wallet create (void);
            // Load a new wallet from an existing private key
            static Wallet load (const std::vector<unsigned char> &privateKey);
            // Load a new wallet from an existing keystore file
            static Wallet load (const std::experimental::filesystem::path &keystore, const std::string &password);

        // Consistency checks
        public:
            void check_consistency (void) const;

        // Private / Public keys
        public:
            std::vector<unsigned char> get_private_key (void) { return m_privateKey; }
        private:
            std::vector<unsigned char> m_privateKey;
            std::vector<unsigned char> m_publicKey;
        private:
            void generate_private_key (void);
            void generate_public_key (void);
        
        // Cryptographic Signature
        public:
            std::vector<unsigned char> sign (const std::vector<unsigned char> &data) const;

        // Address
        public:
            Address get_address (void) const { return m_address; }
        private:
            Address m_address;
        private:
            void generate_address (void);
        
        // Transaction
        public:
            // https://github.com/icon-project/icon-rpc-server/blob/develop/docs/icon-json-rpc-v3.md#coin-transfer
            nlohmann::json get_signed_icx_transaction (
                const Address &to, 
                const ICX::Loop &value, 
                const ICX::Step &stepLimit, 
                const int &nonce = 0
            ) const;
            
            // https://github.com/icon-project/icon-rpc-server/blob/develop/docs/icon-json-rpc-v3.md#score-function-call
            nlohmann::json get_signed_call_transaction (
                const Address &to, 
                const std::string &method, 
                const nlohmann::json &callParams, 
                const ICX::Step &stepLimit, 
                const int &nonce = 0
            ) const;

            // https://github.com/icon-project/icon-rpc-server/blob/develop/docs/icon-json-rpc-v3.md#score-install
            nlohmann::json get_signed_deploy_transaction (
                const Address &to, 
                const std::string &contentType, const std::vector<unsigned char> &content, const nlohmann::json &scoreParams,
                const ICX::Step &stepLimit, 
                const int &nonce
            ) const;

        private:
            nlohmann::json get_common_transaction (const Address &to, const ICX::Step &stepLimit, const int &nonce = 0) const;
            void sign_transaction (nlohmann::json &tx) const;

        // Secp256k1
        private:
            secp256k1_context *m_context;
    };
}