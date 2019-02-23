#include "wallet.h"
#include "exception.h"
#include "common/exception/exception.h"
#include "common/dbg/dbg.h"
#include "common/crypto/sha3.h"
#include "common/crypto/base64.h"
#include "common/exception/exception.h"
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <secp256k1_recovery.h>
#include <chrono>

namespace ICONation::SDK::Blockchain
{
    static void check_private_key (const std::vector<unsigned char> &privateKey)
    {
        if (privateKey.size() != PRIVATE_KEY_SIZE) {
            throw Common::Exception::InvalidSize (privateKey, PRIVATE_KEY_SIZE);
        }
    }

    static void check_public_key (const std::vector<unsigned char> &publicKey)
    {
        if (publicKey.size() != UNCOMPRESSED_PUBKEY_SIZE) {
            throw Common::Exception::InvalidSize (publicKey, UNCOMPRESSED_PUBKEY_SIZE);
        }
    }

    Wallet::Wallet (const std::vector<unsigned char> &privateKey)
    :   m_context (secp256k1_context_create (SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)),
        m_privateKey (privateKey)
    {
        generate_public_key();
        generate_address();
        check_consistency();
    }

    Wallet::Wallet (void)
    :   m_context (secp256k1_context_create (SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN))
    {
    }

    void Wallet::check_consistency (void) const
    {
        check_private_key (m_privateKey);
        check_public_key (m_publicKey);
        m_address.check_consistency();
    }

    Wallet Wallet::load (const std::experimental::filesystem::path &keystore, const std::string &password)
    {
        throw Common::Exception::Unimplemented ("Cannot load wallet from keystore");
    }

    Wallet Wallet::load (const std::vector<unsigned char> &privateKey)
    {
        return Wallet (privateKey);
    }

    Wallet Wallet::create (void)
    {
        Wallet wallet;

        wallet.generate_private_key();
        wallet.generate_public_key();
        wallet.generate_address();
        
        wallet.check_consistency();
        return wallet;
    }

    void Wallet::generate_private_key (void)
    {
        // ECDSA Private key = 32 bytes
        m_privateKey.resize (PRIVATE_KEY_SIZE);

        // Get cryptographically strong random bytes from OpenSSL
        if (RAND_bytes (&m_privateKey[0], PRIVATE_KEY_SIZE) != 1) {
            throw Common::Exception::OpenSSLError ("RAND_bytes failed");
        }

        // Check the private key
        if (secp256k1_ec_seckey_verify (m_context, &m_privateKey[0]) != 1) {
            throw Blockchain::Exception::Secp256k1Error ("secp256k1_ec_seckey_verify failed");
        }
    }

    void Wallet::generate_public_key (void)
    {
        secp256k1_pubkey pubkey;

        // Uncompressed public key = 65 bytes
        m_publicKey.resize (UNCOMPRESSED_PUBKEY_SIZE);

        // Get pubkey from the private key
        if (secp256k1_ec_pubkey_create (m_context, &pubkey, &m_privateKey[0]) != 1) {
            throw Blockchain::Exception::Secp256k1Error ("secp256k1_ec_pubkey_create failed");
        }

        // Serialize uncompressed
        size_t pubkeySize = m_publicKey.size();
        if (secp256k1_ec_pubkey_serialize (m_context, &m_publicKey[0], &pubkeySize, &pubkey, SECP256K1_EC_UNCOMPRESSED) != 1) {
            throw Blockchain::Exception::Secp256k1Error ("secp256k1_ec_pubkey_serialize failed");
        }

        if (pubkeySize != m_publicKey.size()) {
            throw Blockchain::Exception::Secp256k1Error ("pubkeySize != m_publicKey.size()");
        }
    }

    void Wallet::generate_address (void)
    {
        std::string hash = SHA3 (SHA3::Bits256) (&m_publicKey[1], m_publicKey.size() - 1);
        // Only keep the last 20 bytes
        std::string hashAddress = hash.substr (hash.size() - 40);
        m_address = Address (hashAddress);
    }

    std::vector<unsigned char> Wallet::sign (const std::vector<unsigned char> &data) const
    {
        secp256k1_ecdsa_recoverable_signature signature;

        if (data.size() != ECDSA_MESSAGE_HASH_SIZE) {
            throw Common::Exception::InvalidSize (data, ECDSA_MESSAGE_HASH_SIZE);
        }

        // Get the ECDSA signature of data using the private key
        if (secp256k1_ecdsa_sign_recoverable (m_context, &signature, &data[0], &m_privateKey[0], NULL, NULL) != 1) {
            throw Blockchain::Exception::Secp256k1Error ("secp256k1_ecdsa_sign_recoverable failed");
        }

        // Serialize the signature
        std::vector<unsigned char> signatureBytes;
        signatureBytes.resize (ECDSA_RECOVERABLE_SIGNATURE_SIZE);

        std::vector<unsigned char> recoveryId;
        recoveryId.resize (sizeof (int));

        if (secp256k1_ecdsa_recoverable_signature_serialize_compact (m_context, &signatureBytes[0], (int *) &recoveryId[0], &signature) != 1) {
            throw Blockchain::Exception::Secp256k1Error ("secp256k1_ecdsa_recoverable_signature_serialize_compact failed");
        }

        // Add the recovery id at the end of the signature
        signatureBytes.push_back (recoveryId[0]);

        return signatureBytes;
    }

    static void serialize_value (const nlohmann::json &value, std::string &serialized)
    {
        switch (value.type())
        {
            case nlohmann::detail::value_t::string:
                serialized += value.get<std::string>();
            break;

            // https://icondev.readme.io/docs/transaction-signature#section-null-type
            case nlohmann::detail::value_t::null:
                serialized += "\\0";
            break;

            default:
                throw Common::Exception::Unimplemented (
                    fmt::format ("Invalid type : {}", (int) value.type()));
            break;
        }
    }

    static void serialize_transaction_object (const std::string &key, const nlohmann::json &value, bool first, std::string &serialized)
    {
        switch (value.type())
        {
            // https://icondev.readme.io/docs/transaction-signature#String-type
            case nlohmann::detail::value_t::null:
            case nlohmann::detail::value_t::string:
                serialized += first ? "" : ".";
                serialized += key + ".";
                serialize_value (value, serialized);
            break;

            case nlohmann::detail::value_t::number_integer:
            case nlohmann::detail::value_t::number_unsigned:
                throw Common::Exception::Unimplemented (
                    fmt::format ("Don't write integers in your parameters, but hexstring instead ({} = {})",
                        key, value.get<int>())
                );
            break;

            // https://icondev.readme.io/docs/transaction-signature#Dictionary-type
            case nlohmann::detail::value_t::object:
                serialized += first ? "" : ".";
                serialized += key + ".";
                serialized += "{";
                for (auto it = value.begin(); it != value.end(); it++) {
                    serialize_transaction_object (it.key(), it.value(), it == value.begin(), serialized);
                }
                serialized += "}";
            break;

            // https://icondev.readme.io/docs/transaction-signature#Array-type
            case nlohmann::detail::value_t::array:
                serialized += "[";
                for (auto it = value.begin(); it != value.end(); it++) {
                    serialized += (it == value.begin()) ? "" : ".";
                    serialize_value (value, serialized);
                }
                serialized += "]";
            break;

            default:
                throw Common::Exception::Unimplemented (
                    fmt::format ("Cannot serialize an unknown transaction object type ({})", (int) value.type()));
            break;
        }
    }

    static std::string serialize_json_transaction (const nlohmann::json &tx, const std::string &method)
    {
        std::string serialized = method + ".";
        
        for (auto it = tx.begin(); it != tx.end(); it++) {
            serialize_transaction_object (it.key(), it.value(), it == tx.begin(), serialized);
        }

        return serialized;
    }

    nlohmann::json Wallet::get_common_transaction (const Address &to, const ICX::Step &stepLimit, const Network &nid, const int &nonce) const
    {
        nlohmann::json tx;
        std::chrono::milliseconds nowMilliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());

        // Common fields ICX transfer fields
        tx["version"] = "0x3";
        tx["from"] = get_address().to_string();
        tx["to"] = to.to_string();
        tx["stepLimit"] = "0x" + stepLimit.get_str (16);
        tx["timestamp"] = fmt::format ("{:#x}", 1000 * nowMilliseconds.count());
        tx["nonce"] = fmt::format ("{:#x}", nonce);
        tx["nid"] = fmt::format ("{:#x}", nid);

        return tx;
    }

    void Wallet::sign_transaction (nlohmann::json &tx) const
    {
        // Serialize
        std::string serialized = serialize_json_transaction (tx, "icx_sendTransaction");

        // Message hash
        SHA3 sha3 (SHA3::Bits256);
        sha3.add (serialized.c_str(), serialized.size());
        std::vector<unsigned char> messageHash = sha3.getHashBytes();

        // Get the signature
        std::vector<unsigned char> signature = sign (messageHash);

        // Base64 encode it and include it in the tx message
        tx["signature"] = Common::Crypto::Base64().encode (signature);
    }

    nlohmann::json Wallet::get_signed_icx_transaction (
        const Address &to, 
        const ICX::Loop &value, 
        const ICX::Step &stepLimit, 
        const Network &nid,
        const int &nonce
    ) const
    {
        nlohmann::json tx = get_common_transaction (to, stepLimit, nid, nonce);

        tx["value"] = "0x" + value.get_str (16);

        sign_transaction (tx);

        return tx;
    }

    nlohmann::json Wallet::get_signed_call_transaction (
        const Address &to, 
        const std::string &method, 
        const nlohmann::json &callParams, 
        const ICX::Step &stepLimit, 
        const Network &nid,
        const int &nonce
    ) const
    {
        nlohmann::json tx = get_common_transaction (to, stepLimit, nid, nonce);

        tx["dataType"] = "call";
        tx["data"]["method"] = method;
        
        if (!callParams.empty()) {
            tx["data"]["params"] = callParams;
        }

        sign_transaction (tx);

        return tx;
    }

    nlohmann::json Wallet::get_signed_deploy_transaction (
        const Address &to, 
        const std::string &contentType, const std::vector<unsigned char> &content, const nlohmann::json &scoreParams,
        const ICX::Step &stepLimit, 
        const Network &nid,
        const int &nonce
    ) const
    {
        nlohmann::json tx = get_common_transaction (to, stepLimit, nid, nonce);

        // Convert content to hexstring
        std::string contentHex = "0x";
        for (auto &c : content) {
            contentHex += fmt::format ("{:02x}", c);
        }

        tx["dataType"] = "deploy";
        tx["data"]["contentType"] = contentType;
        tx["data"]["content"] = contentHex;
        
        if (!scoreParams.empty()) {
            tx["data"]["params"] = scoreParams;

        }
        sign_transaction (tx);

        return tx;
    }
}