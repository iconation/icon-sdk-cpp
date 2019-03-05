<p align="center">
  <img 
    src="https://iconation.team/images/very_small.png" 
    width="120px"
    alt="ICONation logo">
</p>

<h1 align="center">ICON SDK C++</h1>

 [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Quick start

```C++

#include "sdk/sdk.h"

using namespace ICONation::SDK;
using namespace ICONation::SDK::Blockchain;

int main (int argc, char **argv)
{
    // Create SDK-RPC client
    ICONation::SDK::Client client ("http://iconation.team:9100/api/v3");

    // Generate a new ICX wallet
    Wallet wallet = client.wallet_create();

    // Get your balance
    ICX::Loop balance = client.get_balance (wallet.get_address());

    // Get information about the latest block
    Block block = client.get_last_block();

    // Get information about the previous block
    Block previousBlock = client.get_block_by_height (block.height() - 1);

    // Get genesis block (block height = 0)
    GenesisBlock genesis = client.get_genesis_block();

    // Get total ICX supply amount
    ICX::Loop supply = client.get_total_supply();

    // Get the step price from the governance SCORE
    ICX::Loop stepPrice = client.get_step_price();

    // Transfer 5 ICX to hx0000000000000000000000000000000000000000 with stepLimit = 1000000 steps
    Transaction::Hash txhash = client.wallet_send_icx (
        wallet, "hx0000000000000000000000000000000000000000", 5 * ICX::TO_LOOP, 1000000);

    // Get transaction result of the last transaction
    TransactionResult result = client.get_transaction_result (txhash);

    // Call a Read-Only SCORE method with no param : 
    // Get the step price from the governance SCORE
    client.call_score_readonly (GOVERNANCE_SCORE_ADDRESS, "getStepPrice", {});

    // Call a Read-Only SCORE method with a param : 
    // Get the governance SCORE status
    client.call_score_readonly (GOVERNANCE_SCORE_ADDRESS, "getScoreStatus", {
        {"address", GOVERNANCE_SCORE_ADDRESS.to_string()}
    });

    // Call a SCORE method that writes a transaction, with a step limit = 1000000 steps 
    client.wallet_call_score (wallet, "cx1352acdaadf247ed66baa915f6f66a1aa5ca5e9c", 
        "sign_up", {
            {"_child_address", "hx37b0ae56424d50f791500530c094903f3604f988"},
            {"_is_leader", "0x1"}
        }, 1000000
    );

    // Deploy a SCORE using a zipfile, no params, step limit = 15 ICX 
    const ICX::Loop ICX_TO_STEP = ICX::TO_LOOP / client.get_step_price();
    std::vector <unsigned char> zipbytes = load_score_from_zipfile();
    Transaction::Hash hash = client.wallet_deploy (
        wallet, "cx0000000000000000000000000000000000000000",
        "application/zip", zipbytes, {}, 15 * ICX_TO_STEP
    );

    // Check if a SCORE address hosts an IRC2 Token
    if (client.irc2_token_compliant ("cxf9148db4f8ec78823a50cb06c4fed83660af38d0")) {
        // Get MECA token information
        IRC2 mca = client.get_irc2_token ("cxf9148db4f8ec78823a50cb06c4fed83660af38d0");
        std::cout << "MCA total supply : " << mca.totalSupply() << std::endl;
    }

    return 0;
}
```


## Installation

### Linux

##### Install build tools
```bash
$ sudo apt install make cmake git dh-autoconf
```
##### Build GTest
```bash
$ sudo apt install libgtest-dev
$ cd /usr/src/gtest && sudo cmake CMakeLists.txt && sudo make
$ sudo cp *.a /usr/lib
```

##### Install libcurl
```bash
$ sudo apt install libcurl4-openssl-dev
```

##### Build mpir
```bash
$ sudo apt install yasm texinfo
$ git clone git://github.com/wbhart/mpir.git mpir && cd mpir
$ ./autogen.sh && ./configure --enable-cxx && make && sudo make install
$ sudo ln -s /usr/local/lib/libmpir.so.* /usr/lib/ && sudo ln -s /usr/local/lib/libmpirxx.so.* /usr/lib/
```

##### Build ICON SDK C++
```bash
$ # In the root directory
$ mkdir -p build && cd build
$ cmake -DCMAKE_BUILD_TYPE=Debug -G "Unix Makefiles" -DCMAKE_ARCHITECTURE=x64 ../
$ make -j4
$ # Optionally, you can run the tests
$ cd ../release/x64/ && ./SDK_Tests
```


## Documentation

```C++
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
```
