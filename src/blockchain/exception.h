#pragma once

#include <exception>
#include <fmt/format.h>
#include <fmt/ostream.h>
#include "account.h"
#include "block.h"
#include "token.h"
#include "transaction.h"

namespace ICONation::SDK::Blockchain::Exception
{
    struct NotEnoughFunds : public std::runtime_error {
        NotEnoughFunds (const Account &from, const ICX::Loop &required) throw() : 
            std::runtime_error (fmt::format("'{}', required {}",
                from.to_string(), required)) {}
    };
    
    struct InvalidPrefix : public std::runtime_error {
        InvalidPrefix (const std::string &data, const std::string &expected) throw() : 
            std::runtime_error (fmt::format ("'{}' : Wrong prefix, expected '{}'", data, expected)) {}
    };

    struct InvalidHexOnly : public std::runtime_error {
        InvalidHexOnly (const std::string &data) throw() : 
            std::runtime_error (fmt::format ("'{}' : should be hex digits only", data)) {}
    };

    struct InvalidHeight : public std::runtime_error {
        InvalidHeight (const Block::Height &height) throw() : 
            std::runtime_error (fmt::format ("{}", height)) {}
    };

    struct Secp256k1Error : public std::runtime_error {
        Secp256k1Error (const std::string &message) throw() : 
            std::runtime_error (message) {}
    };

    struct InvalidTransactionVersion : public std::runtime_error {
        InvalidTransactionVersion (uint64_t version) throw()
        :   std::runtime_error (fmt::format ("Invalid Transaction Version '{}'", version)) {}
        virtual char const *what (void) const throw() { return exception::what(); }
    };

    struct InvalidBlockHeight : public std::runtime_error {
        InvalidBlockHeight (const Blockchain::Block::Height &height, const std::string &message) throw()
        :   std::runtime_error (fmt::format ("Invalid Block Height ({}) : '{}'", height, message)) {}
        virtual char const *what (void) const throw() { return exception::what(); }
    };

    struct InvalidIRC2Token : public std::runtime_error {
        InvalidIRC2Token (const Blockchain::Address &score) throw()
        :   std::runtime_error (fmt::format ("Invalid InvalidIRC2Token at {}", score)) {}
        virtual char const *what (void) const throw() { return exception::what(); }
    };
}