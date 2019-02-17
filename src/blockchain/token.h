#pragma once

#include <string>
#include <mpirxx.h>
#include "address.h"

namespace ICONation::SDK::Blockchain
{
    // Base class of any ICON token
    class Token
    {
        public:
            // Token specific types
            typedef mpz_class Unit;
            typedef std::string Name;
            typedef std::string Symbol;
            typedef int Decimal;
            enum Type : int { ICX, IRC2 };

        // Allocators
        public:
            Token (void) = default;
            Token (const Type &type, const Name &name, const Symbol &symbol, const Unit &totalSupply, const Decimal &decimals);
            virtual ~Token (void) = default;

        // Token type
        public:
            const Type &type (void) const { return m_type; }
        protected:
            Type m_type;

        // Name
        public:
            const Name &name (void) const { return m_name; }
        protected:
            Name m_name;

        // Symbol
        public:
            const Symbol &symbol (void) const { return m_symbol; }
        protected:
            Symbol m_symbol;

        // Total Supply
        public:
            const Unit &totalSupply (void) const { return m_totalSupply; }
        protected:
            Unit m_totalSupply;

        // Decimals
        public:
            const Decimal &decimals (void) const { return m_decimals; }
        protected:
            int m_decimals;

        // Function for debug purposes
        public:
            std::string to_string (void) const;
        public:
            friend std::ostream &operator << (std::ostream &stream, const Token &token);
    };

    // Native ICX Coin
    class ICX : public Token
    {
        public:
            // ICX specific types & constants
            // ICX smallest unit : loop
            typedef Token::Unit Loop;
            // Step unit in transactions
            typedef Token::Unit Step;
            // 1 ICX = 10 ** 18 Loop
            static const Loop TO_LOOP;

        // Allocators
        public:
            ICX (void) = default;
            ICX (const Name &name, const Symbol &symbol, const Unit &totalSupply, const Decimal &decimals);
            ~ICX (void) = default;

    };

    // IRC2 Standard Token representation
    // https://github.com/icon-project/IIPs/blob/master/IIPS/iip-2.md
    class IRC2 : public Token
    {
        // Allocators
        public:
            IRC2 (void) = default;
            IRC2 (const Address &score, const Name &name, const Symbol &symbol, const Unit &totalSupply, const Decimal &decimals);
            ~IRC2 (void) = default;

        // SCORE token governance contract
        public:
            const Address &score (void) const { return m_score; }
        private:
            Address m_score;
    };
}