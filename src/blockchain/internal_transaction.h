#pragma once

#include "address.h"
#include "token.h"
#include <memory>

namespace ICONation::SDK::Blockchain
{
    class InternalTransaction
    {
        // Allocators
        public:
            InternalTransaction (const Address &from, const Address &to, const std::shared_ptr<Token> &token, const Token::Unit &amount);
            ~InternalTransaction (void) = default;

        // Sender & Receiver
        public:
            const Address &to (void) const { return m_to; }
            Address &mutable_to (void) { return m_to; }
        private:
            Address m_from;
        public:
            const Address &from (void) const { return m_from; }
            Address &mutable_from (void) { return m_from; }
        private:
            Address m_to;

        // Token
        public:
            const Token &token (void) const { return *m_token; }
        private:
            std::shared_ptr<Token> m_token;

        // Transaction token amount
        public:
            const Token::Unit &amount (void) const { return m_amount; }
            Token::Unit &mutable_amount (void) { return m_amount; }
        private:
            Token::Unit m_amount;
    };
}