#pragma once

#include <exception>
#include <string>
#include <fmt/format.h>

namespace ICONation::SDK::Exception
{
    struct RPCError : public std::runtime_error
    {
        RPCError (int code, const std::string &message) throw()
        :   std::runtime_error (fmt::format ("Code '{}', Message '{}'", code, message)) {}
        virtual char const *what (void) const throw() { return exception::what(); }
    };
}
