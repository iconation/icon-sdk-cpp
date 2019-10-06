#pragma once

#include <string>
#include <vector>

namespace ICONation::SDK::Blockchain
{
class Hash
{
    // Hash specific types
public:
    typedef std::string Prefix;
    typedef std::string Value;

    // Allocators
public:
    Hash(const std::string &input, const Prefix &expectedPrefix, size_t expectedValueSize);
    Hash(const std::string &input, const std::vector<Prefix> &expectedPrefixes, size_t expectedValueSize);
    // Need to call the consistency check externally
    Hash(const Prefix &expectedPrefix, size_t expectedValueSize);
    Hash(const std::vector<Prefix> &expectedPrefixes, size_t expectedValueSize);
    virtual ~Hash(void) = default;

    // Consistency
public:
    void check_consistency(void) const;

private:
    void check_prefix(const Prefix &prefix) const;
    void check_value(const Value &value) const;

    // Prefix
private:
    std::vector<Prefix> m_expectedPrefixes;
    Prefix m_prefix;

    // Hash value
public:
    const Value &value(void) const { return m_value; }

private:
    size_t m_expectedValueSize;
    Value m_value;

    // Full hash
public:
    std::string repr(void) const;

    // Function for debug purposes
public:
    std::string to_string(void) const;

public:
    friend std::ostream &operator<<(std::ostream &stream, const Hash &address);
};
} // namespace ICONation::SDK::Blockchain