#include "hash.h"
#include "exception.h"
#include "common/exception/exception.h"
#include "common/dbg/dbg.h"
#include <algorithm>

namespace ICONation::SDK::Blockchain
{
    // ========== Generic hash ==================================================
    Hash::Hash (const std::string &input, const Prefix &expectedPrefix, size_t expectedValueSize)
    :   Hash (input, std::vector<Prefix>{expectedPrefix}, expectedValueSize)
    {
    }

    Hash::Hash (const std::string &input, const std::vector<Prefix> &expectedPrefixes, size_t expectedValueSize)
    :   m_expectedPrefixes (expectedPrefixes),
        m_expectedValueSize (expectedValueSize)
    {
        std::string prefix = input.substr (0, m_expectedPrefixes.front().size());

        // Determines if it begins with a valid prefix
        if (std::find (m_expectedPrefixes.begin(), m_expectedPrefixes.end(), prefix) != m_expectedPrefixes.end()) {
            m_prefix = prefix;
            m_value = input.substr (m_prefix.size());
        } 
        else {
            // Arbitrarly chose the first prefix as the prefered one, as it shouldn't matter
            m_prefix = m_expectedPrefixes.front();
            // It doesn't seem to be the case
            m_value = input;
        }

        check_consistency();
    }

    Hash::Hash (const Prefix &expectedPrefix, size_t expectedValueSize)
    :   Hash (std::vector<Prefix>{expectedPrefix}, expectedValueSize)
    {
    }

    Hash::Hash (const std::vector<Prefix> &expectedPrefixes, size_t expectedValueSize)
    :   m_expectedPrefixes (expectedPrefixes),
        m_expectedValueSize (expectedValueSize)
    {
    }

    void Hash::check_consistency (void) const
    {
        check_prefix (m_prefix);
        check_value (m_value);
    }

    void Hash::check_prefix (const Prefix &prefix) const
    {
        if (std::find (m_expectedPrefixes.begin(), m_expectedPrefixes.end(), prefix) == m_expectedPrefixes.end()) {
            throw Blockchain::Exception::InvalidPrefix (m_prefix, m_expectedPrefixes.front());
        }
    }

    void Hash::check_value (const Value &value) const
    {
        // Only hex digits
        if (!(std::all_of (value.begin(), value.end(), ::isxdigit))) {
            throw Blockchain::Exception::InvalidHexOnly (value);
        }

        // Check size
        if (value.size() != m_expectedValueSize) {
            throw Common::Exception::InvalidSize (value, m_expectedValueSize);
        }
    }
    
    std::string Hash::repr (void) const
    {
        return m_prefix + m_value;
    }
    
    std::string Hash::to_string (void) const
    {
        return repr();
    }

    std::ostream &operator << (std::ostream &stream, const Hash &hash)
    {
        stream << hash.to_string();
        return stream;
    }
}