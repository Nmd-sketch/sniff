#pragma once
#include <regex>
#include <string>

#include "../model/CaseMode.hpp"
#include "../model/MatchMode.hpp"

namespace domain {

/* Substring-style matcher: search pattern anywhere inside the text. */
class Matcher {
public:
    Matcher(std::string pattern, MatchMode mode, CaseMode caseMode);

    bool matches(const std::string& text) const;

private:
    static std::regex buildRegex(const std::string& pattern, MatchMode mode,
                                 CaseMode caseMode);

    const MatchMode m_mode;
    const CaseMode m_caseMode;
    const std::string m_pattern;
    mutable std::regex m_regex;
};

}  // namespace domain