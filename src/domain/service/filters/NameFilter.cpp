#include "NameFilter.hpp"

#include "../Matcher.hpp"

namespace domain {

NameFilter::NameFilter(std::string pattern, MatchMode mode, CaseMode caseMode,
                       bool fullPath)
    : m_matcher(std::move(pattern), mode, caseMode), m_fullPath(fullPath) {}

bool NameFilter::matches(const IEntry& entry, int depth) const {
    (void)depth;
    const std::string& text = m_fullPath ? entry.getPath() : entry.getName();
    return m_matcher.matches(text);
}

}  // namespace domain