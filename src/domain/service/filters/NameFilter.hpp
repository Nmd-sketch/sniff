#pragma once
#include <string>
#include <utility>

#include "../../model/CaseMode.hpp"
#include "../../model/MatchMode.hpp"
#include "../../ports/IFilter.hpp"
#include "../Matcher.hpp"

namespace domain {

class NameFilter : public IFilter {
public:
    NameFilter(std::string pattern, MatchMode mode, CaseMode caseMode, bool fullPath);

    bool matches(const IEntry& entry, int depth) const override;

private:
    Matcher m_matcher;
    const bool m_fullPath;
};

}  // namespace domain