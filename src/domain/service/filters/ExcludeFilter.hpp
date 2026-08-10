#pragma once
#include <string>
#include <vector>

#include "../../ports/IFilter.hpp"

namespace domain {

/* Exclusion: case-insensitive substring match against the full path. */
class ExcludeFilter : public IFilter {
public:
    explicit ExcludeFilter(std::vector<std::string> patterns);

    bool matches(const IEntry& entry, int depth) const override;

private:
    std::vector<std::string> m_patterns;
};

}  // namespace domain