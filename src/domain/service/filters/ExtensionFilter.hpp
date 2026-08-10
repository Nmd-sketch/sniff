#pragma once
#include <string>
#include <vector>

#include "../../ports/IFilter.hpp"

namespace domain {

/* Extension match on the part after the last dot, case-insensitive. */
class ExtensionFilter : public IFilter {
public:
    explicit ExtensionFilter(std::vector<std::string> extensions);

    bool matches(const IEntry& entry, int depth) const override;

private:
    std::vector<std::string> m_extensions;
};

}  // namespace domain