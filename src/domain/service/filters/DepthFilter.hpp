#pragma once
#include <optional>

#include "../../ports/IFilter.hpp"

namespace domain {

class DepthFilter : public IFilter {
public:
    DepthFilter(std::optional<int> minDepth, std::optional<int> maxDepth);

    bool matches(const IEntry& entry, int depth) const override;

private:
    const std::optional<int> m_minDepth;
    const std::optional<int> m_maxDepth;
};

}  // namespace domain