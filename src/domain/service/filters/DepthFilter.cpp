#include "DepthFilter.hpp"

namespace domain {

DepthFilter::DepthFilter(std::optional<int> minDepth, std::optional<int> maxDepth)
    : m_minDepth(minDepth), m_maxDepth(maxDepth) {}

bool DepthFilter::matches(const IEntry& entry, int depth) const {
    (void)entry;
    if (m_minDepth && depth < *m_minDepth) return false;
    if (m_maxDepth && depth > *m_maxDepth) return false;
    return true;
}

}  // namespace domain