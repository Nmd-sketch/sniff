#include "SizeFilter.hpp"

namespace domain {

SizeFilter::SizeFilter(std::optional<std::uintmax_t> minSize,
                       std::optional<std::uintmax_t> maxSize)
    : m_minSize(minSize), m_maxSize(maxSize) {}

bool SizeFilter::matches(const IEntry& entry, int depth) const {
    (void)depth;
    const std::uintmax_t size = entry.getSizeBytes();
    if (m_minSize && size < *m_minSize) return false;
    if (m_maxSize && size > *m_maxSize) return false;
    return true;
}

}  // namespace domain