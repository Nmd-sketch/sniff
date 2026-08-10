#include "HiddenFilter.hpp"

namespace domain {

HiddenFilter::HiddenFilter(bool detectHidden) : m_detectHidden(detectHidden) {}

bool HiddenFilter::matches(const IEntry& entry, int depth) const {
    (void)depth;
    return m_detectHidden || !entry.isHidden();
}

}  // namespace domain