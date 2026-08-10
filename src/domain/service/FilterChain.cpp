#include "FilterChain.hpp"

namespace domain {

FilterChain::FilterChain(std::vector<std::unique_ptr<IFilter>> filters)
    : m_filters(std::move(filters)) {}

bool FilterChain::matches(const IEntry& entry, int depth) const {
    for (const auto& filter : m_filters) {
        if (!filter->matches(entry, depth)) {
            return false;
        }
    }
    return true;
}

bool FilterChain::empty() const {
    return m_filters.empty();
}

}  // namespace domain