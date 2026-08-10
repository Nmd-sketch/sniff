#pragma once
#include "../../ports/IFilter.hpp"

namespace domain {

/* Without --hidden, hidden entries are filtered out entirely. */
class HiddenFilter : public IFilter {
public:
    explicit HiddenFilter(bool detectHidden);

    bool matches(const IEntry& entry, int depth) const override;

private:
    const bool m_detectHidden;
};

}  // namespace domain