#pragma once
#include <memory>
#include <vector>

#include "../ports/IFilter.hpp"

namespace domain {

class FilterChain {
public:
    explicit FilterChain(std::vector<std::unique_ptr<IFilter>> filters);

    /* All filters must pass (logical AND). */
    bool matches(const IEntry& entry, int depth) const;

    bool empty() const;

private:
    std::vector<std::unique_ptr<IFilter>> m_filters;
};

}  // namespace domain