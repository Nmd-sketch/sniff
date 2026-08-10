#pragma once
#include "../model/IEntry.hpp"

namespace domain {

class IFilter {
public:
    virtual ~IFilter() = default;

    /* Depth is supplied by the traversal (entries do not carry it). */
    virtual bool matches(const IEntry& entry, int depth) const = 0;
};

}  // namespace domain