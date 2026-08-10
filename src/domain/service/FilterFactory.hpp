#pragma once
#include <string>

#include "../model/FilterSpec.hpp"
#include "FilterChain.hpp"

namespace domain {

/* Builds the full filter chain from a parsed FilterSpec. Throws
   std::invalid_argument on invalid date/regex values. */
class FilterFactory {
public:
    static FilterChain createChain(const std::string& pattern, const FilterSpec& spec);
};

}  // namespace domain