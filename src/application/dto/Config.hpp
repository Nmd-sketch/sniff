#pragma once
#include <string>
#include <vector>

#include "../../domain/model/FilterSpec.hpp"

namespace application {

struct Config {
    std::string pattern;
    std::vector<std::string> paths;

    /* Format type is excluded on purpose: the interface layer owns the
       formatter and its data. */
    std::vector<FilterSpec> specs;
};

}  // namespace application