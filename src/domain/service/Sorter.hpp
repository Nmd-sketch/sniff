#pragma once
#include <memory>
#include <vector>

#include "../model/IEntry.hpp"

namespace domain {

/* Sorts entries by full path, case-insensitive. */
class Sorter {
public:
    void sort(std::vector<std::unique_ptr<IEntry>>& entries) const;
};

}  // namespace domain