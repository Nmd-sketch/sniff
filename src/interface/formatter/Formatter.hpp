#pragma once
#include "../../domain/model/IEntry.hpp"
#include <vector>

class Formatter {
public:
    virtual ~Formatter() = default;
    virtual std::string formatEntries(std::vector<IEntry> entries) const;
};
