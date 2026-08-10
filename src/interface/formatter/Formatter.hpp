#pragma once
#include <memory>
#include <string>
#include <vector>

#include "../../domain/model/IEntry.hpp"

class Formatter {
public:
    virtual ~Formatter() = default;
    virtual std::string formatEntries(
        const std::vector<std::unique_ptr<domain::IEntry>>& entries) const = 0;
};