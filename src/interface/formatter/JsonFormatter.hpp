#pragma once
#include <memory>
#include <string>
#include <vector>

#include "Formatter.hpp"

class JsonFormatter : public Formatter {
public:
    std::string formatEntries(
        const std::vector<std::unique_ptr<domain::IEntry>>& entries) const override;
};