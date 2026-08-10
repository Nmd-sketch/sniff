#pragma once
#include <string>
#include <vector>

#include "../../domain/model/FilterSpec.hpp"
#include "../model/FormatType.hpp"

class CommandParser {
public:
    bool parse(const std::vector<std::string>& args);

    const std::vector<FilterSpec>& getFilterSpecs() const;
    const std::vector<std::string>& getCommands() const;
    FormatType getFormatType() const;
    const std::string& lastError() const;

private:
    std::vector<FilterSpec> m_filter_specs;
    std::vector<std::string> m_commands;
    FormatType m_format_type = FormatType::TABLE;
    std::string m_last_error;
};