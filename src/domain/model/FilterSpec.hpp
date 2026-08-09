#pragma once
#include <optional>
#include <string>
#include <vector>
#include <cstdint>

struct FilterSpec {
    /* Extension filter */
    std::optional<std::vector<std::string>> extension;
    
    /* Size filter */
    std::optional<std::uintmax_t> min_size;
    std::optional<std::uintmax_t> max_size;

    /* Hidden files filter */
    std::optional<bool> detect_hidden;

    /* Creation and modification dates filter */
    std::optional<std::string> creation_date;
    std::optional<std::string> modification_date;

};
