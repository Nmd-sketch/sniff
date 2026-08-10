#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "CaseMode.hpp"
#include "FileType.hpp"
#include "MatchMode.hpp"

struct FilterSpec {
    /* Extension filter */
    std::optional<std::vector<std::string>> extension;

    /* Size filter */
    std::optional<std::uintmax_t> min_size;
    std::optional<std::uintmax_t> max_size;

    /* Hidden files filter */
    std::optional<bool> detect_hidden;

    /* Date filters (raw strings; DateFilter owns parsing) */
    std::optional<std::string> modified_within;
    std::optional<std::string> modified_before;
    std::optional<std::string> created_within;
    std::optional<std::string> created_before;

    /* Pattern matching */
    std::optional<MatchMode> match_mode;
    std::optional<CaseMode> case_mode;
    std::optional<bool> full_path;

    /* Type filter */
    std::optional<std::vector<FileType>> types;

    /* Depth filter */
    std::optional<int> min_depth;
    std::optional<int> max_depth;

    /* Exclusion filter */
    std::optional<std::vector<std::string>> exclude;

    /* Traversal */
    std::optional<bool> follow_symlinks;
};