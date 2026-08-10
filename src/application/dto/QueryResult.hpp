#pragma once
#include <chrono>
#include <cstdint>
#include <memory>
#include <vector>

#include "../../domain/model/IEntry.hpp"

namespace application {

struct QueryResultStats {
    std::uint64_t scanned = 0;
    std::uint64_t matches = 0;
    std::uintmax_t total_size = 0;
    std::size_t file_count = 0;
    std::size_t dir_count = 0;
    std::size_t symlink_count = 0;
    std::chrono::milliseconds elapsed{0};
};

struct QueryResult {
    std::vector<std::unique_ptr<domain::IEntry>> entries;
    QueryResultStats stats;
    bool aborted = false;
};

}  // namespace application