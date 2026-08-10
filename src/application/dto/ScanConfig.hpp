#pragma once
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "../../domain/model/FilterSpec.hpp"

namespace application {

using ProgressCallback =
    std::function<void(std::uint64_t scanned, const std::string& currentPath)>;

struct ScanConfig {
    std::vector<std::string> paths;
    std::vector<FilterSpec> specs;
    std::optional<ProgressCallback> on_progress;
};

}  // namespace application