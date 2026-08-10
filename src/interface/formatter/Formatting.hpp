#pragma once
#include <chrono>
#include <cstdint>
#include <string>

namespace formatting {

std::string humanReadableSize(std::uintmax_t bytes);

std::string formatDateTime(std::chrono::system_clock::time_point time);

}  // namespace formatting