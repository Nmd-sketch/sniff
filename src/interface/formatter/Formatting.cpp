#include "Formatting.hpp"

#include <cmath>
#include <cstdio>
#include <ctime>

namespace formatting {

std::string humanReadableSize(std::uintmax_t bytes) {
    static const char* const units[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
    static constexpr std::size_t unit_count = sizeof(units) / sizeof(units[0]);

    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < unit_count) {
        value /= 1024.0;
        ++unit;
    }

    char buffer[32];
    if (unit == 0 || value == std::floor(value)) {
        std::snprintf(buffer, sizeof(buffer), "%.0f %s", value, units[unit]);
    } else {
        std::snprintf(buffer, sizeof(buffer), "%.1f %s", value, units[unit]);
    }
    return buffer;
}

std::string formatDateTime(std::chrono::system_clock::time_point time) {
    const std::time_t raw = std::chrono::system_clock::to_time_t(time);
    std::tm converted{};
#ifdef _WIN32
    gmtime_s(&converted, &raw);
#else
    gmtime_r(&raw, &converted);
#endif
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &converted);
    return buffer;
}

}  // namespace formatting