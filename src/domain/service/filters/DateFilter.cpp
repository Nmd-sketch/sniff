#include "DateFilter.hpp"

#include <cctype>
#include <limits>
#include <stdexcept>

namespace domain {

namespace {

std::optional<std::chrono::seconds> parseDuration(const std::string& value,
                                                  const char* option) {
    std::size_t pos = 0;
    while (pos < value.size() && std::isdigit(static_cast<unsigned char>(value[pos]))) {
        ++pos;
    }
    if (pos == 0) {
        throw std::invalid_argument(std::string("invalid ") + option +
                                    " value '" + value +
                                    "' (expected a duration like 90s, 5m, 2h, 1d or 3w)");
    }
    long long amount = 0;

    try {
        amount = std::stoll(value.substr(0, pos));
    } catch (const std::exception&) {
        throw std::invalid_argument(std::string("invalid ") + option + " value '" +
                                    value + "'");
    }

    const std::string unit = value.substr(pos);
    long long factor = 0;
    if (unit == "s") factor = 1;
    else if (unit == "m") factor = 60;
    else if (unit == "h") factor = 3600;
    else if (unit == "d") factor = 86400;
    else if (unit == "w") factor = 604800;
    else {
        throw std::invalid_argument(std::string("invalid ") + option + " unit '" +
                                    unit + "' in '" + value +
                                    "' (expected s, m, h, d or w)");
    }
    if (amount > 0 && factor > std::numeric_limits<long long>::max() / amount) {
        throw std::invalid_argument(std::string("invalid ") + option + " value '" +
                                    value + "' (duration is too large)");
    }

    /* Cap the duration so "now - duration" can never overflow the clock's
       representation: duration_cast of the max rep keeps the product below
       rep::max, and now is always non-negative. */
    const long long maxSeconds =
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::duration::max())
            .count();
    if (amount * factor > maxSeconds) {
        throw std::invalid_argument(std::string("invalid ") + option + " value '" +
                                    value + "' (duration is too large)");
    }
    return std::chrono::seconds(amount * factor);
}

int parseInt(const std::string& value, std::size_t& pos, std::size_t digits,
             const char* option) {
    int result = 0;
    for (std::size_t i = 0; i < digits; ++i) {
        if (pos >= value.size() || !std::isdigit(static_cast<unsigned char>(value[pos]))) {
            throw std::invalid_argument(std::string("invalid ") + option + " value '" +
                                        value + "' (expected YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)");
        }
        result = result * 10 + (value[pos] - '0');
        ++pos;
    }
    return result;
}

std::chrono::system_clock::time_point parseDateTime(const std::string& value,
                                                    const char* option) {
    std::size_t pos = 0;
    const int year = parseInt(value, pos, 4, option);
    if (pos >= value.size() || value[pos] != '-') {
        throw std::invalid_argument(std::string("invalid ") + option + " value '" +
                                    value + "'");
    }
    ++pos;
    const int month = parseInt(value, pos, 2, option);
    if (pos >= value.size() || value[pos] != '-') {
        throw std::invalid_argument(std::string("invalid ") + option + " value '" +
                                    value + "'");
    }
    ++pos;
    const int day = parseInt(value, pos, 2, option);

    int hour = 0;
    int minute = 0;
    int second = 0;
    if (pos < value.size()) {
        if (value[pos] != ' ') {
            throw std::invalid_argument(std::string("invalid ") + option + " value '" +
                                        value + "'");
        }
        ++pos;
        hour = parseInt(value, pos, 2, option);
        if (pos >= value.size() || value[pos] != ':') {
            throw std::invalid_argument(std::string("invalid ") + option + " value '" +
                                        value + "'");
        }
        ++pos;
        minute = parseInt(value, pos, 2, option);
        if (pos < value.size()) {
            if (value[pos] != ':') {
                throw std::invalid_argument(std::string("invalid ") + option +
                                            " value '" + value + "'");
            }
            ++pos;
            second = parseInt(value, pos, 2, option);
        }
    }
    if (pos != value.size()) {
        throw std::invalid_argument(std::string("invalid ") + option + " value '" +
                                    value + "'");
    }
    if (year < 1 || year > 9999 || month < 1 || month > 12 || day < 1 || day > 31 ||
        hour > 23 || minute > 59 || second > 59) {
        throw std::invalid_argument(std::string("invalid ") + option + " value '" +
                                    value + "'");
    }

    const std::chrono::year_month_day date{std::chrono::year(year),
                                           std::chrono::month(month),
                                           std::chrono::day(day)};
    if (!date.ok()) {
        throw std::invalid_argument(std::string("invalid ") + option + " value '" +
                                    value + "'");
    }
    const auto time_point = std::chrono::sys_days{date} + std::chrono::hours(hour) +
                        std::chrono::minutes(minute) + std::chrono::seconds(second);
    return time_point;
}

}  // namespace

DateFilter::DateFilter(std::optional<std::string> modifiedWithin,
                       std::optional<std::string> modifiedBefore,
                       std::optional<std::string> createdWithin,
                       std::optional<std::string> createdBefore)
    : m_now(std::chrono::system_clock::now()),
      m_modifiedWithin(modifiedWithin
                           ? parseDuration(*modifiedWithin, "--changed-within")
                           : std::nullopt),
      m_modifiedBefore(modifiedBefore
                           ? std::optional<std::chrono::system_clock::time_point>(
                                 parseDateTime(*modifiedBefore, "--changed-before"))
                           : std::nullopt),
      m_createdWithin(createdWithin ? parseDuration(*createdWithin, "--created-within")
                                    : std::nullopt),
      m_createdBefore(createdBefore
                          ? std::optional<std::chrono::system_clock::time_point>(
                                parseDateTime(*createdBefore, "--created-before"))
                          : std::nullopt) {}

bool DateFilter::matches(const IEntry& entry, int depth) const {
    (void)depth;
    if (m_modifiedWithin && entry.getModifiedAt() < m_now - *m_modifiedWithin) {
        return false;
    }
    if (m_modifiedBefore && entry.getModifiedAt() > *m_modifiedBefore) {
        return false;
    }
    if (m_createdWithin && entry.getCreatedAt() < m_now - *m_createdWithin) {
        return false;
    }
    if (m_createdBefore && entry.getCreatedAt() > *m_createdBefore) {
        return false;
    }
    return true;
}

}  // namespace domain
