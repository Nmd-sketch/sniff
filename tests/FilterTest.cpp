#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "../src/domain/model/DomainEntry.hpp"
#include "../src/domain/model/FilterSpec.hpp"
#include "../src/domain/service/FilterChain.hpp"
#include "../src/domain/service/filters/DateFilter.hpp"
#include "../src/domain/service/filters/DepthFilter.hpp"
#include "../src/domain/service/filters/ExcludeFilter.hpp"
#include "../src/domain/service/filters/ExtensionFilter.hpp"
#include "../src/domain/service/filters/HiddenFilter.hpp"
#include "../src/domain/service/filters/NameFilter.hpp"
#include "../src/domain/service/filters/SizeFilter.hpp"
#include "../src/domain/service/filters/TypeFilter.hpp"

namespace {

struct EntrySpec {
    domain::EntryType type = domain::EntryType::FILE;
    bool hidden = false;
    bool executable = false;
    std::string name;
    std::string path;
    std::uintmax_t size = 0;
    std::chrono::system_clock::time_point time =
        std::chrono::system_clock::from_time_t(0);
};

domain::DomainEntry makeEntry(const EntrySpec& spec) {
    return domain::DomainEntry(spec.type, spec.hidden, spec.executable, spec.name,
                               spec.path, spec.size, spec.time, spec.time);
}

}  // namespace

TEST(NameFilter, MatchesOnName) {
    const domain::NameFilter filter("main", MatchMode::FIXED, CaseMode::SENSITIVE, false);
    EXPECT_TRUE(filter.matches(makeEntry({.name = "main.cpp", .path = "a/main.cpp"}), 0));
    EXPECT_FALSE(filter.matches(makeEntry({.name = "utils.hpp", .path = "a/utils.hpp"}), 0));
}

TEST(NameFilter, MatchesOnFullPath) {
    const domain::NameFilter filter("a/main", MatchMode::FIXED, CaseMode::SENSITIVE, true);
    EXPECT_TRUE(filter.matches(makeEntry({.name = "main.cpp", .path = "a/main.cpp"}), 0));
    EXPECT_FALSE(filter.matches(makeEntry({.name = "main.cpp", .path = "b/main.cpp"}), 0));
}

TEST(ExtensionFilter, MatchesSuffix) {
    const domain::ExtensionFilter filter({"cpp", "hpp"});
    EXPECT_TRUE(filter.matches(makeEntry({.name = "main.cpp"}), 0));
    EXPECT_TRUE(filter.matches(makeEntry({.name = "util.HPP"}), 0));
    EXPECT_FALSE(filter.matches(makeEntry({.name = "main.c"}), 0));
    EXPECT_FALSE(filter.matches(makeEntry({.name = "main"}), 0));
}

TEST(ExtensionFilter, EmptyExtensionMatchesExtensionless) {
    const domain::ExtensionFilter filter({""});
    EXPECT_TRUE(filter.matches(makeEntry({.name = "Makefile"}), 0));
    EXPECT_FALSE(filter.matches(makeEntry({.name = "Makefile.txt"}), 0));
}

TEST(SizeFilter, RangeInclusive) {
    const domain::SizeFilter filter(std::optional<std::uintmax_t>(100),
                                    std::optional<std::uintmax_t>(200));
    EXPECT_TRUE(filter.matches(makeEntry({.size = 100}), 0));
    EXPECT_TRUE(filter.matches(makeEntry({.size = 200}), 0));
    EXPECT_FALSE(filter.matches(makeEntry({.size = 99}), 0));
    EXPECT_FALSE(filter.matches(makeEntry({.size = 201}), 0));
}

TEST(SizeFilter, MinOnly) {
    const domain::SizeFilter filter(std::optional<std::uintmax_t>(100), std::nullopt);
    EXPECT_TRUE(filter.matches(makeEntry({.size = 100}), 0));
    EXPECT_FALSE(filter.matches(makeEntry({.size = 99}), 0));
}

TEST(HiddenFilter, ExcludesHiddenWhenNotDetecting) {
    const domain::HiddenFilter filter(false);
    EXPECT_FALSE(filter.matches(makeEntry({.hidden = true}), 0));
    EXPECT_TRUE(filter.matches(makeEntry({.hidden = false}), 0));
}

TEST(HiddenFilter, IncludesHiddenWhenDetecting) {
    const domain::HiddenFilter filter(true);
    EXPECT_TRUE(filter.matches(makeEntry({.hidden = true}), 0));
    EXPECT_TRUE(filter.matches(makeEntry({.hidden = false}), 0));
}

TEST(DepthFilter, MinAndMaxBoundaries) {
    const domain::DepthFilter filter(std::optional<int>(1), std::optional<int>(3));
    EXPECT_FALSE(filter.matches(makeEntry({.name = "x"}), 0));
    EXPECT_TRUE(filter.matches(makeEntry({.name = "x"}), 1));
    EXPECT_TRUE(filter.matches(makeEntry({.name = "x"}), 3));
    EXPECT_FALSE(filter.matches(makeEntry({.name = "x"}), 4));
}

TEST(DepthFilter, MaxOnly) {
    const domain::DepthFilter filter(std::nullopt, std::optional<int>(2));
    EXPECT_TRUE(filter.matches(makeEntry({.name = "x"}), 0));
    EXPECT_TRUE(filter.matches(makeEntry({.name = "x"}), 2));
    EXPECT_FALSE(filter.matches(makeEntry({.name = "x"}), 3));
}

TEST(DateFilter, ModifiedWithin) {
    const auto now = std::chrono::system_clock::now();
    const auto day = std::chrono::hours(24);

    const domain::DateFilter filter(std::string("2d"), std::nullopt, std::nullopt,
                                    std::nullopt);
    EXPECT_TRUE(filter.matches(makeEntry({.time = now - day}), 0));
    EXPECT_FALSE(filter.matches(makeEntry({.time = now - day * 3}), 0));
    EXPECT_TRUE(filter.matches(makeEntry({.time = now}), 0));
}

TEST(DateFilter, ModifiedBefore) {
    const auto now = std::chrono::system_clock::now();

    const domain::DateFilter filter(std::nullopt, std::string("2020-01-01"), std::nullopt,
                                    std::nullopt);
    const auto old = std::chrono::system_clock::from_time_t(1577750400);  // 2019-12-31
    const auto new_ = std::chrono::system_clock::from_time_t(1704067200); // 2024-01-01

    EXPECT_TRUE(filter.matches(makeEntry({.time = old}), 0));
    EXPECT_FALSE(filter.matches(makeEntry({.time = new_}), 0));
    (void)now;
}

TEST(DateFilter, CreatedWithin) {
    const auto now = std::chrono::system_clock::now();
    const auto day = std::chrono::hours(24);

    const domain::DateFilter filter(std::nullopt, std::nullopt, std::string("1d"),
                                    std::nullopt);
    EXPECT_TRUE(filter.matches(makeEntry({.time = now - day / 2}), 0));
    EXPECT_FALSE(filter.matches(makeEntry({.time = now - day * 2}), 0));
}

TEST(DateFilter, AllConditionsMustPass) {
    const auto now = std::chrono::system_clock::now();
    const auto day = std::chrono::hours(24);

    const domain::DateFilter filter(std::string("2d"), std::string("2020-01-01"),
                                    std::nullopt, std::nullopt);
    /* Modified now: passes Within but fails Before. */
    EXPECT_FALSE(filter.matches(makeEntry({.time = now}), 0));
}

TEST(DateFilter, InvalidValuesThrow) {
    EXPECT_THROW(domain::DateFilter(std::string("soon"), std::nullopt, std::nullopt,
                                    std::nullopt),
                 std::invalid_argument);
    EXPECT_THROW(domain::DateFilter(std::nullopt, std::string("2020-13-40"), std::nullopt,
                                    std::nullopt),
                 std::invalid_argument);
}

TEST(TypeFilter, MatchesFileTypes) {
    const domain::TypeFilter filter({FileType::FILE, FileType::DIRECTORY});
    EXPECT_TRUE(filter.matches(makeEntry({.type = domain::EntryType::FILE}), 0));
    EXPECT_TRUE(filter.matches(makeEntry({.type = domain::EntryType::DIRECTORY}), 0));
    EXPECT_FALSE(filter.matches(makeEntry({.type = domain::EntryType::SYMLINK}), 0));
}

TEST(TypeFilter, MatchesExecutableAndEmpty) {
    const domain::TypeFilter executable({FileType::EXECUTABLE});
    EXPECT_TRUE(executable.matches(makeEntry({.executable = true, .size = 500}), 0));
    EXPECT_FALSE(executable.matches(makeEntry({.executable = false, .size = 500}), 0));

    const domain::TypeFilter empty({FileType::EMPTY});
    EXPECT_TRUE(empty.matches(makeEntry({.size = 0}), 0));
    EXPECT_FALSE(empty.matches(makeEntry({.size = 1}), 0));
    EXPECT_FALSE(empty.matches(makeEntry({.type = domain::EntryType::DIRECTORY}), 0));
}

TEST(ExcludeFilter, CaseInsensitiveSubstring) {
    const domain::ExcludeFilter filter({"build", "NODE_MODULES"});
    EXPECT_FALSE(filter.matches(makeEntry({.path = "project/build/x.cpp"}), 0));
    EXPECT_FALSE(filter.matches(makeEntry({.path = "project/node_modules/y.cpp"}), 0));
    EXPECT_TRUE(filter.matches(makeEntry({.path = "project/src/z.cpp"}), 0));
}

TEST(FilterChain, AllFiltersMustPass) {
    std::vector<std::unique_ptr<domain::IFilter>> filters;
    filters.push_back(std::make_unique<domain::ExtensionFilter>(
        std::vector<std::string>{"cpp"}));
    filters.push_back(std::make_unique<domain::SizeFilter>(
        std::optional<std::uintmax_t>(1000), std::nullopt));
    const domain::FilterChain chain(std::move(filters));

    EXPECT_TRUE(chain.matches(makeEntry({.name = "a.cpp", .size = 2000}), 0));
    EXPECT_FALSE(chain.matches(makeEntry({.name = "a.h", .size = 2000}), 0));
    EXPECT_FALSE(chain.matches(makeEntry({.name = "a.cpp", .size = 500}), 0));
}

TEST(FilterChain, EmptyChainMatchesEverything) {
    const domain::FilterChain chain({});
    EXPECT_TRUE(chain.empty());
    EXPECT_TRUE(chain.matches(makeEntry({.name = "anything"}), 0));
}