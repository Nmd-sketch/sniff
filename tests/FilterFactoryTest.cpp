#include <gtest/gtest.h>

#include <chrono>
#include <string>

#include "../src/domain/model/DomainEntry.hpp"
#include "../src/domain/model/FilterSpec.hpp"
#include "../src/domain/service/FilterFactory.hpp"

namespace {

domain::DomainEntry fileEntry(const std::string& name, const std::string& path,
                              std::uintmax_t size = 1000,
                              domain::EntryType type = domain::EntryType::FILE,
                              bool hidden = false, bool executable = false) {
    const auto time = std::chrono::system_clock::now() - std::chrono::hours(1);
    return domain::DomainEntry(type, hidden, executable, name, path, size, time, time);
}

}  // namespace

TEST(FilterFactory, NoOptionsOnlyExcludesHidden) {
    const FilterSpec spec;
    const domain::FilterChain chain = domain::FilterFactory::createChain("", spec);
    EXPECT_FALSE(chain.empty());
    EXPECT_TRUE(chain.matches(fileEntry("main.cpp", "src/main.cpp"), 0));
    EXPECT_FALSE(chain.matches(
        fileEntry("main.cpp", "src/main.cpp", 1000, domain::EntryType::FILE, true), 0));
}

TEST(FilterFactory, PatternBuildsNameFilter) {
    const FilterSpec spec;
    const domain::FilterChain chain = domain::FilterFactory::createChain("main", spec);
    EXPECT_TRUE(chain.matches(fileEntry("main.cpp", "src/main.cpp"), 0));
    EXPECT_FALSE(chain.matches(fileEntry("utils.cpp", "src/utils.cpp"), 0));
}

TEST(FilterFactory, FullSpecFiltersCompose) {
    FilterSpec spec;
    spec.extension = std::vector<std::string>{"cpp"};
    spec.min_size = 500;
    spec.max_size = 5000;
    spec.types = std::vector<FileType>{FileType::FILE};
    spec.max_depth = 2;
    spec.exclude = std::vector<std::string>{"build"};
    spec.detect_hidden = false;

    const domain::FilterChain chain = domain::FilterFactory::createChain("", spec);

    EXPECT_TRUE(chain.matches(fileEntry("main.cpp", "src/main.cpp", 1000), 1));
    EXPECT_FALSE(chain.matches(fileEntry("main.cpp", "src/main.cpp", 100), 1));
    EXPECT_FALSE(chain.matches(fileEntry("main.cpp", "build/main.cpp", 1000), 1));
    EXPECT_FALSE(chain.matches(fileEntry("main.cpp", "src/main.cpp", 1000), 3));
    EXPECT_FALSE(chain.matches(
        fileEntry("main.cpp", "src/main.cpp", 1000, domain::EntryType::SYMLINK), 1));
    EXPECT_FALSE(chain.matches(fileEntry("main.cpp", "src/main.cpp", 1000,
                                         domain::EntryType::FILE, true),
                               1));
}

TEST(FilterFactory, InvalidRegexPatternThrows) {
    FilterSpec spec;
    spec.match_mode = MatchMode::REGEX;
    EXPECT_THROW(domain::FilterFactory::createChain("[unclosed", spec),
                 std::invalid_argument);
}

TEST(FilterFactory, InvalidDateThrows) {
    FilterSpec spec;
    spec.modified_within = std::string("soon");
    EXPECT_THROW(domain::FilterFactory::createChain("", spec), std::invalid_argument);
}
