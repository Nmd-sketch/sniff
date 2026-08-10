#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "../src/application/dto/QueryResult.hpp"
#include "../src/application/dto/ScanConfig.hpp"
#include "../src/application/service/SearchService.hpp"
#include "../src/domain/model/CancellationToken.hpp"
#include "../src/domain/model/DomainEntry.hpp"
#include "../src/domain/ports/IEntryRepository.hpp"

namespace {

class FakeEntryRepository : public domain::IEntryRepository {
public:
    struct Node {
        domain::EntryType type = domain::EntryType::FILE;
        bool hidden = false;
        bool executable = false;
        std::string name;
        std::string path;
        std::uintmax_t size = 0;
        int depth = 0;
        std::chrono::system_clock::time_point time =
            std::chrono::system_clock::now() - std::chrono::hours(1);
    };

    std::vector<Node> nodes;
    int stop_after_sink_calls = -1;
    mutable std::vector<std::vector<std::string>> scanned_paths;
    mutable int sink_calls = 0;

    void scan(const std::vector<std::string>& paths,
              const FilterSpec&,
              const Sink& sink,
              domain::CancellationToken& token) const override {
        scanned_paths.push_back(paths);
        for (const auto& node : nodes) {
            if (token.isStopped()) return;
            auto entry = std::make_unique<domain::DomainEntry>(
                node.type, node.hidden, node.executable, node.name, node.path, node.size,
                node.time, node.time);
            if (!sink(std::move(entry), node.depth)) return;
            ++sink_calls;
            if (stop_after_sink_calls >= 0 && sink_calls >= stop_after_sink_calls) {
                token.requestStop();
            }
        }
    }
};

application::ScanConfig defaultConfig() {
    application::ScanConfig config;
    config.pattern = "main";
    return config;
}

}  // namespace

TEST(SearchService, EmptyRepositoryProducesEmptyResult) {
    const FakeEntryRepository repository;
    const application::SearchService service(repository);

    domain::CancellationToken token;
    const application::QueryResult result = service.search(defaultConfig(), token);

    EXPECT_TRUE(result.entries.empty());
    EXPECT_EQ(result.stats.scanned, 0u);
    EXPECT_EQ(result.stats.matches, 0u);
    EXPECT_FALSE(result.aborted);
}

TEST(SearchService, FiltersAndCollectsMatches) {
    FakeEntryRepository repository;
    repository.nodes = {
        {.name = "main.cpp", .path = "a/main.cpp", .size = 2048},
        {.name = "main.h", .path = "a/main.h", .size = 512},
        {.name = "utils.cpp", .path = "a/utils.cpp", .size = 1024},
    };
    const application::SearchService service(repository);

    domain::CancellationToken token;
    const application::QueryResult result =
        service.search(defaultConfig(), token);

    /* Unanchored regex "main" matches main.cpp and main.h. */
    ASSERT_EQ(result.entries.size(), 2u);
    EXPECT_EQ(result.entries[0]->getName(), "main.cpp");
    EXPECT_EQ(result.entries[1]->getName(), "main.h");
    EXPECT_EQ(result.stats.scanned, 3u);
    EXPECT_EQ(result.stats.matches, 2u);
    EXPECT_EQ(result.stats.total_size, 2560u);
    EXPECT_EQ(result.stats.file_count, 2u);
}

TEST(SearchService, ExtensionSpecFilters) {
    FakeEntryRepository repository;
    repository.nodes = {
        {.name = "notes.txt", .path = "notes.txt"},
        {.name = "main.cpp", .path = "main.cpp", .size = 100},
    };
    const application::SearchService service(repository);

    application::ScanConfig config = defaultConfig();
    FilterSpec spec;
    spec.extension = std::vector<std::string>{"cpp"};
    config.specs.push_back(spec);

    domain::CancellationToken token;
    const application::QueryResult result = service.search(config, token);

    ASSERT_EQ(result.entries.size(), 1u);
    EXPECT_EQ(result.entries[0]->getName(), "main.cpp");
    EXPECT_EQ(result.stats.scanned, 2u);
}

TEST(SearchService, ResultIsSortedByPath) {
    FakeEntryRepository repository;
    repository.nodes = {
        {.name = "b.cpp", .path = "b.cpp"},
        {.name = "a.cpp", .path = "a.cpp"},
        {.name = "c.cpp", .path = "c.cpp"},
    };
    const application::SearchService service(repository);

    application::ScanConfig config;
    config.pattern = ".cpp";
    domain::CancellationToken token;
    const application::QueryResult result = service.search(config, token);

    ASSERT_EQ(result.entries.size(), 3u);
    EXPECT_EQ(result.entries[0]->getPath(), "a.cpp");
    EXPECT_EQ(result.entries[1]->getPath(), "b.cpp");
    EXPECT_EQ(result.entries[2]->getPath(), "c.cpp");
}

TEST(SearchService, AggregatesTypeCounts) {
    FakeEntryRepository repository;
    repository.nodes = {
        {.type = domain::EntryType::DIRECTORY, .name = "src", .path = "src"},
        {.type = domain::EntryType::SYMLINK, .name = "link", .path = "link"},
        {.name = "main.cpp", .path = "src/main.cpp", .size = 500},
    };
    const application::SearchService service(repository);

    application::ScanConfig config;
    config.pattern = "";
    domain::CancellationToken token;
    const application::QueryResult result = service.search(config, token);

    EXPECT_EQ(result.stats.file_count, 1u);
    EXPECT_EQ(result.stats.dir_count, 1u);
    EXPECT_EQ(result.stats.symlink_count, 1u);
    EXPECT_EQ(result.stats.total_size, 500u);
}

TEST(SearchService, HiddenEntriesExcludedByDefault) {
    FakeEntryRepository repository;
repository.nodes = {
        {.hidden = true, .name = ".hidden", .path = ".hidden"},
        {.name = "visible", .path = "visible"},
    };
    const application::SearchService service(repository);

    application::ScanConfig config;
    config.pattern = "";
    domain::CancellationToken token;
    const application::QueryResult result = service.search(config, token);

    ASSERT_EQ(result.entries.size(), 1u);
    EXPECT_EQ(result.entries[0]->getName(), "visible");

    EXPECT_EQ(result.stats.scanned, 2u);
}

TEST(SearchService, AbortedBeforeScanReturnsAbortedEmpty) {
    const FakeEntryRepository repository;
    const application::SearchService service(repository);

    domain::CancellationToken token;
    token.requestStop();
    const application::QueryResult result = service.search(defaultConfig(), token);

    EXPECT_TRUE(result.aborted);
    EXPECT_TRUE(result.entries.empty());
    EXPECT_TRUE(repository.scanned_paths.empty());
}

TEST(SearchService, AbortMidScanKeepsPartialResults) {
    FakeEntryRepository repository;
    repository.stop_after_sink_calls = 2;
    repository.nodes = {
        {.name = "main.cpp", .path = "1.cpp"},
        {.name = "main.cpp", .path = "2.cpp"},
        {.name = "main.cpp", .path = "3.cpp"},
    };
    const application::SearchService service(repository);

    domain::CancellationToken token;
    const application::QueryResult result = service.search(defaultConfig(), token);

    EXPECT_TRUE(result.aborted);
    ASSERT_EQ(result.entries.size(), 2u);
    EXPECT_EQ(result.stats.scanned, 2u);
}

TEST(SearchService, ProgressCallbackIsInvokedAndReportsFinalCount) {
    FakeEntryRepository repository;
    for (int i = 0; i < 5; ++i) {
        repository.nodes.push_back(
            {.name = "f" + std::to_string(i), .path = "f" + std::to_string(i)});
    }
    const application::SearchService service(repository);

    application::ScanConfig config;
    config.pattern = "";
    std::vector<std::uint64_t> reports;
    config.on_progress = [&](std::uint64_t scanned, const std::string&) {
        reports.push_back(scanned);
    };

    domain::CancellationToken token;
    const application::QueryResult result = service.search(config, token);

    ASSERT_FALSE(reports.empty());
    EXPECT_EQ(reports.back(), 5u);
}

TEST(SearchService, DefaultsToCurrentDirectoryWhenNoPaths) {
    FakeEntryRepository repository;
    const application::SearchService service(repository);

    domain::CancellationToken token;
    (void)service.search(defaultConfig(), token);

    ASSERT_EQ(repository.scanned_paths.size(), 1u);
    ASSERT_EQ(repository.scanned_paths[0].size(), 1u);
    EXPECT_EQ(repository.scanned_paths[0][0], ".");
}

TEST(SearchService, InvalidPatternThrows) {
    const FakeEntryRepository repository;
    const application::SearchService service(repository);

    application::ScanConfig config;
    config.pattern = "[unclosed";
    FilterSpec spec;
    spec.match_mode = MatchMode::REGEX;
    config.specs.push_back(spec);

    domain::CancellationToken token;
    EXPECT_THROW(service.search(config, token), std::invalid_argument);
}

