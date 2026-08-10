#include <gtest/gtest.h>

#include <chrono>
#include <csignal>
#include <functional>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "../src/application/dto/QueryResult.hpp"
#include "../src/application/dto/ScanConfig.hpp"
#include "../src/application/port/ISearchService.hpp"
#include "../src/domain/model/CancellationToken.hpp"
#include "../src/domain/model/DomainEntry.hpp"
#include "cli/CliController.hpp"

namespace {

std::string capture(std::ostream& stream, const std::function<void()>& action) {
    std::ostringstream buffer;
    std::streambuf* previous = stream.rdbuf(buffer.rdbuf());
    action();
    stream.rdbuf(previous);
    return buffer.str();
}

class FakeSearchService : public application::ISearchService {
public:
    mutable bool called = false;
    mutable std::vector<std::string> last_paths;
    mutable std::vector<FilterSpec> last_specs;
    mutable const domain::CancellationToken* last_token = nullptr;
    mutable std::function<void()> during_search;

    mutable std::vector<std::unique_ptr<domain::IEntry>> entries;
    mutable bool aborted = false;

    application::QueryResult search(const application::ScanConfig& config,
                                    domain::CancellationToken& token) const override {
        called = true;
        last_paths = config.paths;
        last_specs = config.specs;
        last_token = &token;
        if (during_search) during_search();

        application::QueryResult result;
        result.aborted = aborted;
        for (const auto& entry : entries) {
            result.entries.push_back(std::make_unique<domain::DomainEntry>(
                entry->getType(), entry->isHidden(), entry->isExecutable(),
                entry->getName(), entry->getPath(), entry->getSizeBytes(),
                entry->getCreatedAt(), entry->getModifiedAt()));
        }
        return result;
    }
};

std::unique_ptr<domain::IEntry> makeFileEntry(const std::string& name) {
    return std::make_unique<domain::DomainEntry>(
        domain::EntryType::FILE, false, false, name, name, 1024,
        std::chrono::system_clock::from_time_t(0),
        std::chrono::system_clock::from_time_t(0));
}

}  // namespace

TEST(CliController, ParseErrorPrintsMessageAndSkipsSearch) {
    FakeSearchService service;
    CliController controller(service);

    const std::string err = capture(std::cerr, [&] {
        EXPECT_EQ(controller.run({"--bogus"}), 1);
    });

    EXPECT_NE(err.find("unknown option"), std::string::npos);
    EXPECT_FALSE(service.called);
}

TEST(CliController, NoPatternReturnsErrorAndSkipsSearch) {
    FakeSearchService service;
    CliController controller(service);

    EXPECT_EQ(controller.run({}), 1);
    EXPECT_FALSE(service.called);

    EXPECT_EQ(controller.run({"--format", "json"}), 1);
    EXPECT_FALSE(service.called);
}

TEST(CliController, ForwardsPathsAndSpecsToSearchService) {
    FakeSearchService service;
    CliController controller(service);

    const int code = controller.run({"main.cpp", "src", "tests", "--extension", "cpp"});

    EXPECT_EQ(code, 0);
    EXPECT_TRUE(service.called);
    ASSERT_EQ(service.last_paths.size(), 2u);
    EXPECT_EQ(service.last_paths[0], "src");
    EXPECT_EQ(service.last_paths[1], "tests");
    ASSERT_EQ(service.last_specs.size(), 1u);
    ASSERT_TRUE(service.last_specs[0].extension.has_value());
    EXPECT_EQ(service.last_specs[0].extension->at(0), "cpp");
}

TEST(CliController, FormatsMatchesPerFormatType) {
    FakeSearchService service;
    service.entries.push_back(makeFileEntry("main.cpp"));
    CliController controller(service);

    {
        const std::string out = capture(std::cout, [&] {
            EXPECT_EQ(controller.run({"main.cpp", "src"}), 0);
        });
        EXPECT_FALSE(out.empty());
        EXPECT_NE(out.find("main.cpp"), std::string::npos);
    }

    {
        const std::string out = capture(std::cout, [&] {
            EXPECT_EQ(controller.run({"main.cpp", "src", "--format", "json"}), 0);
        });
        EXPECT_NE(out.find("\"name\""), std::string::npos);
        EXPECT_NE(out.find("main.cpp"), std::string::npos);
    }
}

TEST(CliController, AbortedSearchReturnsInterruptedExitCode) {
    FakeSearchService service;
    service.aborted = true;
    service.entries.push_back(makeFileEntry("main.cpp"));
    CliController controller(service);

    const std::string out = capture(std::cout, [&] {
        EXPECT_EQ(controller.run({"main.cpp", "src"}), 130);
    });

    EXPECT_TRUE(service.called);
    EXPECT_TRUE(out.empty());
}

TEST(CliController, PassesLiveCancellationTokenToSearchService) {
    FakeSearchService service;
    CliController controller(service);

    bool token_stopped = true;
    service.during_search = [&] { token_stopped = service.last_token->isStopped(); };

    EXPECT_EQ(controller.run({"main.cpp", "src"}), 0);
    EXPECT_FALSE(token_stopped);
}

#if !defined(_WIN32)
TEST(CliController, InterruptSignalDuringSearchStopsToken) {
    FakeSearchService service;
    CliController controller(service);

    bool token_was_stopped = false;
    service.during_search = [&] {
        EXPECT_FALSE(service.last_token->isStopped());
        std::raise(SIGINT);
        token_was_stopped = service.last_token->isStopped();
    };

    EXPECT_EQ(controller.run({"main.cpp", "src"}), 0);
    EXPECT_TRUE(token_was_stopped);
}
#endif