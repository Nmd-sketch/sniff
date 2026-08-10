#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "../src/domain/model/DomainEntry.hpp"
#include "../src/domain/service/Sorter.hpp"

namespace {

std::unique_ptr<domain::IEntry> entry(const std::string& path) {
    const auto time = std::chrono::system_clock::from_time_t(0);
    return std::make_unique<domain::DomainEntry>(domain::EntryType::FILE, false, false,
                                                 "name", path, 0, time, time);
}

}  // namespace

TEST(Sorter, SortsByPath) {
    std::vector<std::unique_ptr<domain::IEntry>> entries;
    entries.push_back(entry("zebra.txt"));
    entries.push_back(entry("apple.txt"));
    entries.push_back(entry("mango.txt"));

    domain::Sorter sorter;
    sorter.sort(entries);

    ASSERT_EQ(entries.size(), 3u);
    EXPECT_EQ(entries[0]->getPath(), "apple.txt");
    EXPECT_EQ(entries[1]->getPath(), "mango.txt");
    EXPECT_EQ(entries[2]->getPath(), "zebra.txt");
}

TEST(Sorter, IsCaseInsensitive) {
    std::vector<std::unique_ptr<domain::IEntry>> entries;
    entries.push_back(entry("Zebra.txt"));
    entries.push_back(entry("apple.txt"));

    domain::Sorter sorter;
    sorter.sort(entries);

    EXPECT_EQ(entries[0]->getPath(), "apple.txt");
    EXPECT_EQ(entries[1]->getPath(), "Zebra.txt");
}

TEST(Sorter, EmptyListIsFine) {
    std::vector<std::unique_ptr<domain::IEntry>> entries;
    domain::Sorter sorter;
    sorter.sort(entries);
    EXPECT_TRUE(entries.empty());
}