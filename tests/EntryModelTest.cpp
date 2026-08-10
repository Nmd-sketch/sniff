#include <gtest/gtest.h>

#include <chrono>
#include <type_traits>

#include "../src/domain/model/DomainEntry.hpp"

TEST(EntryModel, IEntryIsAbstract) {
    EXPECT_TRUE(std::is_abstract_v<domain::IEntry>);
}

TEST(EntryModel, DomainEntryRoundTripsValues) {
    const auto created = std::chrono::system_clock::from_time_t(1000);
    const auto modified = std::chrono::system_clock::from_time_t(2000);

    const domain::DomainEntry entry(domain::EntryType::SYMLINK, true, false, "link",
                                    "a/link", 42u, created, modified);

    EXPECT_EQ(entry.getType(), domain::EntryType::SYMLINK);
    EXPECT_TRUE(entry.isHidden());
    EXPECT_FALSE(entry.isExecutable());
    EXPECT_EQ(entry.getName(), "link");
    EXPECT_EQ(entry.getPath(), "a/link");
    EXPECT_EQ(entry.getSizeBytes(), 42u);
    EXPECT_EQ(entry.getCreatedAt(), created);
    EXPECT_EQ(entry.getModifiedAt(), modified);
}

TEST(EntryModel, DomainEntrySizesAreUintmax) {
    const auto time = std::chrono::system_clock::from_time_t(0);
    const domain::DomainEntry file(domain::EntryType::FILE, false, true, "big", "big",
                                   std::numeric_limits<std::uintmax_t>::max(), time, time);

    EXPECT_EQ(file.getSizeBytes(), std::numeric_limits<std::uintmax_t>::max());
    EXPECT_TRUE(file.isExecutable());
}