#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "../src/domain/model/IEntry.hpp"
#include "formatter/Formatting.hpp"
#include "formatter/JsonFormatter.hpp"
#include "formatter/TableFormatter.hpp"
#include "formatter/TreeFormatter.hpp"

namespace {

class FakeEntry : public domain::IEntry {
public:
    FakeEntry(domain::EntryType type, std::string name, std::string path,
              std::uintmax_t size = 0, bool hidden = false,
              std::chrono::system_clock::time_point time =
                  std::chrono::system_clock::from_time_t(0),
              bool executable = false)
        : m_type(type), m_name(std::move(name)), m_path(std::move(path)), m_size(size),
          m_hidden(hidden), m_executable(executable), m_time(time) {}

    const std::string& getName() const override { return m_name; }
    const std::string& getPath() const override { return m_path; }
    domain::EntryType getType() const override { return m_type; }
    bool isHidden() const override { return m_hidden; }
    bool isExecutable() const override { return m_executable; }
    std::uintmax_t getSizeBytes() const override { return m_size; }
    const std::chrono::system_clock::time_point& getCreatedAt() const override { return m_time; }
    const std::chrono::system_clock::time_point& getModifiedAt() const override { return m_time; }

private:
    domain::EntryType m_type;
    std::string m_name;
    std::string m_path;
    std::uintmax_t m_size;
    bool m_hidden;
    bool m_executable;
    std::chrono::system_clock::time_point m_time;
};

using Entries = std::vector<std::unique_ptr<domain::IEntry>>;

Entries makeEntries(std::vector<FakeEntry> raw) {
    Entries entries;
    entries.reserve(raw.size());
    for (auto& entry : raw) {
        entries.push_back(std::make_unique<FakeEntry>(std::move(entry)));
    }
    return entries;
}

constexpr auto epoch = std::chrono::system_clock::time_point{};

}  // namespace

/* ------------------------- Formatting helpers ------------------------- */

TEST(HumanReadableSize, BytesStayInBytes) {
    EXPECT_EQ(formatting::humanReadableSize(0), "0 B");
    EXPECT_EQ(formatting::humanReadableSize(1), "1 B");
    EXPECT_EQ(formatting::humanReadableSize(1023), "1023 B");
}

TEST(HumanReadableSize, BinaryUnits) {
    EXPECT_EQ(formatting::humanReadableSize(1024), "1 KiB");
    EXPECT_EQ(formatting::humanReadableSize(2048), "2 KiB");
    EXPECT_EQ(formatting::humanReadableSize(1048576), "1 MiB");
    EXPECT_EQ(formatting::humanReadableSize(1073741824), "1 GiB");
}

TEST(HumanReadableSize, OneDecimalForFractions) {
    EXPECT_EQ(formatting::humanReadableSize(1536), "1.5 KiB");
    EXPECT_EQ(formatting::humanReadableSize(1610612736), "1.5 GiB");
}

TEST(FormatDateTime, RendersUtcTimestamp) {
    const auto time = std::chrono::system_clock::from_time_t(60 * 60 * 24);
    EXPECT_EQ(formatting::formatDateTime(time), "1970-01-02 00:00:00");
}

/* ------------------------- TableFormatter ------------------------- */

TEST(TableFormatter, EmptyListYieldsNothing) {
    EXPECT_EQ(TableFormatter().formatEntries(makeEntries({})), "");
}

TEST(TableFormatter, RendersAlignedColumns) {
    const Entries entries = makeEntries({
        {domain::EntryType::FILE, "main.cpp", "src/main.cpp", 1536, false, epoch},
        {domain::EntryType::DIRECTORY, "src", "src", 0, false, epoch},
        {domain::EntryType::SYMLINK, "link", "src/link", 0, false, epoch},
    });

    const std::string expected =
        "TYPE  NAME      SIZE     MODIFIED\n"
        "f     main.cpp  1.5 KiB  1970-01-01 00:00:00\n"
        "d     src       -        1970-01-01 00:00:00\n"
        "l     link      -        1970-01-01 00:00:00\n";

    EXPECT_EQ(TableFormatter().formatEntries(entries), expected);
}

TEST(TableFormatter, NonFilesShowDashInSizeColumn) {
    const Entries entries = makeEntries({
        {domain::EntryType::DIRECTORY, "build", "build", 999999, false, epoch},
        {domain::EntryType::SYMLINK, "current", "current", 12345, false, epoch},
    });

    const std::string expected =
        "TYPE  NAME     SIZE  MODIFIED\n"
        "d     build    -     1970-01-01 00:00:00\n"
        "l     current  -     1970-01-01 00:00:00\n";

    EXPECT_EQ(TableFormatter().formatEntries(entries), expected);
}

/* ------------------------- TreeFormatter ------------------------- */

TEST(TreeFormatter, EmptyListYieldsNothing) {
    EXPECT_EQ(TreeFormatter().formatEntries(makeEntries({})), "");
}

TEST(TreeFormatter, SingleDirectoryWithNestedChildren) {
    const Entries entries = makeEntries({
        {domain::EntryType::FILE, "b", "a/b"},
        {domain::EntryType::FILE, "c.txt", "a/c.txt"},
        {domain::EntryType::FILE, "e", "a/d/e"},
    });

    const std::string expected =
        "a/\n"
        "|-- d/\n"
        "|   \\-- e\n"
        "|-- b\n"
        "\\-- c.txt\n";

    EXPECT_EQ(TreeFormatter().formatEntries(entries), expected);
}

TEST(TreeFormatter, MultipleRootsRenderIndependently) {
    const Entries entries = makeEntries({
        {domain::EntryType::FILE, "b", "a/b"},
        {domain::EntryType::FILE, "z.txt", "z.txt"},
    });

    const std::string expected =
        "a/\n"
        "\\-- b\n"
        "z.txt\n";

    EXPECT_EQ(TreeFormatter().formatEntries(entries), expected);
}

TEST(TreeFormatter, ChildrenSortedDirectoriesFirstThenName) {
    const Entries entries = makeEntries({
        {domain::EntryType::DIRECTORY, "zdir", "a/zdir"},
        {domain::EntryType::FILE, "afile", "a/afile"},
        {domain::EntryType::DIRECTORY, "bdir", "a/bdir"},
    });

    const std::string expected =
        "a/\n"
        "|-- bdir/\n"
        "|-- zdir/\n"
        "\\-- afile\n";

    EXPECT_EQ(TreeFormatter().formatEntries(entries), expected);
}

TEST(TreeFormatter, WindowsSeparatorsNormalized) {
    const Entries entries = makeEntries({
        {domain::EntryType::FILE, "c.txt", "a\\b\\c.txt"},
    });

    const std::string expected =
        "a/\n"
        "\\-- b/\n"
        "    \\-- c.txt\n";

    EXPECT_EQ(TreeFormatter().formatEntries(entries), expected);
}

/* ------------------------- JsonFormatter ------------------------- */

TEST(JsonFormatter, EmptyListYieldsEmptyArray) {
    EXPECT_EQ(JsonFormatter().formatEntries(makeEntries({})), "{\n  \"entries\": []\n}\n");
}

TEST(JsonFormatter, SingleEntryAllFields) {
    const Entries entries = makeEntries({
        {domain::EntryType::FILE, "main.cpp", "src/main.cpp", 2048, false, epoch},
    });

    const std::string expected =
        "{\n"
        "  \"entries\": [\n"
        "    {\n"
        "      \"name\": \"main.cpp\",\n"
        "      \"path\": \"src/main.cpp\",\n"
        "      \"type\": \"file\",\n"
        "      \"size\": 2048,\n"
        "      \"created\": \"1970-01-01 00:00:00\",\n"
        "      \"modified\": \"1970-01-01 00:00:00\",\n"
        "      \"hidden\": false\n"
        "    }\n"
        "  ]\n"
        "}\n";

    EXPECT_EQ(JsonFormatter().formatEntries(entries), expected);
}

TEST(JsonFormatter, MultipleEntriesCommaSeparated) {
    const Entries entries = makeEntries({
        {domain::EntryType::DIRECTORY, "src", "src", 0, true, epoch},
        {domain::EntryType::SYMLINK, "latest", "src/latest", 0, false, epoch},
    });

    const std::string expected =
        "{\n"
        "  \"entries\": [\n"
        "    {\n"
        "      \"name\": \"src\",\n"
        "      \"path\": \"src\",\n"
        "      \"type\": \"directory\",\n"
        "      \"size\": 0,\n"
        "      \"created\": \"1970-01-01 00:00:00\",\n"
        "      \"modified\": \"1970-01-01 00:00:00\",\n"
        "      \"hidden\": true\n"
        "    },\n"
        "    {\n"
        "      \"name\": \"latest\",\n"
        "      \"path\": \"src/latest\",\n"
        "      \"type\": \"symlink\",\n"
        "      \"size\": 0,\n"
        "      \"created\": \"1970-01-01 00:00:00\",\n"
        "      \"modified\": \"1970-01-01 00:00:00\",\n"
        "      \"hidden\": false\n"
        "    }\n"
        "  ]\n"
        "}\n";

    EXPECT_EQ(JsonFormatter().formatEntries(entries), expected);
}

TEST(JsonFormatter, EscapesSpecialCharacters) {
    const Entries entries = makeEntries({
        {domain::EntryType::FILE, "we\"ird\nname", "a\\b\\we\"ird\nname", 0, false, epoch},
    });

    const std::string expected =
        "{\n"
        "  \"entries\": [\n"
        "    {\n"
        "      \"name\": \"we\\\"ird\\nname\",\n"
        "      \"path\": \"a\\\\b\\\\we\\\"ird\\nname\",\n"
        "      \"type\": \"file\",\n"
        "      \"size\": 0,\n"
        "      \"created\": \"1970-01-01 00:00:00\",\n"
        "      \"modified\": \"1970-01-01 00:00:00\",\n"
        "      \"hidden\": false\n"
        "    }\n"
        "  ]\n"
        "}\n";

    EXPECT_EQ(JsonFormatter().formatEntries(entries), expected);
}