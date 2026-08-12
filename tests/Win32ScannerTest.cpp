#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#include <windows.h>

#include "../src/domain/model/CancellationToken.hpp"
#include "../src/domain/model/FilterSpec.hpp"
#include "../src/infrastructure/scanner/Win32Scanner.hpp"

namespace {

std::string withForwardSlashes(std::string path) {
    for (char& c : path) {
        if (c == '\\') c = '/';
    }
    return path;
}

class TempDir {
public:
    TempDir() {
        const auto base = std::filesystem::temp_directory_path();
        for (int attempt = 0; attempt < 10; ++attempt) {
            const auto candidate =
                base / ("sniff_scan_" + std::to_string(GetCurrentProcessId()) + "_" +
                        std::to_string(m_counter++));
            if (std::filesystem::create_directory(candidate)) {
                m_root = candidate;
                return;
            }
        }
        throw std::runtime_error("unable to create a temporary directory");
    }

    ~TempDir() {
        if (!m_root.empty()) {
            std::error_code error;
            std::filesystem::remove_all(m_root, error);
        }
    }

    std::string root() const { return withForwardSlashes(m_root.string()); }
    std::string file(const std::string& relative) const {
        return withForwardSlashes((m_root / relative).string());
    }

    void makeFile(const std::string& relative, const std::string& content) const {
        std::ofstream out(m_root / relative, std::ios::binary);
        out << content;
    }

    void makeDir(const std::string& relative) const {
        std::filesystem::create_directories(m_root / relative);
    }

    void setHidden(const std::string& relative) const {
        const std::wstring wide = (m_root / relative).c_str();
        const DWORD attrs = GetFileAttributesW(wide.c_str());
        SetFileAttributesW(wide.c_str(), attrs | FILE_ATTRIBUTE_HIDDEN);
    }

    std::wstring wide(const std::string& relative) const {
        return (m_root / relative).c_str();
    }

private:
    std::filesystem::path m_root;
    static int m_counter;
};

int TempDir::m_counter = 0;

std::vector<std::tuple<std::string, int>> collect(const domain::IEntryRepository& scanner,
                                                  const std::vector<std::string>& paths,
                                                  const FilterSpec& spec = {},
                                                  domain::CancellationToken* token = nullptr) {
    std::vector<std::tuple<std::string, int>> result;
    domain::CancellationToken local;
    domain::CancellationToken& cancel = token != nullptr ? *token : local;
    scanner.scan(paths, spec,
                 [&](std::unique_ptr<domain::IEntry> entry, int depth) {
                     result.emplace_back(entry->getPath(), depth);
                     return true;
                 },
                 cancel);
    return result;
}

bool hasPath(const std::vector<std::tuple<std::string, int>>& entries, const std::string& path) {
    for (const auto& entry : entries) {
        if (std::get<0>(entry) == path) return true;
    }
    return false;
}

int depthOf(const std::vector<std::tuple<std::string, int>>& entries,
            const std::string& path) {
    for (const auto& entry : entries) {
        if (std::get<0>(entry) == path) return std::get<1>(entry);
    }
    return -1;
}

}  // namespace

TEST(Win32Scanner, WalksTreeWithDepths) {
    TempDir dir;
    dir.makeDir("sub");
    dir.makeFile("a.txt", "a");
    dir.makeFile("sub/b.txt", "b");

    infrastructure::Win32Scanner scanner;
    const auto entries = collect(scanner, {dir.root()});

    ASSERT_EQ(entries.size(), 3u);
    EXPECT_EQ(depthOf(entries, dir.root() + "/a.txt"), 0);
    EXPECT_EQ(depthOf(entries, dir.root() + "/sub"), 0);
    EXPECT_EQ(depthOf(entries, dir.root() + "/sub/b.txt"), 1);
}

TEST(Win32Scanner, SingleFileRootIsEmitted) {
    TempDir dir;
    dir.makeFile("single.txt", "x");

    infrastructure::Win32Scanner scanner;
    const auto entries = collect(scanner, {dir.file("single.txt")});

    EXPECT_EQ(entries.size(), 1u);
    EXPECT_EQ(std::get<0>(entries[0]), dir.file("single.txt"));
    EXPECT_EQ(std::get<1>(entries[0]), 0);
}

TEST(Win32Scanner, MissingRootThrows) {
    TempDir dir;
    infrastructure::Win32Scanner scanner;
    domain::CancellationToken token;
    FilterSpec spec;
    EXPECT_THROW(
        scanner.scan({dir.file("does_not_exist")}, spec,
                     [&](std::unique_ptr<domain::IEntry>, int) { return true; }, token),
        std::runtime_error);
}

TEST(Win32Scanner, HiddenFlagIsReported) {
    TempDir dir;
    dir.makeFile("secret.dat", "s");
    dir.makeFile("plain.dat", "p");
    dir.setHidden("secret.dat");

    infrastructure::Win32Scanner scanner;
    domain::CancellationToken token;
    FilterSpec spec;
    bool sawSecret = false;
    bool sawPlain = false;
    bool sawOther = false;
    scanner.scan({dir.root()}, spec,
                 [&](std::unique_ptr<domain::IEntry> entry, int) {
                     if (entry->getName() == "secret.dat") {
                         sawSecret = entry->isHidden();
                     } else if (entry->getName() == "plain.dat") {
                         sawPlain = entry->isHidden();
                     } else {
                         sawOther = true;
                     }
                     return true;
                 },
                 token);

    EXPECT_TRUE(sawSecret);
    EXPECT_FALSE(sawPlain);
    EXPECT_FALSE(sawOther);
}

TEST(Win32Scanner, SizeAndDatesArePopulated) {
    TempDir dir;
    dir.makeFile("data.bin", std::string(7, 'x'));

    infrastructure::Win32Scanner scanner;
    domain::CancellationToken token;
    FilterSpec spec;
    bool found = false;
    std::uintmax_t size = 0;
    auto created = std::chrono::system_clock::time_point{};
    auto modified = std::chrono::system_clock::time_point{};
    scanner.scan({dir.root()}, spec,
                 [&](std::unique_ptr<domain::IEntry> entry, int) {
                     if (entry->getName() == "data.bin") {
                         found = true;
                         size = entry->getSizeBytes();
                         created = entry->getCreatedAt();
                         modified = entry->getModifiedAt();
                     }
                     return true;
                 },
                 token);

    ASSERT_TRUE(found);
    EXPECT_EQ(size, 7u);
    EXPECT_LE(created, modified);
}

TEST(Win32Scanner, ExecutableExtensionIsDetected) {
    TempDir dir;
    dir.makeFile("tool.exe", "x");
    dir.makeFile("notes.txt", "x");

    infrastructure::Win32Scanner scanner;
    domain::CancellationToken token;
    FilterSpec spec;
    bool sawExe = false;
    bool sawTxt = false;
    bool sawOther = false;
    scanner.scan({dir.root()}, spec,
                 [&](std::unique_ptr<domain::IEntry> entry, int) {
                     if (entry->getName() == "tool.exe") {
                         sawExe = entry->isExecutable();
                     } else if (entry->getName() == "notes.txt") {
                         sawTxt = entry->isExecutable();
                     } else {
                         sawOther = true;
                     }
                     return true;
                 },
                 token);

    EXPECT_TRUE(sawExe);
    EXPECT_FALSE(sawTxt);
    EXPECT_FALSE(sawOther);
}

TEST(Win32Scanner, MaxDepthPrunesTraversal) {
    TempDir dir;
    dir.makeDir("sub/inner");
    dir.makeFile("top.txt", "t");
    dir.makeFile("sub/mid.txt", "m");
    dir.makeFile("sub/inner/deep.txt", "d");

    infrastructure::Win32Scanner scanner;
    FilterSpec maxZero;
    maxZero.max_depth = 0;
    const auto shallow = collect(scanner, {dir.root()}, maxZero);

    EXPECT_TRUE(hasPath(shallow, dir.root() + "/top.txt"));
    EXPECT_TRUE(hasPath(shallow, dir.root() + "/sub"));
    EXPECT_FALSE(hasPath(shallow, dir.root() + "/sub/mid.txt"));
    EXPECT_FALSE(hasPath(shallow, dir.root() + "/sub/inner"));

    FilterSpec maxOne;
    maxOne.max_depth = 1;
    const auto oneLevel = collect(scanner, {dir.root()}, maxOne);

    EXPECT_TRUE(hasPath(oneLevel, dir.root() + "/sub/mid.txt"));
    EXPECT_FALSE(hasPath(oneLevel, dir.root() + "/sub/inner/deep.txt"));
}

TEST(Win32Scanner, CancellationStopsTraversal) {
    TempDir dir;
    for (int i = 0; i < 10; ++i) {
        dir.makeFile("file" + std::to_string(i) + ".txt", "x");
    }

    infrastructure::Win32Scanner scanner;
    domain::CancellationToken token;
    FilterSpec spec;
    std::vector<std::string> paths;
    scanner.scan({dir.root()}, spec,
                 [&](std::unique_ptr<domain::IEntry> entry, int) {
                     paths.push_back(entry->getName());
                     token.requestStop();
                     return true;
                 },
                 token);

    EXPECT_EQ(paths.size(), 1u);
}

TEST(Win32Scanner, CancelledBeforeScanEmitsNothing) {
    TempDir dir;
    dir.makeFile("a.txt", "a");

    infrastructure::Win32Scanner scanner;
    domain::CancellationToken token;
    token.requestStop();
    const auto entries = collect(scanner, {dir.root()}, {}, &token);

    EXPECT_TRUE(entries.empty());
}

TEST(Win32Scanner, SymlinksNotFollowedByDefault) {
    TempDir dir;
    dir.makeDir("target");
    dir.makeFile("target/inner.txt", "i");

    if (!CreateSymbolicLinkW(dir.wide("link").c_str(), dir.wide("target").c_str(),
                             SYMBOLIC_LINK_FLAG_DIRECTORY | 0x2)) {
        GTEST_SKIP() << "symbolic link creation is not permitted in this environment";
    }

    infrastructure::Win32Scanner scanner;
    const auto entries = collect(scanner, {dir.root()});

    EXPECT_TRUE(hasPath(entries, dir.root() + "/link"));
    EXPECT_TRUE(hasPath(entries, dir.root() + "/target/inner.txt"));
    EXPECT_FALSE(hasPath(entries, dir.root() + "/link/inner.txt"));
}

TEST(Win32Scanner, SymlinksFollowedWhenEnabled) {
    TempDir dir;
    dir.makeDir("target");
    dir.makeFile("target/inner.txt", "i");

    if (!CreateSymbolicLinkW(dir.wide("link").c_str(), dir.wide("target").c_str(),
                             SYMBOLIC_LINK_FLAG_DIRECTORY | 0x2)) {
        GTEST_SKIP() << "symbolic link creation is not permitted in this environment";
    }

    infrastructure::Win32Scanner scanner;
    FilterSpec spec;
    spec.follow_symlinks = true;
    const auto entries = collect(scanner, {dir.root()}, spec);

    EXPECT_TRUE(hasPath(entries, dir.root() + "/link"));
    EXPECT_TRUE(hasPath(entries, dir.root() + "/link/inner.txt"));
    EXPECT_TRUE(hasPath(entries, dir.root() + "/target/inner.txt"));
}

TEST(Win32Scanner, MultipleRootsAreScanned) {
    TempDir first;
    TempDir second;
    first.makeFile("one.txt", "1");
    second.makeFile("two.txt", "2");

    infrastructure::Win32Scanner scanner;
    const auto entries = collect(scanner, {first.root(), second.root()});

    EXPECT_EQ(entries.size(), 2u);
    EXPECT_TRUE(hasPath(entries, first.root() + "/one.txt"));
    EXPECT_TRUE(hasPath(entries, second.root() + "/two.txt"));
}