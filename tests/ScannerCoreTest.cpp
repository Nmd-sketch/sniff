#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <windows.h>

#include "../src/infrastructure/scanner/Win32ScanCore.hpp"

namespace {

FILETIME fileTimeFromTicks(unsigned long long ticks) {
    FILETIME ft{};
    ft.dwLowDateTime = static_cast<DWORD>(ticks & 0xFFFFFFFFULL);
    ft.dwHighDateTime = static_cast<DWORD>(ticks >> 32);
    return ft;
}

}  // namespace

TEST(ScanCore, ClassifiesPlainFiles) {
    EXPECT_EQ(infrastructure::classifyType(0), domain::EntryType::FILE);
    EXPECT_EQ(infrastructure::classifyType(FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN),
              domain::EntryType::FILE);
}

TEST(ScanCore, ClassifiesDirectories) {
    EXPECT_EQ(infrastructure::classifyType(FILE_ATTRIBUTE_DIRECTORY),
              domain::EntryType::DIRECTORY);
}

TEST(ScanCore, ClassifiesReparsePointsAsSymlinks) {
    EXPECT_EQ(infrastructure::classifyType(FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY),
              domain::EntryType::SYMLINK);
}

TEST(ScanCore, HiddenFlag) {
    EXPECT_FALSE(infrastructure::isHidden(0));
    EXPECT_TRUE(infrastructure::isHidden(FILE_ATTRIBUTE_HIDDEN));
    EXPECT_TRUE(infrastructure::isHidden(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_DIRECTORY));
}

TEST(ScanCore, FileTimeAtUnixEpoch) {
    const auto expected = std::chrono::system_clock::from_time_t(0);
    EXPECT_EQ(infrastructure::timePointFromFileTime(fileTimeFromTicks(116444736000000000ULL)),
              expected);
}

TEST(ScanCore, FileTimePlusOneSecond) {
    const auto epoch = std::chrono::system_clock::from_time_t(0);
    const auto oneSecondLater = epoch + std::chrono::seconds(1);
    const auto epochTicks = 116444736000000000ULL;
    EXPECT_EQ(
        infrastructure::timePointFromFileTime(fileTimeFromTicks(epochTicks + 10000000ULL)),
        oneSecondLater);
}

TEST(ScanCore, CombinesSizeFields) {
    EXPECT_EQ(infrastructure::sizeFromWin32(0, 0), 0u);
    EXPECT_EQ(infrastructure::sizeFromWin32(0, 42), 42u);
    EXPECT_EQ(infrastructure::sizeFromWin32(1, 0), 4294967296u);
    EXPECT_EQ(infrastructure::sizeFromWin32(1, 1), 4294967297u);
}

TEST(ScanCore, Utf8ToWide) {
    EXPECT_EQ(infrastructure::utf8ToWide("plain"), L"plain");
    EXPECT_EQ(infrastructure::utf8ToWide(std::string("\xc3\xa9")), L"\u00e9");
    EXPECT_EQ(infrastructure::utf8ToWide(""), L"");
}

TEST(ScanCore, WideToUtf8) {
    EXPECT_EQ(infrastructure::wideToUtf8(L"plain"), "plain");
    EXPECT_EQ(infrastructure::wideToUtf8(L"\u00e9"), std::string("\xc3\xa9"));
    EXPECT_EQ(infrastructure::wideToUtf8(L""), "");
}

TEST(ScanCore, Utf8RoundTrip) {
    const std::string mixed("sniff\xc3\xa9\xf0\x9f\x94\x8d.cpp");
    EXPECT_EQ(infrastructure::wideToUtf8(infrastructure::utf8ToWide(mixed)), mixed);
}

TEST(ScanCore, CanonicalPathOfInvalidHandleIsEmpty) {
    EXPECT_TRUE(infrastructure::canonicalPathOf(INVALID_HANDLE_VALUE).empty());
}

TEST(ScanCore, CanonicalPathOfResolvesDirectory) {
    wchar_t tmp[MAX_PATH]{};
    const DWORD len = GetTempPathW(MAX_PATH, tmp) + 1;
    tmp[len - 1] = L'm' + (GetCurrentProcessId() % 26);

    const std::wstring dir = std::wstring(tmp, len);
    CreateDirectoryW(dir.c_str(), nullptr);
    const HANDLE h = CreateFileW(dir.c_str(), FILE_READ_ATTRIBUTES,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                 OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    ASSERT_NE(h, INVALID_HANDLE_VALUE);
    const std::wstring canonical = infrastructure::canonicalPathOf(h);
    CloseHandle(h);
    RemoveDirectoryW(dir.c_str());

    ASSERT_FALSE(canonical.empty());
    EXPECT_NE(canonical.back(), L'\0');
}

TEST(ScanCore, CanonicalPathOfIsDeterministic) {
    wchar_t tmp[MAX_PATH]{};
    const DWORD len = GetTempPathW(MAX_PATH, tmp) + 1;
    tmp[len - 1] = L'n' + (GetCurrentProcessId() % 26);

    const std::wstring dir = std::wstring(tmp, len);
    CreateDirectoryW(dir.c_str(), nullptr);
    const HANDLE h1 = CreateFileW(dir.c_str(), FILE_READ_ATTRIBUTES,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                  OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    const HANDLE h2 = CreateFileW(dir.c_str(), FILE_READ_ATTRIBUTES,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                  OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    ASSERT_NE(h1, INVALID_HANDLE_VALUE);
    ASSERT_NE(h2, INVALID_HANDLE_VALUE);

    const std::wstring c1 = infrastructure::canonicalPathOf(h1);
    const std::wstring c2 = infrastructure::canonicalPathOf(h2);
    CloseHandle(h1);
    CloseHandle(h2);
    RemoveDirectoryW(dir.c_str());

    ASSERT_FALSE(c1.empty());
    EXPECT_EQ(c1, c2);
}

TEST(ScanCore, LongPathPrefixesShortDrivePath) {
    EXPECT_EQ(infrastructure::longPathOf(L"C:\\foo\\bar"), L"\\\\?\\C:\\foo\\bar");
    EXPECT_EQ(infrastructure::longPathOf(L"C:/foo/bar"), L"\\\\?\\C:\\foo\\bar");
}

TEST(ScanCore, LongPathEmptyIsEmpty) {
    EXPECT_EQ(infrastructure::longPathOf(L""), L"");
}

TEST(ScanCore, LongPathPrefixesAbsoluteDrivePath) {
    const std::wstring longPath(L"C:\\" + std::wstring(300, L'a'));
    const std::wstring prefixed = infrastructure::longPathOf(longPath);
    EXPECT_EQ(prefixed, L"\\\\?\\" + longPath);
}

TEST(ScanCore, LongPathDoesNotDoublePrefix) {
    const std::wstring longPath(L"C:\\" + std::wstring(300, L'a'));
    const std::wstring once = infrastructure::longPathOf(longPath);
    EXPECT_EQ(infrastructure::longPathOf(once), once);
}

TEST(ScanCore, LongPathResolvesRelativeToAbsoluteAndPrefixes) {
    const std::wstring relative(L"rel\\" + std::wstring(300, L'b'));
    const std::wstring prefixed = infrastructure::longPathOf(relative);
    EXPECT_EQ(prefixed.rfind(L"\\\\?\\", 0), 0u);
    EXPECT_NE(prefixed.find(L"rel\\" + std::wstring(300, L'b')), std::wstring::npos);
    EXPECT_TRUE(prefixed.size() > relative.size());
}

TEST(ScanCore, LongPathUsesUncPrefixForUncPath) {
    const std::wstring unc(L"\\\\server\\share\\" + std::wstring(300, L'c'));
    const std::wstring prefixed = infrastructure::longPathOf(unc);
    EXPECT_EQ(prefixed, L"\\\\?\\UNC\\server\\share\\" + std::wstring(300, L'c'));
}

TEST(ScanCore, NormalizeScanRoot) {
    EXPECT_EQ(infrastructure::normalizeScanRoot("src"), "src");
    EXPECT_EQ(infrastructure::normalizeScanRoot("src\\"), "src");
    EXPECT_EQ(infrastructure::normalizeScanRoot("."), "");
    EXPECT_EQ(infrastructure::normalizeScanRoot(".\\"), "");
    EXPECT_EQ(infrastructure::normalizeScanRoot("./src"), "src");
    EXPECT_EQ(infrastructure::normalizeScanRoot(".\\src"), "src");
    EXPECT_EQ(infrastructure::normalizeScanRoot("C:\\foo"), "C:/foo");
    EXPECT_EQ(infrastructure::normalizeScanRoot("C:/foo/"), "C:/foo");
}

TEST(ScanCore, JoinRelativePath) {
    EXPECT_EQ(infrastructure::joinRelativePath("", "x"), "x");
    EXPECT_EQ(infrastructure::joinRelativePath("src", "x"), "src/x");
    EXPECT_EQ(infrastructure::joinRelativePath("src", "sub/x"), "src/sub/x");
}

TEST(ScanCore, FileExtension) {
    EXPECT_EQ(infrastructure::fileExtension("main.cpp"), ".cpp");
    EXPECT_EQ(infrastructure::fileExtension("main.CPP"), ".cpp");
    EXPECT_EQ(infrastructure::fileExtension("archive.tar.gz"), ".gz");
    EXPECT_EQ(infrastructure::fileExtension("Makefile"), "");
    EXPECT_EQ(infrastructure::fileExtension(".gitignore"), "");
    EXPECT_EQ(infrastructure::fileExtension("noext"), "");
}

TEST(ScanCore, ExecutableExtensionDetection) {
    EXPECT_TRUE(infrastructure::hasExecutableExtension(".exe", {".exe", ".txt"}));
    EXPECT_FALSE(infrastructure::hasExecutableExtension(".exe", {".txt"}));
    EXPECT_FALSE(infrastructure::hasExecutableExtension("", {".exe"}));
    EXPECT_FALSE(infrastructure::hasExecutableExtension(".txt", {}));
}

TEST(ScanCore, CuratedExtensionsAlwaysPresent) {
    const auto extensions = infrastructure::executableExtensions();
    EXPECT_TRUE(infrastructure::hasExecutableExtension(".exe", extensions));
    EXPECT_TRUE(infrastructure::hasExecutableExtension(".bat", extensions));
    EXPECT_TRUE(infrastructure::hasExecutableExtension(".ps1", extensions));
}