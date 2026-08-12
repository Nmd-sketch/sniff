#include "Win32Scanner.hpp"

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <windows.h>

#include "../../domain/model/DomainEntry.hpp"
#include "Win32ScanCore.hpp"

namespace infrastructure {

namespace {

std::unique_ptr<domain::IEntry> makeEntry(const WIN32_FIND_DATAW& data,
                                          std::string name,
                                          std::string fullPath,
                                          const std::vector<std::string>& extensions) {
    return std::make_unique<domain::DomainEntry>(
        classifyType(data.dwFileAttributes), isHidden(data.dwFileAttributes),
        classifyType(data.dwFileAttributes) != domain::EntryType::DIRECTORY &&
            hasExecutableExtension(fileExtension(name), extensions),
        std::move(name), std::move(fullPath), sizeFromWin32(data.nFileSizeHigh, data.nFileSizeLow),
        timePointFromFileTime(data.ftCreationTime), timePointFromFileTime(data.ftLastWriteTime));
}

}  // namespace

void Win32Scanner::scan(const std::vector<std::string>& paths,
                        const FilterSpec& spec,
                        const Sink& sink,
                        domain::CancellationToken& token) const {
    std::vector<std::wstring> visited;
    const bool followSymlinks = spec.follow_symlinks.value_or(false);
    const bool hasMaxDepth = spec.max_depth.has_value();
    const int maxDepth = spec.max_depth.value_or(-1);
    const std::vector<std::string> extensions = executableExtensions();

    const auto descend = [&](const WIN32_FIND_DATAW& data, int entryDepth) {
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) return false;
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 && !followSymlinks) {
            return false;
        }
        if (hasMaxDepth && entryDepth + 1 > maxDepth) return false;
        return true;
    };

    const auto cycleCheck = [&](const std::wstring& wideDir, bool isSymlinkDir) {
        if (!isSymlinkDir) return true;
        HANDLE h = CreateFileW(wideDir.c_str(), FILE_READ_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                               OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (h == INVALID_HANDLE_VALUE) return true;
        DWORD len = GetFinalPathNameByHandleW(h, nullptr, 0, FILE_NAME_NORMALIZED);
        std::wstring canonical;
        if (len > 0) {
            canonical.resize(len);
            GetFinalPathNameByHandleW(h, &canonical[0], len, FILE_NAME_NORMALIZED);
        }
        CloseHandle(h);
        if (canonical.empty()) return true;
        for (const auto& existing : visited) {
            if (existing == canonical) return false;
        }
        visited.push_back(std::move(canonical));
        return true;
    };

    std::function<bool(const std::wstring&, const std::string&, int, bool)> walk;
    walk = [&](const std::wstring& wideDir, const std::string& relPrefix, int depth,
               bool isSymlinkDir) {
        if (token.isStopped()) return false;
        if (!cycleCheck(wideDir, isSymlinkDir)) return true;

        std::wstring pattern = wideDir;
        if (pattern.empty() || pattern.back() != L'\\') pattern.push_back(L'\\');
        pattern.append(L"*");

        WIN32_FIND_DATAW data{};
        HANDLE hFind = FindFirstFileW(pattern.c_str(), &data);
        if (hFind == INVALID_HANDLE_VALUE) return true;

        do {
            if (token.isStopped()) {
                FindClose(hFind);
                return false;
            }
            const std::wstring wideName(data.cFileName);
            if (wideName == L"." || wideName == L"..") continue;

            const std::string name = wideToUtf8(wideName);
            const std::string fullPath = joinRelativePath(relPrefix, name);
            if (!sink(makeEntry(data, name, fullPath, extensions), depth)) {
                FindClose(hFind);
                return false;
            }
            if (descend(data, depth)) {
                std::wstring childDir = wideDir;
                if (childDir.empty() || childDir.back() != L'\\') childDir.push_back(L'\\');
                childDir.append(wideName);
                const bool childIsSymlink =
                    (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                if (!walk(childDir, fullPath, depth + 1, childIsSymlink)) {
                    FindClose(hFind);
                    return false;
                }
            }
        } while (FindNextFileW(hFind, &data));
        FindClose(hFind);
        return true;
    };

    for (const auto& path : paths) {
        if (token.isStopped()) return;

        const std::wstring widePath = utf8ToWide(path);
        const DWORD rootAttrs = GetFileAttributesW(widePath.c_str());
        if (rootAttrs == INVALID_FILE_ATTRIBUTES) {
            throw std::runtime_error(path + ": No such file or directory");
        }

        if ((rootAttrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            WIN32_FIND_DATAW data{};
            HANDLE hFind = FindFirstFileW(widePath.c_str(), &data);
            if (hFind == INVALID_HANDLE_VALUE) {
                throw std::runtime_error(path + ": No such file or directory");
            }
            FindClose(hFind);
            if (!sink(makeEntry(data, wideToUtf8(data.cFileName), normalizeScanRoot(path),
                                extensions),
                      0)) {
                return;
            }
            continue;
        }

        if (!walk(widePath, normalizeScanRoot(path), 0,
                  (rootAttrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0)) {
            return;
        }
    }
}

}  // namespace infrastructure