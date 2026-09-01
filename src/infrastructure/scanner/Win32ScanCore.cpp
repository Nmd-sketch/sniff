#include "Win32ScanCore.hpp"

#include <cctype>
#include <cstdlib>

namespace infrastructure {

domain::EntryType classifyType(DWORD attributes) {
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) return domain::EntryType::SYMLINK;
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) return domain::EntryType::DIRECTORY;
    return domain::EntryType::FILE;
}

bool isHidden(DWORD attributes) {
    return (attributes & FILE_ATTRIBUTE_HIDDEN) != 0;
}

std::chrono::system_clock::time_point timePointFromFileTime(FILETIME fileTime) {
    const long long ticks =
        (static_cast<long long>(fileTime.dwHighDateTime) << 32) | fileTime.dwLowDateTime;
    constexpr long long kEpochDiffTicks = 116444736000000000LL;
    const auto seconds =
        std::chrono::seconds((ticks - kEpochDiffTicks) / 10000000LL);
    return std::chrono::system_clock::time_point(seconds);
}

std::uintmax_t sizeFromWin32(DWORD sizeHigh, DWORD sizeLow) {
    return (static_cast<std::uintmax_t>(sizeHigh) << 32) | sizeLow;
}

std::wstring utf8ToWide(const std::string& text) {
    if (text.empty()) return {};
    const int needed =
        MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring result(static_cast<std::size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        result.data(), needed);
    return result;
}

std::string wideToUtf8(const std::wstring& text) {
    if (text.empty()) return {};
    const int needed =
        WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                            nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string result(static_cast<std::size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        result.data(), needed, nullptr, nullptr);
    return result;
}

/* Converts \\ to / in the path (normalization) */
std::string normalizeScanRoot(const std::string& root) {
    std::string normalized;
    normalized.reserve(root.size());
    for (const char c : root) {
        normalized.push_back(c == '\\' ? '/' : c);
    }
    while (normalized.size() > 1 && normalized.back() == '/') {
        normalized.pop_back();
    }
    if (normalized == ".") return "";
    if (normalized.rfind("./", 0) == 0 && normalized.size() > 2) {
        normalized.erase(0, 2);
    }
    return normalized;
}

std::string joinRelativePath(const std::string& relPrefix, const std::string& name) {
    if (relPrefix.empty()) return name;
    std::string result;
    result.reserve(relPrefix.size() + 1 + name.size());
    result += relPrefix;
    result.push_back('/');
    result += name;
    return result;
}

std::string fileExtension(const std::string& name) {
    const auto dot = name.find_last_of('.');
    if (dot == std::string::npos || dot == 0 || dot == name.size() - 1) return "";
    std::string ext = name.substr(dot);
    for (char& c : ext) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return ext;
}

std::vector<std::string> executableExtensions() {
	// Predefined list of executables
    std::vector<std::string> result = {".exe", ".com", ".bat", ".cmd", ".ps1", ".msi", ".scr"};
    char* pathext = nullptr;
    if (_dupenv_s(&pathext, nullptr, "PATHEXT") == 0 && pathext != nullptr) {
        const std::string value(pathext);
        free(pathext);
        std::size_t start = 0;
        while (start <= value.size()) {
            const std::size_t end = value.find(';', start);
            std::string part =
                value.substr(start, end == std::string::npos ? std::string::npos : end - start);
            for (char& c : part) {
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            if (!part.empty() && part[0] != '.') {
                part.insert(part.begin(), '.');
            }
            if (!part.empty()) {
                result.push_back(part);
            }
            if (end == std::string::npos) break;
            start = end + 1;
        }
    }
    return result;
}

/* Extracts the path out of a handle */
std::wstring canonicalPathOf(HANDLE handle) {
    if (handle == INVALID_HANDLE_VALUE) return {};
    DWORD len = GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED);
    if (len == 0) return {};
    std::wstring buffer(static_cast<std::size_t>(len), L'\0');
    DWORD written = GetFinalPathNameByHandleW(handle, buffer.data(), len, FILE_NAME_NORMALIZED);
    if (written == 0 || written >= len) return {};
    buffer.resize(static_cast<std::size_t>(written));
    return buffer;
}

/* Checks if the extension of a file is on our list of extensions */
bool hasExecutableExtension(const std::string& lowerExtension,
                            const std::vector<std::string>& extensions) {
    if (lowerExtension.empty()) return false;
    for (const auto& ext : extensions) {
        if (ext == lowerExtension) return true;
    }
    return false;
}

}  // namespace infrastructure
