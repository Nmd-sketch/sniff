#include "../include/core.hpp"
#include <cstdint>
#include <cwctype>
#include <windows.h>

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

static std::string ToUtf8(std::wstring_view wide) {
  // If the w_string_view is empty we return an empty string
  if (wide.empty())
    return {};

  // Convert the wide string to UTF-8
  int len = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(),
                                static_cast<int>(wide.size()), nullptr, 0,
                                nullptr, nullptr);

  // If the conversion fails we return an empty string
  if (len <= 0)
    return {};

  // We create a string with length len and initialize it with null characters
  std::string narrow(len, '\0');

  // We convert the wide string to utf-8 and store the result in narrow
  WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(),
                      static_cast<int>(wide.size()), narrow.data(), len,
                      nullptr, nullptr);
  return narrow;
}

static std::wstring ToWide(std::string_view narrow) {
  // If the string_view is empty we return
  if (narrow.empty())
    return {};

  // We take the number of wide characters needed to represent the narrow string
  int len = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, narrow.data(),
                                static_cast<int>(narrow.size()), nullptr, 0);
  // If the conversion fails we return an empty string
  if (len <= 0)
    return {};

  // We create a string with length len and initialize it with null characters
  std::wstring wide(len, L'\0');

  // We convert the narrow string to wide and store the result in wide
  MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, narrow.data(),
                      static_cast<int>(narrow.size()), wide.data(), len);
  return wide;
}

static std::uintmax_t FileSize(const WIN32_FIND_DATAW &fd) {
  return (static_cast<std::uintmax_t>(fd.nFileSizeHigh) << 32) |
         static_cast<std::uintmax_t>(fd.nFileSizeLow);
}

static bool IsDotDir(const wchar_t *name) {
  return name[0] == L'.' &&
         (name[1] == L'\0' || (name[1] == L'.' && name[2] == L'\0'));
}

static bool IsHidden(const WIN32_FIND_DATAW &fd) {
  if (fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) {
    return true;
  }
  if (fd.cFileName[0] == L'.' && !IsDotDir(fd.cFileName)) {
    return true;
  }
  return false;
}

static bool MatchExtension(std::wstring_view filename, std::wstring_view ext) {
  if (ext.empty() || ext == L"_all_ext")
    return true;
  if (ext.front() == L'.')
    ext.remove_prefix(1);

  auto pos = filename.rfind(L'.');
  if (pos == std::wstring_view::npos)
    return false;

  std::wstring_view file_ext = filename.substr(pos + 1);
  if (file_ext.size() != ext.size())
    return false;

  for (size_t i = 0; i < file_ext.size(); ++i)
    if (std::towlower(file_ext[i]) != std::towlower(ext[i]))
      return false;
  return true;
}

// Count depth of an absolute, normalized path
static std::size_t PathDepth(std::wstring_view p) {
  // If p starts with a UNC path, remove the prefix
  if (p.starts_with(L"\\\\?\\UNC\\")) {
    p.remove_prefix(8);
    int shares = 0;
    std::size_t i = 0;

    // Now we count the number of shares (\\) in the path
    for (auto it = p.begin(); it != p.end() && shares < 2; ++it) {
      if (*it == L'\\')
        ++shares;
      ++i;
    }
    // Remove the i share segments
    p.remove_prefix(i);

    // If p starts with two share segments, remove them
  } else if (p.starts_with(L"\\\\?\\")) {
    p.remove_prefix(4);
  }

  // If p starts with a drive letter and a colon, remove them
  if (p.size() >= 2 && p[1] == L':') {
    p.remove_prefix(2);

    // If p starts with two shares, remove them
  } else if (p.starts_with(L"\\\\")) {
    p.remove_prefix(2);
    int shares = 0;
    std::size_t i = 0;
    for (auto it = p.begin(); it != p.end() && shares < 2; ++it) {
      if (*it == L'\\')
        ++shares;
      ++i;
    }
    p.remove_prefix(i);
  }

  // We remove any leading slash or backslash
  if (!p.empty() && (p.front() == L'\\' || p.front() == L'/'))
    p.remove_prefix(1);

  // We count the number of directory segments in p
  std::size_t d = 0;
  for (size_t i = 0; i < p.size(); ++i)
    if ((p[i] == L'\\' || p[i] == L'/') && i > 0 && p[i - 1] != L'\\' &&
        p[i - 1] != L'/')
      ++d;

  // Count the final directory segment if there is one
  if (!p.empty() && p.back() != L'\\' && p.back() != L'/')
    ++d;

  // We return the number of counted directories
  return d;
}

// ------------------------------------------------------------------
// Recursive scan
// ------------------------------------------------------------------

static void ScanRecursive(const std::wstring &current_path,
                          std::wstring_view user_ext, int max_depth,
                          std::size_t current_depth, bool ignore_hidden,
                          std::uintmax_t min_size, std::uintmax_t max_size,
                          std::vector<sniff::Entry> &out) {
  if (max_depth >= 0 && static_cast<int>(current_depth) > max_depth)
    return;

  std::wstring search = current_path;
  if (!search.empty() && search.back() != L'\\' && search.back() != L'/')
    search += L'\\';
  search += L'*';

  WIN32_FIND_DATAW fd;
  HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
  if (hFind == INVALID_HANDLE_VALUE) {
    DWORD err = GetLastError();
    if (err == ERROR_FILE_NOT_FOUND) {
      return;
    }
    if (err == ERROR_ACCESS_DENIED || err == ERROR_PATH_NOT_FOUND) {
      return;
    }

    throw std::runtime_error("FindFirstFileW Failed: " + std::to_string(err));
  }

  do {
    if (ignore_hidden && IsHidden(fd))
      continue;
    if (IsDotDir(fd.cFileName))
      continue;

    std::wstring full = current_path;
    if (!full.empty() && full.back() != L'\\' && full.back() != L'/')
      full += L'\\';
    full += fd.cFileName;

    bool is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

    std::string utf8_path = ToUtf8(full);

    if (is_dir) {
      // Recurse deeper
      ScanRecursive(full, user_ext, max_depth, current_depth + 1, ignore_hidden,
                    min_size, max_size, out);
    } else {
      // Only add files matching the extension

      if (MatchExtension(fd.cFileName, user_ext)) {
        std::uintmax_t fileSize = FileSize(fd);
        if (fileSize < min_size || fileSize > max_size) {
          continue;
        }
        out.push_back({utf8_path, fileSize, false});
      }
    }
  } while (FindNextFileW(hFind, &fd));

  FindClose(hFind);
}

// ------------------------------------------------------------------
// Public API
// ------------------------------------------------------------------

std::vector<sniff::Entry> sniff::raw_scan(std::string_view root_path,
                                          std::string_view user_extension,
                                          int max_depth, bool ignore_hidden,
                                          std::uintmax_t min_size,
                                          std::uintmax_t max_size) {
  std::vector<Entry> results;

  // 1. Convert encoding properly
  std::wstring wroot = ToWide(root_path);
  std::wstring wext = ToWide(user_extension);
  if (wroot.empty())
    return results;

  WIN32_FIND_DATAW fd;
  HANDLE hFind = FindFirstFileW(wroot.c_str(), &fd);
  if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
    return results;

  // 2. Normalize to absolute path
  WCHAR normalized[MAX_PATH];
  DWORD n = GetFullPathNameW(wroot.c_str(), MAX_PATH, normalized, nullptr);
  if (n == 0 || n >= MAX_PATH)
    return results;
  std::wstring abs_root(normalized);

  // 4. Scan (current_depth starts at root_depth)
  ScanRecursive(abs_root, wext, max_depth, 0, ignore_hidden, min_size, max_size,
                results);
  return results;
}
