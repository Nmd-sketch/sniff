#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include <windows.h>

#include "../../domain/model/EntryType.hpp"

namespace infrastructure {

/* Classify the entry type from directory attribute flags. */
domain::EntryType classifyType(DWORD attributes);

/* True when FILE_ATTRIBUTE_HIDDEN is set. */
bool isHidden(DWORD attributes);

/* Convert a FILETIME (100ns ticks since 1601-01-01) to the system clock. */
std::chrono::system_clock::time_point timePointFromFileTime(FILETIME fileTime);

/* Combine the 32-bit size fields from a WIN32_FIND_DATA record. */
std::uintmax_t sizeFromWin32(DWORD sizeHigh, DWORD sizeLow);

/* UTF-8 <-> UTF-16 conversion. */
std::wstring utf8ToWide(const std::string& text);
std::string wideToUtf8(const std::wstring& text);

/* Resolve the normalized canonical path of a directory handle, or empty on failure.
   Unlike a naive two-call GetFinalPathNameByHandleW, a failed second call (which can
   leave the buffer full of NULs) yields an empty result, and a trailing embedded NUL
   is trimmed. */
std::wstring canonicalPathOf(HANDLE handle);

/* Normalize a scan root: backslashes to '/', strip trailing '/', '.' -> "", strip a leading "./". */
std::string normalizeScanRoot(const std::string& root);

/* Join a relative prefix and a name with '/', no separator when the prefix is empty. */
std::string joinRelativePath(const std::string& relPrefix, const std::string& name);

/* Lowercased extension including the leading dot; empty when there is none. */
std::string fileExtension(const std::string& name);

/* Curated defaults plus PATHEXT environment entries (lowercased, with leading dot). */
std::vector<std::string> executableExtensions();

/* True when the lowercased extension (with dot) matches an entry in the set. */
bool hasExecutableExtension(const std::string& lowerExtension,
                            const std::vector<std::string>& extensions);

}  // namespace infrastructure