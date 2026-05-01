#include "../include/core.hpp"
#include <cctype>
#include <climits>
#include <cstdlib>
#include <dirent.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <fcntl.h>
#include <cstring>

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

static bool IsDotDir(const char *name) {
  return name[0] == '.' &&
         (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

static std::string NormalizePath(std::string_view path) {
  if (path.empty())
    return "/";
  if (path[0] == '/')
    return std::string(path);
  char cwd[PATH_MAX];
  if (!getcwd(cwd, sizeof(cwd)))
    return std::string(path);
  return std::string(cwd) + '/' + std::string(path);
}

// ------------------------------------------------------------------
// Recursive scanner - path modified in-place, restored on return
// ------------------------------------------------------------------

static void scan_recursive(
    std::string &path,
    int depth,
    const std::string &ext_lower,
    bool match_all_ext,
    int max_depth,
    bool ignore_hidden,
    std::uintmax_t min_size,
    std::uintmax_t max_size,
    std::vector<sniff::Entry> &results) {

  DIR *const d = opendir(path.c_str());
  if (!d)
    return;

  const int dir_fd = dirfd(d);
  const bool needs_slash = path.back() != '/';

  struct dirent *ent;
  while ((ent = readdir(d)) != nullptr) {
    const char *name = ent->d_name;

    if (IsDotDir(name))
      continue;
    if (ignore_hidden && name[0] == '.')
      continue;

    const unsigned char d_type = ent->d_type;

    // --- Directory: recurse immediately, modify path in-place ---
    if (d_type == DT_DIR) {
      if (max_depth >= 0 && depth >= max_depth)
        continue;
      const size_t saved = path.size();
      if (needs_slash)
        path += '/';
      path += name;
      scan_recursive(path, depth + 1, ext_lower, match_all_ext,
                     max_depth, ignore_hidden, min_size, max_size, results);
      path.resize(saved);
      continue;
    }

    // --- Skip non-regular without stat ---
    if (d_type != DT_REG && d_type != DT_UNKNOWN)
      continue;

    // --- Stat via dirfd (no path construction needed) ---
    struct stat fst;
    if (fstatat(dir_fd, name, &fst, AT_SYMLINK_NOFOLLOW) != 0)
      continue;

    // --- Handle DT_UNKNOWN (NFS, etc.) ---
    if (d_type == DT_UNKNOWN) {
      if (S_ISDIR(fst.st_mode)) {
        if (max_depth >= 0 && depth >= max_depth)
          continue;
        const size_t saved = path.size();
        if (needs_slash)
          path += '/';
        path += name;
        scan_recursive(path, depth + 1, ext_lower, match_all_ext,
                       max_depth, ignore_hidden, min_size, max_size, results);
        path.resize(saved);
        continue;
      }
      if (!S_ISREG(fst.st_mode))
        continue;
    }

    // --- Extension filter ---
    if (!match_all_ext) {
      const char *dot = strrchr(name, '.');
      if (!dot)
        continue;
      const char *fext = dot + 1;
      const size_t elen = ext_lower.size();
      size_t i = 0;
      for (; i < elen && fext[i]; ++i) {
        if (std::tolower(static_cast<unsigned char>(fext[i])) !=
            static_cast<unsigned char>(ext_lower[i]))
          break;
      }
      if (i != elen || fext[i] != '\0')
        continue;
    }

    // --- Size filter ---
    const std::uintmax_t sz = static_cast<std::uintmax_t>(fst.st_size);
    if (sz < min_size || sz > max_size)
      continue;

    // --- Only now build the full path (file passed ALL filters) ---
    std::string full = path;
    if (needs_slash)
      full += '/';
    full += name;
    results.push_back({std::move(full), sz, false});
  }

  closedir(d);
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
  std::string abs_root = NormalizePath(root_path);

  struct stat root_st;
  if (lstat(abs_root.c_str(), &root_st) != 0 || !S_ISDIR(root_st.st_mode))
    return results;

  results.reserve(4096);

  // Pre-compute lowered extension once
  std::string ext_lower;
  bool match_all_ext = user_extension.empty() || user_extension == "_all_ext";
  if (!match_all_ext) {
    for (char c : user_extension) {
      if (c == '.' && ext_lower.empty())
        continue;
      ext_lower.push_back(std::tolower(static_cast<unsigned char>(c)));
    }
    if (ext_lower.empty())
      match_all_ext = true;
  }

  scan_recursive(abs_root, 0, ext_lower, match_all_ext,
                 max_depth, ignore_hidden, min_size, max_size, results);

  return results;
}
