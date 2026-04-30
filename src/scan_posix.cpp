#include "../include/core.hpp"
#include <cctype>
#include <climits>
#include <cstdlib>
#include <dirent.h>
#include <queue>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

static bool IsDotDir(const char *name) {
  return name[0] == '.' &&
         (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

static bool IsHidden(const char *name) {
  return name[0] == '.' && !IsDotDir(name);
}

static bool MatchExtension(std::string_view filename, std::string_view ext) {
  if (ext.empty() || ext == "_all_ext")
    return true;
  if (ext.front() == '.')
    ext.remove_prefix(1);

  auto pos = filename.rfind('.');
  if (pos == std::string_view::npos)
    return false;

  std::string_view file_ext = filename.substr(pos + 1);
  if (file_ext.size() != ext.size())
    return false;

  for (size_t i = 0; i < file_ext.size(); ++i)
    if (std::tolower(static_cast<unsigned char>(file_ext[i])) !=
        std::tolower(static_cast<unsigned char>(ext[i])))
      return false;
  return true;
}

static std::string PathJoin(const std::string &a, const char *b) {
  if (a.empty())
    return std::string(b);
  if (a.back() == '/')
    return a + b;
  return a + "/" + b;
}

// Pure string normalization. No filesystem hits.
static std::string NormalizePath(std::string_view path) {
  std::string p(path);
  if (!p.empty() && p[0] == '/')
    return p;

  char cwd[PATH_MAX];
  if (!getcwd(cwd, sizeof(cwd)))
    return p;
  return std::string(cwd) + "/" + p;
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

  struct stat st;
  if (lstat(abs_root.c_str(), &st) != 0 || !S_ISDIR(st.st_mode))
    return results;

  std::queue<std::pair<std::string, int>> q;
  q.emplace(abs_root, 0);

  while (!q.empty()) {
    auto [dir_path, depth] = q.front();
    q.pop();

    DIR *d = opendir(dir_path.c_str());
    if (!d)
      continue;

    struct dirent *ent;
    while ((ent = readdir(d)) != nullptr) {
      if (IsDotDir(ent->d_name))
        continue;
      if (ignore_hidden && IsHidden(ent->d_name))
        continue;

      std::string full = PathJoin(dir_path, ent->d_name);

      // Portable: we MUST stat to know type and size.
      // lstat() does not follow symlinks, so we won't recurse into symlinked dirs.
      struct stat fst;
      if (lstat(full.c_str(), &fst) != 0)
        continue;

      if (S_ISDIR(fst.st_mode)) {
        if (max_depth < 0 || depth < max_depth) {
          q.emplace(full, depth + 1);
        }
        continue;
      }

      if (!S_ISREG(fst.st_mode))
        continue; // skip symlinks, pipes, devices, etc.

      // Cheap filter: extension check before size (string ops vs 64-bit compare)
      if (!MatchExtension(ent->d_name, user_extension))
        continue;

      std::uintmax_t file_size = static_cast<std::uintmax_t>(fst.st_size);
      if (file_size < min_size || file_size > max_size)
        continue;

      results.push_back({full, file_size, false});
    }
    closedir(d);
  }

  return results;
}
