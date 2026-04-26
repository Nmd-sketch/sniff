#include "../../include/core.hpp"
#include <limits>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
namespace py = pybind11;

PYBIND11_MODULE(sniff, m) {
  m.doc() = "Sniff: A blazing fast, safe, and scriptable file finder";

  // We bind the C++ Entry struct to a python class
  py::class_<sniff::Entry>(m, "Entry")
      // Passing std::filesystem::path is potentially unsafe so we pass a string
      .def_property_readonly(
          "path", [](const sniff::Entry &e) { return e.path.string(); })
      .def_readonly("size_bytes", &sniff::Entry::size_bytes)
      .def_readonly("is_directory", &sniff::Entry::is_directory);

  // We bind the functions
  m.def(
      "find",
      [](const std::string &root_path_str, int max_depth,
         std::uintmax_t min_size, std::uintmax_t max_size, bool ignore_hidden) {
        return sniff::find(std::filesystem::path(root_path_str), max_depth,
                           min_size, max_size, ignore_hidden);
      },
      py::arg("root_path"), py::arg("max_depth") = -1,
      py::arg("min_size") = std::uintmax_t(0),
      py::arg("max_size") = std::numeric_limits<std::uintmax_t>::max(),
      py::arg("ignore_hidden") = true, "finds all files inside a directory");

  m.def(
      "glob_find",
      [](const std::string &root_path_str, std::string_view extension,
         int max_depth, std::uintmax_t min_size, std::uintmax_t max_size,
         bool ignore_hidden) {
        return sniff::glob_find(std::filesystem::path(root_path_str), extension,
                                max_depth, min_size, max_size, ignore_hidden);
      },
      py::arg("root_path"), py::arg("extension"), py::arg("max_depth") = -1,
      py::arg("min_size") = std::uintmax_t(0),
      py::arg("max_size") = std::numeric_limits<std::uintmax_t>::max(),
      py::arg("ignore_hidden") = true,
      "Finds files matching a specific extension");
}
