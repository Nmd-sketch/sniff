#include "TreeFormatter.hpp"

#include <algorithm>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct Node {
    std::string name;
    bool isDirectory = false;
    std::vector<Node> children;
};

std::vector<std::string> splitPath(const std::string& raw) {
    std::vector<std::string> parts;
    std::string current;
    for (const char ch : raw) {
        if (ch == '/' || ch == '\\') {
            if (!current.empty()) {
                parts.push_back(current);
                current.clear();
            }
        } else {
            current.push_back(ch);
        }
    }
    if (!current.empty()) {
        parts.push_back(current);
    }
    return parts;
}

Node* findOrAdd(std::vector<Node>& level, const std::string& name, bool isDirectory) {
    for (Node& node : level) {
        if (node.name == name) {
            if (isDirectory) node.isDirectory = true;
            return &node;
        }
    }
    level.push_back(Node{name, isDirectory, {}});
    return &level.back();
}

void insertPath(std::vector<Node>& roots, const std::vector<std::string>& components,
                domain::EntryType type) {
    if (components.empty()) return;

    std::vector<Node>* level = &roots;
    for (std::size_t i = 0; i < components.size(); ++i) {
        const bool isLast = (i + 1 == components.size());
        const bool isDirectory = !isLast || type == domain::EntryType::DIRECTORY;
        Node* node = findOrAdd(*level, components[i], isDirectory);
        if (isLast) break;
        level = &node->children;
    }
}

void sortNodes(std::vector<Node>& nodes) {
    std::sort(nodes.begin(), nodes.end(), [](const Node& first, const Node& second) {
        if (first.isDirectory != second.isDirectory) return first.isDirectory;
        return first.name < second.name;
    });
    for (Node& node : nodes) {
        if (node.isDirectory) sortNodes(node.children);
    }
}

void renderChild(std::ostream& out, const Node& node, const std::string& prefix, bool isLast) {
    out << prefix << (isLast ? "└── " : "├── ") << node.name;
    if (node.isDirectory) out << '/';
    out << '\n';

    const std::string childPrefix = prefix + (isLast ? "    " : "│   ");
    const std::size_t count = node.children.size();
    for (std::size_t i = 0; i < count; ++i) {
        renderChild(out, node.children[i], childPrefix, i + 1 == count);
    }
}

void renderRoot(std::ostream& out, const Node& root) {
    out << root.name;
    if (root.isDirectory) out << '/';
    out << '\n';

    const std::size_t count = root.children.size();
    for (std::size_t i = 0; i < count; ++i) {
        renderChild(out, root.children[i], "", i + 1 == count);
    }
}

}  // namespace

std::string TreeFormatter::formatEntries(
    const std::vector<std::unique_ptr<domain::IEntry>>& entries) const {
    std::vector<Node> roots;
    for (const auto& entry : entries) {
        insertPath(roots, splitPath(entry->getPath()), entry->getType());
    }
    sortNodes(roots);

    std::ostringstream out;
    for (const Node& root : roots) {
        renderRoot(out, root);
    }
    return out.str();
}