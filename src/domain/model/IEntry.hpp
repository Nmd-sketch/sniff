#pragma once
#include <string>

struct IEntry {
    virtual bool isHidden() const;
    virtual bool isSymlink() const;
    virtual bool isDirectory() const;
    virtual const std::string& getPath() const;
    virtual std::size_t getSizeBytes() const;
    virtual const std::string& getCreationDate() const;
    virtual const std::string& getModificationDate() const;
    virtual ~IEntry() = default;
};
