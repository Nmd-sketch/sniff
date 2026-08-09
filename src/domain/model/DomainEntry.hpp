#pragma once
#include "IEntry.hpp"

namespace domain {
    struct DomainEntry : public IEntry {
    private:
        const bool m_isSymlink;
        const bool m_isHidden;
        const bool m_isDirectory;
        const std::string m_path;
        const std::string m_filename;
        const std::string m_creationDate;
        const std::string m_modificationDate;
        const std::size_t m_sizeBytes;

    public:
        explicit DomainEntry(bool symLink, bool hidden, bool isDir, std::string path,
                            std::string filename, std::string creationDate, std::string modificationDate,
                            std::size_t sizeBytes)
            : m_isSymlink(symLink), m_isHidden(hidden), m_isDirectory(isDir),
            m_path(std::move(path)), m_filename(std::move(filename)), m_creationDate(std::move(creationDate)),
            m_modificationDate(std::move(modificationDate)), m_sizeBytes(sizeBytes){}

         bool isHidden() const override {
             return m_isHidden;
         };

         bool isSymlink() const override {
             return m_isSymlink;
         };

         bool isDirectory() const override {
             return m_isDirectory;
         };

         const std::string& getPath() const override {
             return m_path;
         };

         std::size_t getSizeBytes() const override {
             return m_sizeBytes;
         };

         const std::string& getCreationDate() const override {
             return m_creationDate;
         };

         const std::string& getModificationDate() const override {
             return m_modificationDate;
         };
        
    };

} // namespace domain
