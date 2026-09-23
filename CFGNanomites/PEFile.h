#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <stdexcept>
#include <Windows.h>
#include "Utils.h"

class PEFile
{
public:
    void Load(const std::string& path)
    {
        m_buffer = Utils::ReadFile(path);
        Parse();
    }

    void Save(const std::string& path) const
    {
        Utils::WriteFile(path, m_buffer);
    }

    std::vector<uint8_t>& Buffer()
    {
        return m_buffer;
    }

    const std::vector<uint8_t>& Buffer() const
    {
        return m_buffer;
    }

    IMAGE_DOS_HEADER* Dos()
    {
        return reinterpret_cast<IMAGE_DOS_HEADER*>(m_buffer.data());
    }

    IMAGE_NT_HEADERS64* Nt()
    {
        return reinterpret_cast<IMAGE_NT_HEADERS64*>(m_buffer.data() + Dos()->e_lfanew);
    }

    IMAGE_SECTION_HEADER* SectionTable()
    {
        auto* nt = Nt();
        return reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<uint8_t*>(nt) + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);
    }

    uint16_t SectionCount()
    {
        return Nt()->FileHeader.NumberOfSections;
    }

    uint32_t RvaToOffset(uint32_t rva)
    {
        auto* sec = SectionTable();
        auto n = SectionCount();
        for (uint16_t i = 0; i < n; ++i)
        {
            uint32_t va = sec[i].VirtualAddress;
            uint32_t vs = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
            if (rva >= va && rva < va + vs)
            {
                return sec[i].PointerToRawData + (rva - va);
            }
        }
        return 0;
    }

    int FindSectionByRva(uint32_t rva)
    {
        auto* sec = SectionTable();
        auto n = SectionCount();
        for (uint16_t i = 0; i < n; ++i)
        {
            uint32_t va = sec[i].VirtualAddress;
            uint32_t vs = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
            if (rva >= va && rva < va + vs)
            {
                return static_cast<int>(i);
            }
        }
        return -1;
    }

    uint32_t SectionRawEndRva(uint32_t rva)
    {
        auto* sec = SectionTable();
        auto n = SectionCount();
        for (uint16_t i = 0; i < n; ++i)
        {
            uint32_t va = sec[i].VirtualAddress;
            uint32_t vs = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
            if (rva >= va && rva < va + vs)
            {
                return va + sec[i].SizeOfRawData;
            }
        }
        return 0;
    }

    uint32_t LastEndRva()
    {
        auto* sec = SectionTable();
        auto n = SectionCount();
        uint32_t last = 0;
        for (uint16_t i = 0; i < n; ++i)
        {
            uint32_t vs = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
            uint32_t e = sec[i].VirtualAddress + vs;
            if (e > last)
            {
                last = e;
            }
        }
        return last;
    }

private:
    void Parse() const
    {
        if (m_buffer.size() < sizeof(IMAGE_DOS_HEADER))
        {
            throw std::runtime_error("file too small");
        }
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_buffer.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            throw std::runtime_error("not MZ");
        }
        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(m_buffer.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
        {
            throw std::runtime_error("not PE");
        }
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            throw std::runtime_error("not PE32+ (only x64 supported)");
        }
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        {
            throw std::runtime_error("not AMD64");
        }
        if (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
        {
            throw std::runtime_error("IMAGE_FILE_RELOCS_STRIPPED set - can't inject VAs");
        }
    }

    std::vector<uint8_t> m_buffer;
};