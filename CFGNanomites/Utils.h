#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>

class Utils
{
public:
    static uint32_t AlignUp(uint32_t v, uint32_t a)
    {
        return (v + a - 1) & ~(a - 1);
    }

    static std::vector<uint8_t> ReadFile(const std::string& path)
    {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f)
        {
            throw std::runtime_error("cannot open " + path);
        }
        auto sz = f.tellg();
        f.seekg(0);
        std::vector<uint8_t> b(static_cast<size_t>(sz));
        f.read(reinterpret_cast<char*>(b.data()), sz);
        return b;
    }

    static void WriteFile(const std::string& path, const std::vector<uint8_t>& buffer)
    {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f)
        {
            throw std::runtime_error("cannot write " + path);
        }
        f.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
    }

    template <typename T>
    static void PutBytes(std::vector<uint8_t>& v, const T& x)
    {
        size_t o = v.size();
        v.resize(o + sizeof(T));
        std::memcpy(v.data() + o, &x, sizeof(T));
    }

    static constexpr uint64_t HashName(const char* s)
    {
        uint64_t h = 0xcbf29ce484222325ULL;
        while (*s)
        {
            h ^= static_cast<uint64_t>(*s++);
            h *= 0x100000001b3ULL;
        }
        return h;
    }
};