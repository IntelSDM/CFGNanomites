#pragma once

#include <cstdint>
#include <vector>
#include <Windows.h>
#include <Zydis/Zydis.h>

struct CallSite
{
    uint32_t Rva;
    uint32_t TargetRva;
    uint8_t Length;
    bool IsDirect;
    bool IsCfgDispatch;
};

class CallScanner
{
public:
    static std::vector<CallSite> Scan(const std::vector<uint8_t>& file, const IMAGE_SECTION_HEADER* sectable, uint16_t nsections, uint32_t fptrslotrva, uint32_t& outscannedsections, uint64_t& outdecoded)
    {
        std::vector<CallSite> calls;
        ZydisDecoder decoder;
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        outscannedsections = 0;
        outdecoded = 0;
        for (uint16_t s = 0; s < nsections; ++s)
        {
            const auto& sh = sectable[s];
            if (!(sh.Characteristics & IMAGE_SCN_MEM_EXECUTE))
            {
                continue;
            }
            if (!sh.SizeOfRawData)
            {
                continue;
            }
            if (sh.PointerToRawData >= file.size())
            {
                continue;
            }
            uint32_t rawsize = sh.SizeOfRawData;
            if (static_cast<uint64_t>(sh.PointerToRawData) + rawsize > file.size())
            {
                rawsize = static_cast<uint32_t>(file.size() - sh.PointerToRawData);
            }
            const uint8_t* base = file.data() + sh.PointerToRawData;
            const uint32_t secrva = sh.VirtualAddress;
            ++outscannedsections;
            uint32_t off = 0;
            while (off < rawsize)
            {
                ZydisDecodedInstruction ins;
                ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
                const ZyanStatus st = ZydisDecoderDecodeFull(&decoder, base + off, rawsize - off, &ins, ops);
                if (!ZYAN_SUCCESS(st))
                {
                    off += 1;
                    continue;
                }
                ++outdecoded;
                if (ins.mnemonic == ZYDIS_MNEMONIC_CALL)
                {
                    CallSite c{};
                    c.Rva = secrva + off;
                    c.Length = ins.length;
                    if (ins.operand_count > 0 && ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                    {
                        c.IsDirect = true;
                        ZyanU64 abs = 0;
                        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &ops[0], c.Rva, &abs)))
                        {
                            c.TargetRva = static_cast<uint32_t>(abs);
                        }
                    }
                    else if (ins.operand_count > 0 && ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[0].mem.base == ZYDIS_REGISTER_RIP && ins.length == 6)
                    {
                        ZyanU64 abs = 0;
                        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &ops[0], c.Rva, &abs)))
                        {
                            if (static_cast<uint32_t>(abs) == fptrslotrva)
                            {
                                c.IsCfgDispatch = true;
                            }
                        }
                    }
                    if (c.IsDirect || c.IsCfgDispatch)
                    {
                        calls.push_back(c);
                    }
                }
                off += ins.length;
            }
        }
        return calls;
    }
};