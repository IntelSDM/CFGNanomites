#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <climits>
#include <vector>
#include <map>
#include <string>
#include <stdexcept>
#include <Zydis/Zydis.h>
#include "Utils.h"

class Shellcode
{
public:
    virtual ~Shellcode() = default;

    const uint8_t* Data() const
    {
        return m_bytes.data();
    }

    std::size_t Size() const
    {
        return m_bytes.size();
    }

    const std::map<uint64_t, std::size_t>& Offsets() const
    {
        return m_offsets;
    }

    std::size_t OffsetOf(const char* name) const
    {
        return m_offsets.at(Utils::HashName(name));
    }

protected:
    struct Fixup
    {
        std::string Label;
        std::size_t PatchOff;
        std::size_t RipBase;
        bool IsShort;
    };

    std::vector<uint8_t> m_bytes;
    std::map<uint64_t, std::size_t> m_offsets;
    std::map<std::string, std::size_t> m_labels;
    std::vector<Fixup> m_fixups;

    void Emit(const ZydisEncoderRequest& req)
    {
        uint8_t buf[ZYDIS_MAX_INSTRUCTION_LENGTH];
        ZyanUSize len = sizeof(buf);
        if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, buf, &len)))
        {
            const char* mn = ZydisMnemonicGetString(req.mnemonic);
            throw std::runtime_error(std::string("zydis encoder failed for mnemonic: ") + (mn ? mn : "?"));
        }
        m_bytes.insert(m_bytes.end(), buf, buf + len);
    }

    void Sentinel(const char* name)
    {
        m_offsets[Utils::HashName(name)] = m_bytes.size() - 4;
    }

    void MarkOffset(const char* name)
    {
        m_offsets[Utils::HashName(name)] = m_bytes.size();
    }

    void Label(const std::string& name)
    {
        m_labels[name] = m_bytes.size();
    }

    void ResolveFixups()
    {
        for (const auto& f : m_fixups)
        {
            const auto it = m_labels.find(f.Label);
            if (it == m_labels.end())
            {
                throw std::runtime_error("unresolved label: " + f.Label);
            }
            const int64_t disp = static_cast<int64_t>(it->second) - static_cast<int64_t>(f.RipBase);
            if (f.IsShort)
            {
                if (disp < -128 || disp > 127)
                {
                    throw std::runtime_error("rel8 out of range for label: " + f.Label);
                }
                m_bytes[f.PatchOff] = static_cast<uint8_t>(static_cast<int8_t>(disp));
            }
            else
            {
                const int32_t d32 = static_cast<int32_t>(disp);
                std::memcpy(&m_bytes[f.PatchOff], &d32, 4);
            }
        }
    }

    static ZydisEncoderRequest MakeReq(ZydisMnemonic m)
    {
        ZydisEncoderRequest r{};
        r.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        r.mnemonic = m;
        return r;
    }

    static uint16_t RegBytes(ZydisRegister reg)
    {
        return static_cast<uint16_t>(ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, reg) / 8);
    }

    void PushReg(ZydisRegister reg)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_PUSH);
        r.operand_count = 1;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = reg;
        Emit(r);
    }

    void PopReg(ZydisRegister reg)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_POP);
        r.operand_count = 1;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = reg;
        Emit(r);
    }

    void MovRegReg(ZydisRegister dst, ZydisRegister src)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_MOV);
        r.operand_count = 2;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = dst;
        r.operands[1].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[1].reg.value = src;
        Emit(r);
    }

    void MovRegMem(ZydisRegister dst, ZydisRegister base, int32_t disp = 0)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_MOV);
        r.operand_count = 2;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = dst;
        r.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
        r.operands[1].mem.base = base;
        r.operands[1].mem.displacement = disp;
        r.operands[1].mem.size = RegBytes(dst);
        Emit(r);
    }

    void MovMemReg(ZydisRegister base, int32_t disp, ZydisRegister src)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_MOV);
        r.operand_count = 2;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
        r.operands[0].mem.base = base;
        r.operands[0].mem.displacement = disp;
        r.operands[0].mem.size = RegBytes(src);
        r.operands[1].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[1].reg.value = src;
        Emit(r);
    }

    void MovRegImm32(ZydisRegister dst, uint32_t imm)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_MOV);
        r.operand_count = 2;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = dst;
        r.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        r.operands[1].imm.u = imm;
        Emit(r);
    }

    void LeaRipRel(ZydisRegister dst, int32_t disp)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_LEA);
        r.operand_count = 2;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = dst;
        r.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
        r.operands[1].mem.base = ZYDIS_REGISTER_RIP;
        r.operands[1].mem.displacement = disp;
        r.operands[1].mem.size = 8;
        Emit(r);
    }

    void MovRegRipRel(ZydisRegister dst, int32_t disp)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_MOV);
        r.operand_count = 2;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = dst;
        r.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
        r.operands[1].mem.base = ZYDIS_REGISTER_RIP;
        r.operands[1].mem.displacement = disp;
        r.operands[1].mem.size = RegBytes(dst);
        Emit(r);
    }

    void SubRegReg(ZydisRegister dst, ZydisRegister src)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_SUB);
        r.operand_count = 2;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = dst;
        r.operands[1].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[1].reg.value = src;
        Emit(r);
    }

    void SubRegImm32Sentinel(ZydisRegister dst)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_SUB);
        r.operand_count = 2;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = dst;
        r.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        r.operands[1].imm.s = INT32_MIN;
        Emit(r);
        std::memset(&m_bytes[m_bytes.size() - 4], 0, 4);
    }

    void AddRegReg(ZydisRegister dst, ZydisRegister src)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_ADD);
        r.operand_count = 2;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = dst;
        r.operands[1].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[1].reg.value = src;
        Emit(r);
    }

    void AddRegImm(ZydisRegister dst, int32_t imm)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_ADD);
        r.operand_count = 2;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = dst;
        r.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        r.operands[1].imm.s = imm;
        Emit(r);
    }

    void XorRegReg(ZydisRegister dst, ZydisRegister src)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_XOR);
        r.operand_count = 2;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = dst;
        r.operands[1].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[1].reg.value = src;
        Emit(r);
    }

    void XorRegRipRel(ZydisRegister dst, int32_t disp)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_XOR);
        r.operand_count = 2;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = dst;
        r.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
        r.operands[1].mem.base = ZYDIS_REGISTER_RIP;
        r.operands[1].mem.displacement = disp;
        r.operands[1].mem.size = RegBytes(dst);
        Emit(r);
    }

    void CmpRegReg(ZydisRegister a, ZydisRegister b)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_CMP);
        r.operand_count = 2;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = a;
        r.operands[1].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[1].reg.value = b;
        Emit(r);
    }

    void CmpRegImm(ZydisRegister reg, int32_t imm)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_CMP);
        r.operand_count = 2;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = reg;
        r.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        r.operands[1].imm.s = imm;
        Emit(r);
    }

    void IncReg(ZydisRegister reg)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_INC);
        r.operand_count = 1;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = reg;
        Emit(r);
    }

    void ImulRegRegImm(ZydisRegister dst, ZydisRegister src, uint32_t imm)
    {
        if (RegBytes(dst) != 4 || RegBytes(src) != 4)
        {
            throw std::runtime_error("ImulRegRegImm: only r32 supported");
        }
        const uint8_t dstid = static_cast<uint8_t>(ZydisRegisterGetId(dst));
        const uint8_t srcid = static_cast<uint8_t>(ZydisRegisterGetId(src));
        uint8_t rex = 0;
        if (dstid >= 8)
        {
            rex |= 0x04;
        }
        if (srcid >= 8)
        {
            rex |= 0x01;
        }
        if (rex != 0)
        {
            m_bytes.push_back(0x40 | rex);
        }
        m_bytes.push_back(0x69);
        m_bytes.push_back(static_cast<uint8_t>(0xC0 | ((dstid & 7) << 3) | (srcid & 7)));
        const uint32_t imm32 = imm;
        m_bytes.insert(m_bytes.end(), reinterpret_cast<const uint8_t*>(&imm32), reinterpret_cast<const uint8_t*>(&imm32) + 4);
    }

    void JmpReg(ZydisRegister reg)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_JMP);
        r.operand_count = 1;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
        r.operands[0].reg.value = reg;
        Emit(r);
    }

    void JmpRipRelMem(int32_t disp)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_JMP);
        r.operand_count = 1;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
        r.operands[0].mem.base = ZYDIS_REGISTER_RIP;
        r.operands[0].mem.displacement = disp;
        r.operands[0].mem.size = 8;
        Emit(r);
    }

    void JmpShort(const std::string& label)
    {
        auto r = MakeReq(ZYDIS_MNEMONIC_JMP);
        r.branch_type = ZYDIS_BRANCH_TYPE_SHORT;
        r.branch_width = ZYDIS_BRANCH_WIDTH_8;
        r.operand_count = 1;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        r.operands[0].imm.s = 0;
        Emit(r);
        m_fixups.push_back({ label, m_bytes.size() - 1, m_bytes.size(), true });
    }

    void JccShort(ZydisMnemonic mnem, const std::string& label)
    {
        auto r = MakeReq(mnem);
        r.branch_type = ZYDIS_BRANCH_TYPE_SHORT;
        r.branch_width = ZYDIS_BRANCH_WIDTH_8;
        r.operand_count = 1;
        r.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
        r.operands[0].imm.s = 0;
        Emit(r);
        m_fixups.push_back({ label, m_bytes.size() - 1, m_bytes.size(), true });
    }

    void Ret()
    {
        const auto r = MakeReq(ZYDIS_MNEMONIC_RET);
        Emit(r);
    }

    void Int3()
    {
        const auto r = MakeReq(ZYDIS_MNEMONIC_INT3);
        Emit(r);
    }

    void VerifySize(std::size_t expected) const
    {
        if (m_bytes.size() != expected)
        {
            throw std::runtime_error("shellcode size mismatch after build");
        }
    }
};