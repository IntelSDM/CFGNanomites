#pragma once

#include "Shellcode.h"

class CFGNanoShellcode : public Shellcode
{
public:
    static constexpr uint32_t MixMul = 0x9E3779B9u;

    CFGNanoShellcode()
    {
        Build();
    }

private:
    void Build()
    {
        PushReg(ZYDIS_REGISTER_RAX);
        PushReg(ZYDIS_REGISTER_RCX);
        PushReg(ZYDIS_REGISTER_RDX);
        PushReg(ZYDIS_REGISTER_R8);
        PushReg(ZYDIS_REGISTER_R9);
        PushReg(ZYDIS_REGISTER_R10);
        PushReg(ZYDIS_REGISTER_R11);
        PushReg(ZYDIS_REGISTER_RBX);
        PushReg(ZYDIS_REGISTER_RSI);

        LeaRipRel(ZYDIS_REGISTER_RBX, 0);
        MarkOffset("AfterLeaRip");

        SubRegImm32Sentinel(ZYDIS_REGISTER_RBX);
        Sentinel("ImgAdj");

        MovRegMem(ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RSP, 72);
        SubRegReg(ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RBX);

        LeaRipRel(ZYDIS_REGISTER_RCX, 0);
        Sentinel("TableBase");

        MovRegRipRel(ZYDIS_REGISTER_EDX, 0);
        Sentinel("Count");

        XorRegReg(ZYDIS_REGISTER_ESI, ZYDIS_REGISTER_ESI);

        Label("loop");
        CmpRegReg(ZYDIS_REGISTER_ESI, ZYDIS_REGISTER_EDX);
        JccShort(ZYDIS_MNEMONIC_JNB, "miss");
        MovRegMem(ZYDIS_REGISTER_R10D, ZYDIS_REGISTER_RCX);
        CmpRegReg(ZYDIS_REGISTER_R10D, ZYDIS_REGISTER_EAX);
        JccShort(ZYDIS_MNEMONIC_JZ, "hit");
        AddRegImm(ZYDIS_REGISTER_RCX, 12);
        IncReg(ZYDIS_REGISTER_ESI);
        JmpShort("loop");

        Label("hit");
        MovRegMem(ZYDIS_REGISTER_R10D, ZYDIS_REGISTER_RCX, 4);
        MovRegMem(ZYDIS_REGISTER_R11D, ZYDIS_REGISTER_RCX, 8);
        MovRegMem(ZYDIS_REGISTER_R8, ZYDIS_REGISTER_RSP, 72);
        SubRegReg(ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R11);
        MovRegMem(ZYDIS_REGISTER_R11D, ZYDIS_REGISTER_R8);
        XorRegRipRel(ZYDIS_REGISTER_R11D, 0);
        Sentinel("BuildKey");
        XorRegReg(ZYDIS_REGISTER_R11D, ZYDIS_REGISTER_EAX);
        ImulRegRegImm(ZYDIS_REGISTER_R11D, ZYDIS_REGISTER_R11D, MixMul);
        XorRegReg(ZYDIS_REGISTER_R10D, ZYDIS_REGISTER_R11D);
        AddRegReg(ZYDIS_REGISTER_R10, ZYDIS_REGISTER_RBX);
        MovMemReg(ZYDIS_REGISTER_RSP, 24, ZYDIS_REGISTER_R10);
        PopReg(ZYDIS_REGISTER_RSI);
        PopReg(ZYDIS_REGISTER_RBX);
        PopReg(ZYDIS_REGISTER_R11);
        PopReg(ZYDIS_REGISTER_R10);
        PopReg(ZYDIS_REGISTER_R9);
        PopReg(ZYDIS_REGISTER_R8);
        PopReg(ZYDIS_REGISTER_RDX);
        PopReg(ZYDIS_REGISTER_RCX);
        PopReg(ZYDIS_REGISTER_RAX);
        JmpReg(ZYDIS_REGISTER_R10);

        Label("miss");
        PopReg(ZYDIS_REGISTER_RSI);
        PopReg(ZYDIS_REGISTER_RBX);
        PopReg(ZYDIS_REGISTER_R11);
        PopReg(ZYDIS_REGISTER_R10);
        PopReg(ZYDIS_REGISTER_R9);
        PopReg(ZYDIS_REGISTER_R8);
        PopReg(ZYDIS_REGISTER_RDX);
        PopReg(ZYDIS_REGISTER_RCX);
        PopReg(ZYDIS_REGISTER_RAX);
        JmpRipRelMem(0);
        Sentinel("FakeSlot");

        ResolveFixups();
        VerifySize(0x98);
    }
};