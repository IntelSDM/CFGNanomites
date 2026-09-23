#pragma once

#include "Shellcode.h"

class TlsCallbackShellcode : public Shellcode
{
public:
    TlsCallbackShellcode()
    {
        Build();
    }

private:
    void Build()
    {
        CmpRegImm(ZYDIS_REGISTER_EDX, 1);
        JccShort(ZYDIS_MNEMONIC_JNZ, "done");

        MovRegImm32(ZYDIS_REGISTER_EAX, 0);
        Sentinel("ShellRva");
        AddRegReg(ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX);

        MovRegImm32(ZYDIS_REGISTER_EDX, 0);
        Sentinel("FptrRva");
        AddRegReg(ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RCX);

        MovRegMem(ZYDIS_REGISTER_R9, ZYDIS_REGISTER_RDX);

        MovRegImm32(ZYDIS_REGISTER_R10D, 0);
        Sentinel("FakeRva");
        AddRegReg(ZYDIS_REGISTER_R10, ZYDIS_REGISTER_RCX);

        MovMemReg(ZYDIS_REGISTER_R10, 0, ZYDIS_REGISTER_R9);
        MovMemReg(ZYDIS_REGISTER_RDX, 0, ZYDIS_REGISTER_RAX);
        MovRegMem(ZYDIS_REGISTER_R11, ZYDIS_REGISTER_RDX);
        CmpRegReg(ZYDIS_REGISTER_R11, ZYDIS_REGISTER_RAX);
        JccShort(ZYDIS_MNEMONIC_JNZ, "fail");
        JmpShort("done");

        Label("fail");
        Int3();

        Label("done");
        Ret();

        ResolveFixups();
        VerifySize(0x33);
    }
};