#include "Pch.h"
/*
CFGNanomites is just a POC
THis isn't the proper way to do this, you need a proper obfuscation pipeline/LLVM pass to do this properly
Realistically you want to make all the calls:
MOV RAX Vtable
call [__guard_dispatch_icall_fptr]
We can't do this though from basic patching so this POC takes all existing:
call [__guard_dispatch_icall_fptr]
And turns them into a call to a redirector
So all vtable calls turn to:
Call redirector
While all normal calls are also to the redirector, hiding which is and isn't a vtable
Then this redirector actually just calls __guard_dispatch_icall_fptr for us as its 6 bytes and a direct call is 5 bytes.
Then the hook in __guard_dispatch_icall_fptr is redirecting the fake vtables into their real calls in there at runtime.

This is a very basic POC of it, to do this properly you do need a PROPER obfuscation pipeline! Don't expect any form of production usage here!
*/

#include <random>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <Windows.h>
#include "Utils.h"
#include "PEFile.h"
#include "Shellcode/Shellcode.h"
#include "Shellcode/CFGNanoShellcode.h"
#include "Shellcode/TlsCallbackShellcode.h"
#include "CallScanner.h"
#include "NanoLayout.h"

struct RegistryEntry
{
    uint32_t SiteRetRva;
    uint32_t Ct32;
    uint32_t RefOff;
    uint32_t TargetRva;
};

struct DirectCandidate
{
    uint32_t SiteRva;
    uint32_t SiteOff;
    uint32_t TargetRva;
    uint32_t SecRawEndRva;
    int32_t E8Disp;
};

struct CfgCandidate
{
    uint32_t SiteRva;
    uint32_t SiteOff;
    int32_t E8Disp;
};

struct ShellPatch
{
    std::size_t Off;
    uint32_t Target;
    bool IsDisp;
};

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::fprintf(stderr, "usage: %s <input.exe> <output.exe>\n", argv[0]);
        return 1;
    }

    PEFile pe;
    try
    {
        pe.Load(argv[1]);
    }
    catch (const std::exception& e)
    {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    }

    auto& file = pe.Buffer();
    auto* nt = pe.Nt();

    const bool hadguardcf = (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
    if (hadguardcf)
    {
        nt->OptionalHeader.DllCharacteristics &= static_cast<uint16_t>(~IMAGE_DLLCHARACTERISTICS_GUARD_CF);
    }

    auto& tlsdd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    auto& relocdd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    auto& lcfgdd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

    if (!relocdd.VirtualAddress || !relocdd.Size)
    {
        std::fprintf(stderr, "no base reloc directory to extend\n");
        return 1;
    }

    const uint32_t filealign = nt->OptionalHeader.FileAlignment;
    const uint32_t secalign = nt->OptionalHeader.SectionAlignment;
    const uint64_t imagebase = nt->OptionalHeader.ImageBase;
    const uint16_t nsections = nt->FileHeader.NumberOfSections;
    auto* sectable = pe.SectionTable();

    const uintptr_t shendoff = reinterpret_cast<uintptr_t>(sectable + nsections + 2) - reinterpret_cast<uintptr_t>(file.data());
    if (shendoff > nt->OptionalHeader.SizeOfHeaders)
    {
        std::fprintf(stderr, "no room in headers for two more IMAGE_SECTION_HEADERs (SizeOfHeaders=%u)\n", nt->OptionalHeader.SizeOfHeaders);
        return 1;
    }

    constexpr size_t dispatchoff = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFDispatchFunctionPointer);
    if (!lcfgdd.VirtualAddress || lcfgdd.Size < dispatchoff + 8)
    {
        std::fprintf(stderr, "load config missing or too small for GuardCFDispatchFunctionPointer\n");
        return 1;
    }
    const uint32_t lcfgoff = pe.RvaToOffset(lcfgdd.VirtualAddress);
    if (!lcfgoff)
    {
        std::fprintf(stderr, "cannot resolve load config on disk\n");
        return 1;
    }
    uint64_t fptrslotva = 0;
    std::memcpy(&fptrslotva, file.data() + lcfgoff + dispatchoff, 8);
    if (fptrslotva < imagebase || fptrslotva >= imagebase + 0x80000000ULL)
    {
        std::fprintf(stderr, "GuardCFDispatchFunctionPointer VA 0x%llX out of range\n", static_cast<unsigned long long>(fptrslotva));
        return 1;
    }
    const uint32_t fptrslotrva = static_cast<uint32_t>(fptrslotva - imagebase);

    const int fptrsectionidx = pe.FindSectionByRva(fptrslotrva);
    if (fptrsectionidx < 0)
    {
        std::fprintf(stderr, "cannot locate section for fptr slot\n");
        return 1;
    }
    const bool fptrsectionwaswritable = (sectable[fptrsectionidx].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    if (!fptrsectionwaswritable)
    {
        sectable[fptrsectionidx].Characteristics |= IMAGE_SCN_MEM_WRITE;
    }

    std::vector<uint32_t> funcbegins;
    {
        auto& pdatadd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (pdatadd.VirtualAddress && pdatadd.Size >= 12)
        {
            const uint32_t pdoff = pe.RvaToOffset(pdatadd.VirtualAddress);
            if (pdoff)
            {
                const uint32_t n = pdatadd.Size / 12;
                funcbegins.reserve(n);
                for (uint32_t i = 0; i < n; ++i)
                {
                    const uint32_t eo = pdoff + i * 12;
                    if (static_cast<uint64_t>(eo) + 12 > file.size())
                    {
                        break;
                    }
                    uint32_t b;
                    std::memcpy(&b, file.data() + eo, 4);
                    if (b)
                    {
                        funcbegins.push_back(b);
                    }
                }
                std::sort(funcbegins.begin(), funcbegins.end());
                funcbegins.erase(std::unique(funcbegins.begin(), funcbegins.end()), funcbegins.end());
            }
        }
    }
    if (funcbegins.empty())
    {
        std::fprintf(stderr, "no RUNTIME_FUNCTION entries in .pdata\n");
        return 1;
    }

    uint32_t scannedsecs = 0;
    uint64_t decodedcount = 0;
    const auto calls = CallScanner::Scan(file, sectable, nsections, fptrslotrva, scannedsecs, decodedcount);
    size_t ndirect = 0;
    size_t ncfg = 0;
    for (const auto& c : calls)
    {
        if (c.IsDirect)
        {
            ++ndirect;
        }
        if (c.IsCfgDispatch)
        {
            ++ncfg;
        }
    }
    std::printf("[+] scanned %u executable section(s); decoded %llu instr(s)\n", scannedsecs, static_cast<unsigned long long>(decodedcount));
    std::printf("[+] calls found: %zu total\n", calls.size());
    std::printf("direct E8 rel32: %zu\n", ndirect);
    std::printf("FF 15 cfg dispatch (fptr_slot): %zu\n", ncfg);
    std::printf("[+] .pdata: %zu RUNTIME_FUNCTION range(s) available\n", funcbegins.size());

    const bool hasexistingtls = tlsdd.VirtualAddress && tlsdd.Size;
    IMAGE_TLS_DIRECTORY64 existingtls{};
    uint32_t existingtlsfileoff = 0;
    std::vector<uint64_t> existingcbs;
    if (hasexistingtls)
    {
        if (tlsdd.Size < sizeof(IMAGE_TLS_DIRECTORY64))
        {
            std::fprintf(stderr, "existing TLS dir size (%u) below sizeof(IMAGE_TLS_DIRECTORY64) (%zu)\n", tlsdd.Size, sizeof(IMAGE_TLS_DIRECTORY64));
            return 1;
        }
        existingtlsfileoff = pe.RvaToOffset(tlsdd.VirtualAddress);
        if (!existingtlsfileoff)
        {
            std::fprintf(stderr, "cannot resolve existing TLS dir on disk\n");
            return 1;
        }
        std::memcpy(&existingtls, file.data() + existingtlsfileoff, sizeof(existingtls));
        if (existingtls.AddressOfCallBacks)
        {
            if (existingtls.AddressOfCallBacks < imagebase)
            {
                std::fprintf(stderr, "AddressOfCallBacks below ImageBase\n");
                return 1;
            }
            const uint32_t cbrva = static_cast<uint32_t>(existingtls.AddressOfCallBacks - imagebase);
            const uint32_t cboffinfile = pe.RvaToOffset(cbrva);
            if (!cboffinfile)
            {
                std::fprintf(stderr, "cannot resolve callback array on disk\n");
                return 1;
            }
            bool terminated = false;
            for (int i = 0; i < 256; ++i)
            {
                uint64_t v;
                std::memcpy(&v, file.data() + cboffinfile + i * 8, 8);
                if (!v)
                {
                    terminated = true;
                    break;
                }
                existingcbs.push_back(v);
            }
            if (!terminated)
            {
                std::fprintf(stderr, "callback array not null-terminated in 256 slots\n");
                return 1;
            }
        }
    }

    const uint32_t nanorva = Utils::AlignUp(pe.LastEndRva(), secalign);
    const uint32_t ndatrva = Utils::AlignUp(nanorva + NanoLayout::NanoBytes, secalign);

    const uint32_t shellcoderva = nanorva + NanoLayout::OffShellcode;
    const uint32_t tlscbrva = nanorva + NanoLayout::OffTlsCb;
    const uint32_t countrva = nanorva + NanoLayout::OffCount;
    const uint32_t buildkeyrva = nanorva + NanoLayout::OffBuildKey;
    const uint32_t tablerva = nanorva + NanoLayout::OffTable;
    const uint32_t fakeslotrva = ndatrva + NanoLayout::OffFakeSlot;

    uint32_t buildkey32;
    {
        std::random_device rd;
        buildkey32 = (static_cast<uint32_t>(rd()) ^ (static_cast<uint32_t>(rd()) << 16)) | 1u;
    }

    std::vector<RegistryEntry> registry;
    std::vector<DirectCandidate> directcands;
    std::vector<CfgCandidate> cfgcands;
    registry.reserve(std::min<size_t>(ndirect, NanoLayout::MaxTableEntries));
    directcands.reserve(std::min<size_t>(ndirect, NanoLayout::MaxTableEntries));
    cfgcands.reserve(ncfg);

    uint32_t skipunresolvable = 0;
    uint32_t skipopcode = 0;
    uint32_t skipdisprange = 0;
    uint32_t skipzerofill = 0;
    uint32_t skipcapped = 0;

    for (const auto& c : calls)
    {
        const uint32_t siteoff = pe.RvaToOffset(c.Rva);
        if (!siteoff || static_cast<uint64_t>(siteoff) + c.Length > file.size())
        {
            ++skipunresolvable;
            continue;
        }
        if (c.IsDirect)
        {
            if (c.Length != 5)
            {
                continue;
            }
            if (file[siteoff] != 0xE8)
            {
                ++skipopcode;
                continue;
            }
            const int64_t ripafter = static_cast<int64_t>(c.Rva) + 5;
            const int64_t disp = static_cast<int64_t>(shellcoderva) - ripafter;
            if (disp < INT32_MIN || disp > INT32_MAX)
            {
                ++skipdisprange;
                continue;
            }
            const uint32_t secrawend = pe.SectionRawEndRva(c.Rva);
            if (!secrawend)
            {
                ++skipunresolvable;
                continue;
            }
            if (directcands.size() >= NanoLayout::MaxTableEntries)
            {
                ++skipcapped;
                continue;
            }
            directcands.push_back({ c.Rva, siteoff, c.TargetRva, secrawend, static_cast<int32_t>(disp) });
        }
        else if (c.IsCfgDispatch)
        {
            if (c.Length != 6)
            {
                continue;
            }
            if (file[siteoff] != 0xFF || file[siteoff + 1] != 0x15)
            {
                ++skipopcode;
                continue;
            }
            const int64_t ripafter = static_cast<int64_t>(c.Rva) + 5;
            const int64_t disp = static_cast<int64_t>(shellcoderva) - ripafter;
            if (disp < INT32_MIN || disp > INT32_MAX)
            {
                ++skipdisprange;
                continue;
            }
            cfgcands.push_back({ c.Rva, siteoff, static_cast<int32_t>(disp) });
        }
    }

    for (const auto& d : directcands)
    {
        file[d.SiteOff] = 0xE8;
        std::memcpy(file.data() + d.SiteOff + 1, &d.E8Disp, 4);
    }
    for (const auto& g : cfgcands)
    {
        file[g.SiteOff] = 0xE8;
        std::memcpy(file.data() + g.SiteOff + 1, &g.E8Disp, 4);
        file[g.SiteOff + 5] = 0x90;
    }

    for (const auto& d : directcands)
    {
        const uint32_t siteretrva = d.SiteRva + 5;
        const uint32_t refoff = 0;
        const uint32_t refrva = siteretrva - refoff;
        if (refrva + 4 > d.SecRawEndRva)
        {
            ++skipzerofill;
            continue;
        }
        const uint32_t reffileoff = pe.RvaToOffset(refrva);
        if (!reffileoff || static_cast<uint64_t>(reffileoff) + 4 > file.size())
        {
            ++skipunresolvable;
            continue;
        }
        uint32_t refbytes;
        std::memcpy(&refbytes, file.data() + reffileoff, 4);
        const uint32_t key32 = ((refbytes ^ buildkey32) ^ siteretrva) * CFGNanoShellcode::MixMul;
        const uint32_t ct32 = d.TargetRva ^ key32;
        registry.push_back({ siteretrva, ct32, refoff, d.TargetRva });
    }

    std::sort(registry.begin(), registry.end(), [](const RegistryEntry& a, const RegistryEntry& b)
        {
            return a.SiteRetRva < b.SiteRetRva;
        });

    std::printf("[+] direct E8: %zu rewritten, %zu registered (capped=%u, opcode=%u, unresolvable=%u, disp-range=%u, zerofill=%u)\n", directcands.size(), registry.size(), skipcapped, skipopcode, skipunresolvable, skipdisprange, skipzerofill);
    std::printf("[+] CFG FF 15: %zu rewritten to E8+NOP (camouflage)\n", cfgcands.size());
    {
        const size_t kshow = registry.size() < 8 ? registry.size() : 8;
        for (size_t k = 0; k < kshow; ++k)
        {
            const auto& e = registry[k];
            const uint32_t siterva = e.SiteRetRva - 5;
            std::printf("[%zu] site=0x%08X E8->E8  target=0x%08X  (site_ret=0x%08X  ct32=0x%08X  ref_off=0x%X)\n", k, siterva, e.TargetRva, e.SiteRetRva, e.Ct32, e.RefOff);
        }
        if (registry.size() > kshow)
        {
            std::printf("... (%zu more)\n", registry.size() - kshow);
        }
    }

    std::vector<uint8_t> nanosec(NanoLayout::NanoBytes, 0);
    std::fflush(stdout);
    std::unique_ptr<CFGNanoShellcode> cfgshellptr;
    std::unique_ptr<TlsCallbackShellcode> tlsshellptr;
    try
    {
        cfgshellptr = std::make_unique<CFGNanoShellcode>();
        tlsshellptr = std::make_unique<TlsCallbackShellcode>();
    }
    catch (const std::exception& e)
    {
        std::fprintf(stderr, "shellcode build failed: %s\n", e.what());
        return 1;
    }
    const CFGNanoShellcode& cfgshell = *cfgshellptr;
    const TlsCallbackShellcode& tlsshell = *tlsshellptr;

    std::memcpy(nanosec.data() + NanoLayout::OffShellcode, cfgshell.Data(), cfgshell.Size());
    {
        const ShellPatch sp[] =
        {
            { cfgshell.OffsetOf("ImgAdj"), shellcoderva + static_cast<uint32_t>(cfgshell.OffsetOf("AfterLeaRip")), false },
            { cfgshell.OffsetOf("TableBase"), tablerva, true },
            { cfgshell.OffsetOf("Count"), countrva, true },
            { cfgshell.OffsetOf("BuildKey"), buildkeyrva, true },
            { cfgshell.OffsetOf("FakeSlot"), fakeslotrva, true },
        };
        for (const auto& p : sp)
        {
            uint32_t v = p.Target;
            if (p.IsDisp)
            {
                const int64_t ripafter = static_cast<int64_t>(shellcoderva) + static_cast<int64_t>(p.Off) + 4;
                const int64_t disp = static_cast<int64_t>(p.Target) - ripafter;
                if (disp < INT32_MIN || disp > INT32_MAX)
                {
                    std::fprintf(stderr, "shellcode disp32 overflow at off 0x%zX\n", p.Off);
                    return 1;
                }
                v = static_cast<uint32_t>(static_cast<int32_t>(disp));
            }
            std::memcpy(nanosec.data() + NanoLayout::OffShellcode + p.Off, &v, 4);
        }
    }

    std::memcpy(nanosec.data() + NanoLayout::OffTlsCb, tlsshell.Data(), tlsshell.Size());
    {
        uint32_t v;
        v = shellcoderva;
        std::memcpy(nanosec.data() + NanoLayout::OffTlsCb + tlsshell.OffsetOf("ShellRva"), &v, 4);
        v = fptrslotrva;
        std::memcpy(nanosec.data() + NanoLayout::OffTlsCb + tlsshell.OffsetOf("FptrRva"), &v, 4);
        v = fakeslotrva;
        std::memcpy(nanosec.data() + NanoLayout::OffTlsCb + tlsshell.OffsetOf("FakeRva"), &v, 4);
    }

    std::memcpy(nanosec.data() + NanoLayout::OffBuildKey, &buildkey32, 4);
    {
        const uint32_t count = static_cast<uint32_t>(registry.size());
        std::memcpy(nanosec.data() + NanoLayout::OffCount, &count, 4);
        for (size_t i = 0; i < registry.size(); ++i)
        {
            std::memcpy(nanosec.data() + NanoLayout::OffTable + i * NanoLayout::TableEntrySize, &registry[i], NanoLayout::TableEntrySize);
        }
    }

    uint32_t cur = 0;
    const uint32_t fakeslotoff = cur;
    cur += 8;
    uint32_t idxoff = 0;
    uint32_t tlsoff = 0;
    if (!hasexistingtls)
    {
        cur = Utils::AlignUp(cur, 8);
        idxoff = cur;
        cur += 8;
        tlsoff = cur;
        cur += sizeof(IMAGE_TLS_DIRECTORY64);
    }
    cur = Utils::AlignUp(cur, 8);
    const uint32_t cboff = cur;
    cur += static_cast<uint32_t>((existingcbs.size() + 2) * 8);
    cur = Utils::AlignUp(cur, 4);
    const uint32_t reloccopyoff = cur;
    cur += relocdd.Size;
    const uint32_t newrelocoff = cur;

    const uint32_t estrelocentries = static_cast<uint32_t>((hasexistingtls ? 0 : 4) + existingcbs.size() + 1);
    const uint32_t relocentriespadded = (estrelocentries + 1) & ~1u;
    const uint32_t newrelocblocksize = sizeof(IMAGE_BASE_RELOCATION) + relocentriespadded * sizeof(uint16_t);

    const uint32_t ndatvirtsize = newrelocoff + newrelocblocksize;
    const uint32_t ndatrawsize = Utils::AlignUp(ndatvirtsize, filealign);

    std::vector<uint8_t> ndatsec(ndatrawsize, 0);
    (void)fakeslotoff;

    if (!hasexistingtls)
    {
        IMAGE_TLS_DIRECTORY64 tls{};
        tls.StartAddressOfRawData = imagebase + ndatrva + idxoff;
        tls.EndAddressOfRawData = imagebase + ndatrva + idxoff;
        tls.AddressOfIndex = imagebase + ndatrva + idxoff;
        tls.AddressOfCallBacks = imagebase + ndatrva + cboff;
        tls.SizeOfZeroFill = 0;
        tls.Characteristics = 0;
        std::memcpy(ndatsec.data() + tlsoff, &tls, sizeof(tls));
    }

    const uint64_t ourcbva = imagebase + tlscbrva;
    {
        size_t w = cboff;
        for (const uint64_t v : existingcbs)
        {
            std::memcpy(ndatsec.data() + w, &v, 8);
            w += 8;
        }
        std::memcpy(ndatsec.data() + w, &ourcbva, 8);
    }

    const uint32_t oldrelocoffinfile = pe.RvaToOffset(relocdd.VirtualAddress);
    if (!oldrelocoffinfile)
    {
        std::fprintf(stderr, "cannot resolve old reloc dir on disk\n");
        return 1;
    }
    std::memcpy(ndatsec.data() + reloccopyoff, file.data() + oldrelocoffinfile, relocdd.Size);

    const uint32_t relocpagebase = ndatrva & ~0xFFFu;
    auto makeentry = [&](uint32_t offinndat) -> uint16_t
        {
            const uint32_t rva = ndatrva + offinndat;
            const uint32_t pageoff = rva - relocpagebase;
            return static_cast<uint16_t>((IMAGE_REL_BASED_DIR64 << 12) | (pageoff & 0xFFF));
        };
    std::vector<uint16_t> entries;
    if (!hasexistingtls)
    {
        entries.push_back(makeentry(tlsoff + 0));
        entries.push_back(makeentry(tlsoff + 8));
        entries.push_back(makeentry(tlsoff + 16));
        entries.push_back(makeentry(tlsoff + 24));
    }
    for (size_t i = 0; i <= existingcbs.size(); ++i)
    {
        entries.push_back(makeentry(cboff + static_cast<uint32_t>(i * 8)));
    }
    if (entries.size() & 1)
    {
        entries.push_back(0);
    }
    if (entries.size() != relocentriespadded)
    {
        std::fprintf(stderr, "reloc entry count mismatch (predicted %u, actual %zu)\n", relocentriespadded, entries.size());
        return 1;
    }

    IMAGE_BASE_RELOCATION br{};
    br.VirtualAddress = relocpagebase;
    br.SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + static_cast<uint32_t>(entries.size() * sizeof(uint16_t));
    std::memcpy(ndatsec.data() + newrelocoff, &br, sizeof(br));
    std::memcpy(ndatsec.data() + newrelocoff + sizeof(br), entries.data(), entries.size() * sizeof(uint16_t));

    IMAGE_SECTION_HEADER nanosh{};
    std::memcpy(nanosh.Name, ".nano", 5);
    nanosh.Misc.VirtualSize = NanoLayout::NanoBytes;
    nanosh.VirtualAddress = nanorva;
    nanosh.SizeOfRawData = Utils::AlignUp(NanoLayout::NanoBytes, filealign);
    nanosh.PointerToRawData = Utils::AlignUp(static_cast<uint32_t>(file.size()), filealign);
    nanosh.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    std::memcpy(&sectable[nsections], &nanosh, sizeof(nanosh));

    IMAGE_SECTION_HEADER ndatsh{};
    std::memcpy(ndatsh.Name, ".ndat", 5);
    ndatsh.Misc.VirtualSize = ndatvirtsize;
    ndatsh.VirtualAddress = ndatrva;
    ndatsh.SizeOfRawData = ndatrawsize;
    ndatsh.PointerToRawData = nanosh.PointerToRawData + nanosh.SizeOfRawData;
    ndatsh.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    std::memcpy(&sectable[nsections + 1], &ndatsh, sizeof(ndatsh));

    if (hasexistingtls)
    {
        const uint64_t newcbva = imagebase + ndatrva + cboff;
        std::memcpy(file.data() + existingtlsfileoff + offsetof(IMAGE_TLS_DIRECTORY64, AddressOfCallBacks), &newcbva, sizeof(newcbva));
    }
    else
    {
        tlsdd.VirtualAddress = ndatrva + tlsoff;
        tlsdd.Size = sizeof(IMAGE_TLS_DIRECTORY64);
    }

    nt->FileHeader.NumberOfSections = nsections + 2;
    nt->OptionalHeader.SizeOfImage = Utils::AlignUp(ndatrva + ndatvirtsize, secalign);
    nt->OptionalHeader.SizeOfInitializedData += nanosh.SizeOfRawData + ndatrawsize;

    const uint32_t oldrelocsize = relocdd.Size;
    relocdd.VirtualAddress = ndatrva + reloccopyoff;
    relocdd.Size = oldrelocsize + br.SizeOfBlock;

    if (file.size() < nanosh.PointerToRawData)
    {
        file.resize(nanosh.PointerToRawData, 0);
    }
    file.insert(file.end(), nanosec.begin(), nanosec.end());
    file.insert(file.end(), ndatsec.begin(), ndatsec.end());

    try
    {
        pe.Save(argv[2]);
    }
    catch (const std::exception& e)
    {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    }

    std::printf("[+] .nano RVA=0x%08X raw=0x%08X vsize=0x%X rsize=0x%X\n", nanorva, nanosh.PointerToRawData, NanoLayout::NanoBytes, nanosh.SizeOfRawData);
    std::printf("shellcode RVA=0x%08X (%zu B)\n", shellcoderva, cfgshell.Size());
    std::printf("tls_cb RVA=0x%08X (%zu B) VA=0x%016llX\n", tlscbrva, tlsshell.Size(), static_cast<unsigned long long>(ourcbva));
    std::printf("count RVA=0x%08X = %zu\n", countrva, registry.size());
    std::printf("build key RVA=0x%08X = 0x%08X\n", buildkeyrva, buildkey32);
    std::printf("table RVA=0x%08X (%zu entries, cap %u)\n", tablerva, registry.size(), (NanoLayout::NanoBytes - NanoLayout::OffTable) / NanoLayout::TableEntrySize);
    std::printf("[+] .ndat RVA=0x%08X raw=0x%08X vsize=0x%X rsize=0x%X\n", ndatrva, ndatsh.PointerToRawData, ndatvirtsize, ndatrawsize);
    std::printf("fake_slot RVA=0x%08X\n", fakeslotrva);
    std::printf("[+] fptr slot VA=0x%016llX (RVA 0x%08X, in section '%.8s'%s)\n", static_cast<unsigned long long>(fptrslotva), fptrslotrva, sectable[fptrsectionidx].Name, fptrsectionwaswritable ? "" : " -- MEM_WRITE added");
    if (hasexistingtls)
    {
        std::printf("[+] TLS dir preserved at RVA 0x%08X; %zu existing callback(s) chained ahead of ours\n", tlsdd.VirtualAddress, existingcbs.size());
    }
    else
    {
        std::printf("[+] TLS dir RVA=0x%08X size=%u (fresh)\n", tlsdd.VirtualAddress, tlsdd.Size);
    }
    std::printf("[+] reloc dir RVA=0x%08X size=%u (was %u; +%u new)\n", relocdd.VirtualAddress, relocdd.Size, oldrelocsize, br.SizeOfBlock);
    if (hadguardcf)
    {
        std::printf("[!] cleared IMAGE_DLLCHARACTERISTICS_GUARD_CF\n");
    }
    return 0;
}