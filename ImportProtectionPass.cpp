#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "ImportProtectionPass.h"

#include "DLLHelper/DLLGrabberUtility.h"
#include "DLLHelper/OfficialDLLDownloader.h"
#include "DLLHelper/DLLExportGrabber.h"

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace llvm;

llvm::cl::opt<bool> ImportProtectionEnable("obfimportprotection", llvm::cl::init(true), llvm::cl::desc("Master Toggle"));

static constexpr const char* SystemDir = "C:\\Windows\\System32";
static constexpr unsigned MaxWindowBytes = 16384;
static constexpr int MaxFwdHops = 16;

static const char* const SeedHosts[] = {
    "ntdll.dll", "kernelbase.dll", "win32u.dll", "gdi32full.dll",
    "combase.dll", "sechost.dll", "shcore.dll", "bcrypt.dll", "ucrtbase.dll",
    "kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll",
    "shell32.dll", "shlwapi.dll", "ole32.dll", "oleaut32.dll",
    "ws2_32.dll", "winhttp.dll", "wininet.dll", "msvcrt.dll",
    "crypt32.dll", "psapi.dll", "version.dll", "setupapi.dll",
    "comctl32.dll", "comdlg32.dll", "wintrust.dll", "dbghelp.dll",
    "dxgi.dll", "d3d11.dll", "d3d12.dll",
};
static constexpr unsigned SeedHostsCount = sizeof(SeedHosts) / sizeof(SeedHosts[0]);

static constexpr size_t OutLen = 32;
static constexpr size_t BlockLen = 64;
static constexpr size_t MaxChunkLen = 1024;
static constexpr size_t MaxDepth = 54;

static constexpr uint32_t IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

static constexpr uint8_t MsgSchedule[7][16] = {
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    { 2,  6,  3, 10,  7,  0,  4, 13,  1, 11, 12,  5,  9, 14, 15,  8},
    { 3,  4, 10, 12, 13,  2,  7, 14,  6,  5,  9,  0, 11, 15,  8,  1},
    {10,  7, 12,  9, 14,  3, 13, 15,  4,  0, 11,  2,  5,  8,  1,  6},
    {12, 13,  9, 11, 15, 10, 14,  8,  7,  2,  5,  3,  0,  1,  6,  4},
    { 9, 14, 11,  5,  8, 12, 15,  1, 13,  3,  0, 10,  2,  6,  4,  7},
    {11, 15,  5,  0,  1,  9,  8,  6, 14, 10,  2, 12,  3,  4,  7, 13},
};

static constexpr uint8_t FlagChunkStart = 1 << 0;
static constexpr uint8_t FlagChunkEnd = 1 << 1;
static constexpr uint8_t FlagParent = 1 << 2;
static constexpr uint8_t FlagRoot = 1 << 3;

static inline uint32_t Load32(const uint8_t* p)
{
    uint32_t w;
    std::memcpy(&w, p, 4);
    return w;
}

static inline void Store32(uint8_t* p, uint32_t w)
{
    std::memcpy(p, &w, 4);
}

static inline uint32_t Rotr32(uint32_t w, unsigned c)
{
    return (w >> c) | (w << ((32 - c) & 31));
}

static inline void GMix(uint32_t* s, size_t a, size_t b, size_t c, size_t d, uint32_t mx, uint32_t my)
{
    s[a] = s[a] + s[b] + mx;
    s[d] = Rotr32(s[d] ^ s[a], 16);
    s[c] = s[c] + s[d];
    s[b] = Rotr32(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my;
    s[d] = Rotr32(s[d] ^ s[a], 8);
    s[c] = s[c] + s[d];
    s[b] = Rotr32(s[b] ^ s[c], 7);
}

static void RoundFn(uint32_t state[16], const uint32_t msg[16], unsigned r)
{
    const uint8_t* sch = MsgSchedule[r];
    GMix(state, 0, 4, 8, 12, msg[sch[0]], msg[sch[1]]);
    GMix(state, 1, 5, 9, 13, msg[sch[2]], msg[sch[3]]);
    GMix(state, 2, 6, 10, 14, msg[sch[4]], msg[sch[5]]);
    GMix(state, 3, 7, 11, 15, msg[sch[6]], msg[sch[7]]);
    GMix(state, 0, 5, 10, 15, msg[sch[8]], msg[sch[9]]);
    GMix(state, 1, 6, 11, 12, msg[sch[10]], msg[sch[11]]);
    GMix(state, 2, 7, 8, 13, msg[sch[12]], msg[sch[13]]);
    GMix(state, 3, 4, 9, 14, msg[sch[14]], msg[sch[15]]);
}

static void CompressPre(uint32_t state[16], const uint32_t cv[8], const uint8_t block[BlockLen], uint8_t blocklen, uint64_t counter, uint8_t flags)
{
    uint32_t m[16];
    for (int i = 0; i < 16; ++i) m[i] = Load32(block + i * 4);
    for (int i = 0; i < 8; ++i) state[i] = cv[i];
    state[8] = IV[0]; state[9] = IV[1]; state[10] = IV[2]; state[11] = IV[3];
    state[12] = static_cast<uint32_t>(counter);
    state[13] = static_cast<uint32_t>(counter >> 32);
    state[14] = static_cast<uint32_t>(blocklen);
    state[15] = static_cast<uint32_t>(flags);
    for (unsigned r = 0; r < 7; ++r) RoundFn(state, m, r);
}

static void CompressInPlace(uint32_t cv[8], const uint8_t block[BlockLen], uint8_t blocklen, uint64_t counter, uint8_t flags)
{
    uint32_t s[16];
    CompressPre(s, cv, block, blocklen, counter, flags);
    for (int i = 0; i < 8; ++i) cv[i] = s[i] ^ s[i + 8];
}

static void CompressXof(const uint32_t cv[8], const uint8_t block[BlockLen], uint8_t blocklen, uint64_t counter, uint8_t flags, uint8_t out[64])
{
    uint32_t s[16];
    CompressPre(s, cv, block, blocklen, counter, flags);
    for (int i = 0; i < 8; ++i)
    {
        Store32(out + i * 4, s[i] ^ s[i + 8]);
        Store32(out + (i + 8) * 4, s[i + 8] ^ cv[i]);
    }
}

struct Output
{
    uint32_t inputcv[8];
    uint64_t counter;
    uint8_t block[BlockLen];
    uint8_t blocklen;
    uint8_t flags;
};

static void OutputChainingValue(const Output& o, uint8_t outcv[32])
{
    uint32_t cvwords[8];
    std::memcpy(cvwords, o.inputcv, 32);
    CompressInPlace(cvwords, o.block, o.blocklen, o.counter, o.flags);
    for (int i = 0; i < 8; ++i) Store32(outcv + i * 4, cvwords[i]);
}

static void OutputRootBytes(const Output& o, uint8_t* out, size_t outlen)
{
    uint64_t counter = 0;
    uint8_t wide[64];
    while (outlen > 0)
    {
        CompressXof(o.inputcv, o.block, o.blocklen, counter, o.flags | FlagRoot, wide);
        size_t take = outlen < 64 ? outlen : 64;
        std::memcpy(out, wide, take);
        out += take;
        outlen -= take;
        ++counter;
    }
}

struct ChunkState
{
    uint32_t cv[8];
    uint64_t chunkcounter;
    uint8_t buf[BlockLen];
    uint8_t buflen;
    uint8_t blockscompressed;
    uint8_t flags;
};

static void ChunkInit(ChunkState& s, const uint32_t key[8], uint8_t flags)
{
    std::memcpy(s.cv, key, 32);
    s.chunkcounter = 0;
    std::memset(s.buf, 0, BlockLen);
    s.buflen = 0;
    s.blockscompressed = 0;
    s.flags = flags;
}

static void ChunkReset(ChunkState& s, const uint32_t key[8], uint64_t newchunkcounter)
{
    std::memcpy(s.cv, key, 32);
    s.chunkcounter = newchunkcounter;
    std::memset(s.buf, 0, BlockLen);
    s.buflen = 0;
    s.blockscompressed = 0;
}

static inline size_t ChunkLen(const ChunkState& s)
{
    return BlockLen * static_cast<size_t>(s.blockscompressed) + static_cast<size_t>(s.buflen);
}

static inline uint8_t ChunkStartFlag(const ChunkState& s)
{
    return s.blockscompressed == 0 ? FlagChunkStart : 0;
}

static size_t ChunkFillBuf(ChunkState& s, const uint8_t* in, size_t inlen)
{
    size_t take = BlockLen - static_cast<size_t>(s.buflen);
    if (take > inlen) take = inlen;
    std::memcpy(s.buf + s.buflen, in, take);
    s.buflen += static_cast<uint8_t>(take);
    return take;
}

static void ChunkUpdate(ChunkState& s, const uint8_t* in, size_t inlen)
{
    if (s.buflen > 0)
    {
        size_t take = ChunkFillBuf(s, in, inlen);
        in += take;
        inlen -= take;
        if (inlen > 0)
        {
            CompressInPlace(s.cv, s.buf, BlockLen, s.chunkcounter, s.flags | ChunkStartFlag(s));
            s.blockscompressed++;
            s.buflen = 0;
            std::memset(s.buf, 0, BlockLen);
        }
    }
    while (inlen > BlockLen)
    {
        CompressInPlace(s.cv, in, BlockLen, s.chunkcounter, s.flags | ChunkStartFlag(s));
        s.blockscompressed++;
        in += BlockLen;
        inlen -= BlockLen;
    }
    ChunkFillBuf(s, in, inlen);
}

static Output ChunkOutput(const ChunkState& s)
{
    Output o;
    std::memcpy(o.inputcv, s.cv, 32);
    std::memcpy(o.block, s.buf, BlockLen);
    o.blocklen = s.buflen;
    o.counter = s.chunkcounter;
    o.flags = s.flags | ChunkStartFlag(s) | FlagChunkEnd;
    return o;
}

static Output ParentOutput(const uint8_t block[BlockLen], const uint32_t key[8], uint8_t flags)
{
    Output o;
    std::memcpy(o.inputcv, key, 32);
    std::memcpy(o.block, block, BlockLen);
    o.blocklen = BlockLen;
    o.counter = 0;
    o.flags = flags | FlagParent;
    return o;
}

struct Hasher
{
    uint32_t key[8];
    ChunkState chunk;
    uint8_t cvstacklen;
    uint8_t cvstack[(MaxDepth + 1) * 32];
};

static void HasherInit(Hasher& h)
{
    std::memcpy(h.key, IV, 32);
    ChunkInit(h.chunk, IV, 0);
    h.cvstacklen = 0;
}

static inline int Popcount64(uint64_t x)
{
    int c = 0;
    while (x)
    {
        c += static_cast<int>(x & 1);
        x >>= 1;
    }
    return c;
}

static void MergeCvStack(Hasher& h, uint64_t totallen)
{
    size_t target = static_cast<size_t>(Popcount64(totallen));
    while (static_cast<size_t>(h.cvstacklen) > target)
    {
        uint8_t* parentnode = &h.cvstack[(h.cvstacklen - 2) * 32];
        Output po = ParentOutput(parentnode, h.key, h.chunk.flags);
        OutputChainingValue(po, parentnode);
        h.cvstacklen--;
    }
}

static void PushCv(Hasher& h, const uint8_t newcv[32], uint64_t chunkcounter)
{
    MergeCvStack(h, chunkcounter);
    std::memcpy(&h.cvstack[h.cvstacklen * 32], newcv, 32);
    h.cvstacklen++;
}

static void HasherUpdate(Hasher& h, const uint8_t* in, size_t inlen)
{
    while (inlen > 0)
    {
        if (ChunkLen(h.chunk) == MaxChunkLen)
        {
            uint8_t cv[32];
            Output o = ChunkOutput(h.chunk);
            OutputChainingValue(o, cv);
            uint64_t totalchunks = h.chunk.chunkcounter + 1;
            PushCv(h, cv, totalchunks);
            ChunkReset(h.chunk, h.key, totalchunks);
        }
        size_t want = MaxChunkLen - ChunkLen(h.chunk);
        size_t take = inlen < want ? inlen : want;
        ChunkUpdate(h.chunk, in, take);
        in += take;
        inlen -= take;
    }
}

static void HasherFinalize(const Hasher& h, uint8_t* out, size_t outlen)
{
    if (h.cvstacklen == 0)
    {
        Output o = ChunkOutput(h.chunk);
        OutputRootBytes(o, out, outlen);
        return;
    }

    Output o;
    size_t cvsremaining;
    if (ChunkLen(h.chunk) > 0)
    {
        cvsremaining = h.cvstacklen;
        o = ChunkOutput(h.chunk);
    }
    else
    {
        cvsremaining = static_cast<size_t>(h.cvstacklen) - 2;
        uint8_t block[BlockLen];
        std::memcpy(block, &h.cvstack[cvsremaining * 32], BlockLen);
        o = ParentOutput(block, h.key, h.chunk.flags);
    }
    while (cvsremaining > 0)
    {
        cvsremaining--;
        uint8_t block[BlockLen];
        std::memcpy(block, &h.cvstack[cvsremaining * 32], 32);
        uint8_t rightcv[32];
        OutputChainingValue(o, rightcv);
        std::memcpy(block + 32, rightcv, 32);
        o = ParentOutput(block, h.key, h.chunk.flags);
    }
    OutputRootBytes(o, out, outlen);
}

// This entire BLAKE3 implementation MUST stay byte-identical with IntegrityRuntime.cpp (and the stamper's inlined copy) — the pass XORs h_expected into enc_rva at obf time and the runtime XORs its own hash out at every call site, so any divergence here makes every protected call land at garbage
static uint64_t HashLow64(const uint8_t* data, size_t len)
{
    Hasher h;
    HasherInit(h);
    HasherUpdate(h, data, len);
    uint8_t out[OutLen];
    HasherFinalize(h, out, OutLen);
    uint64_t r;
    std::memcpy(&r, out, sizeof(r));
    return r;
}

static std::string ToLowerASCII(std::string s)
{
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

static bool IsAPISet(const std::string& n)
{
    return n.rfind("api-ms-", 0) == 0 || n.rfind("ext-ms-", 0) == 0;
}

static std::string UnmangleCName(StringRef n)
{
    std::string s = n.str();
    if (!s.empty() && s[0] == '_') s.erase(0, 1);
    const size_t at = s.find('@');
    if (at != std::string::npos) s.resize(at);
    return s;
}

static bool IsEligibleDLLImport(const Function& f)
{
    if (!f.isDeclaration()) return false;
    if (f.isIntrinsic()) return false;
    if (!f.hasDLLImportStorageClass()) return false;
    if (f.getLinkage() != GlobalValue::ExternalLinkage) return false;
    if (f.isVarArg()) return false;
    return true;
}

struct HostCache
{
    bool sourced = false;
    std::wstring canonicalpath;
    DLLExportGrabber::ExportTable exports;
};

static bool SourceHost(const std::string& host, HostCache& out)
{
    out.sourced = false;
    if (IsAPISet(host)) return false;

    std::filesystem::path syspath(SystemDir);
    syspath /= host;

    DLLGrabberUtility::DllIdentity id;
    std::wstring err;
    if (!DLLGrabberUtility::Instance().GrabIdentity(syspath.wstring(), id, err)) return false;

    OfficialDllDownloader::DownloadResult dr;
    if (OfficialDllDownloader::Instance().TryGetCachedDll(id.DllName, id.TimeDateStamp, id.SizeOfImage, dr) && dr.Success)
    {
        out.canonicalpath = dr.OutputPath;
    }
    else if (OfficialDllDownloader::Instance().DownloadDll(id.DllName, id.TimeDateStamp, id.SizeOfImage, dr) && dr.Success)
    {
        out.canonicalpath = dr.OutputPath;
    }
    else
    {
        return false;
    }

    if (!DLLExportGrabber::Instance().GrabExports(out.canonicalpath, out.exports, err)) return false;
    out.sourced = true;
    return true;
}

static bool ResolveImport(const std::string& firsthost, const std::string& firstname, std::map<std::string, HostCache>& hosts, std::string& outhost, uint32_t& outrva)
{
    std::string host = firsthost;
    std::string name = firstname;
    for (int hop = 0; hop <= MaxFwdHops; ++hop)
    {
        if (IsAPISet(host)) return false;
        auto it = hosts.find(host);
        if (it == hosts.end())
        {
            HostCache hs;
            SourceHost(host, hs);
            auto ins = hosts.emplace(host, std::move(hs));
            it = ins.first;
        }
        if (!it->second.sourced) return false;
        const DLLExportGrabber::ExportTable& t = it->second.exports;
        auto ni = t.NameToIndex.find(name);
        if (ni == t.NameToIndex.end()) return false;
        const DLLExportGrabber::ExportEntry& e = t.Entries[ni->second];
        if (!e.Forwarded)
        {
            outhost = host;
            outrva = e.Rva;
            return true;
        }
        if (e.ForwardApiset) return false;
        if (e.ForwardByOrdinal) return false;
        if (e.ForwardDll.empty() || e.ForwardName.empty()) return false;
        host = e.ForwardDll;
        name = e.ForwardName;
    }
    return false;
}

static bool GetExportByteSpan(const DLLExportGrabber::ExportTable& t, uint32_t rva, uint32_t cap, uint32_t& out)
{
    uint32_t next = UINT32_MAX;
    for (const auto& e : t.Entries)
    {
        if (e.Forwarded) continue;
        if (e.Rva == 0) continue;
        if (e.Rva > rva && e.Rva < next) next = e.Rva;
    }
    if (next == UINT32_MAX) return false;
    uint32_t len = next - rva;
    if (len == 0) return false;
    if (len > cap) len = cap;
    out = len;
    return true;
}

#ifdef _WIN32
static bool ReadCodeBytes(const std::wstring& dllpath, uint32_t rva, uint32_t length, std::vector<uint8_t>& out)
{
    out.clear();
    HANDLE file = CreateFileW(dllpath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fs{};
    if (!GetFileSizeEx(file, &fs) || fs.QuadPart < 0x1000)
    {
        CloseHandle(file);
        return false;
    }
    HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mapping)
    {
        CloseHandle(file);
        return false;
    }
    auto* base = reinterpret_cast<const uint8_t*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
    if (!base)
    {
        CloseHandle(mapping);
        CloseHandle(file);
        return false;
    }

    auto cleanup = [&]()
    {
        UnmapViewOfFile(base);
        CloseHandle(mapping);
        CloseHandle(file);
    };

    const uint64_t fsize = static_cast<uint64_t>(fs.QuadPart);
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || static_cast<uint64_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > fsize)
    {
        cleanup();
        return false;
    }
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        cleanup();
        return false;
    }

    const uint16_t seccount = nt->FileHeader.NumberOfSections;
    const uint64_t sectbloff = static_cast<uint64_t>(dos->e_lfanew) + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
    if (sectbloff + static_cast<uint64_t>(seccount) * sizeof(IMAGE_SECTION_HEADER) > fsize)
    {
        cleanup();
        return false;
    }
    auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(base + sectbloff);

    uint64_t off = 0;
    uint32_t sectionendrva = 0;
    for (uint16_t i = 0; i < seccount; ++i)
    {
        const uint32_t span = (std::max)(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData);
        if (rva >= sections[i].VirtualAddress && rva - sections[i].VirtualAddress < span)
        {
            off = static_cast<uint64_t>(sections[i].PointerToRawData) + (rva - sections[i].VirtualAddress);
            sectionendrva = sections[i].VirtualAddress + span;
            break;
        }
    }
    if (!off)
    {
        cleanup();
        return false;
    }

    uint32_t effective = length;
    if (sectionendrva > rva && effective > sectionendrva - rva) effective = sectionendrva - rva;
    if (off + effective > fsize)
    {
        if (fsize <= off)
        {
            cleanup();
            return false;
        }
        effective = static_cast<uint32_t>(fsize - off);
    }
    if (effective == 0)
    {
        cleanup();
        return false;
    }

    out.resize(effective);
    std::memcpy(out.data(), base + off, effective);
    cleanup();
    return true;
}
#else
static bool ReadCodeBytes(const std::wstring&, uint32_t, uint32_t, std::vector<uint8_t>&)
{
    return false;
}
#endif

static bool HasAnnotationTag(Function& f, const char* tag)
{
    Module* m = f.getParent();
    GlobalVariable* ga = m->getGlobalVariable("llvm.global.annotations");
    if (!ga) return false;

    ConstantArray* ca = dyn_cast<ConstantArray>(ga->getOperand(0));
    if (!ca) return false;

    for (unsigned i = 0; i < ca->getNumOperands(); ++i)
    {
        ConstantStruct* cs = dyn_cast<ConstantStruct>(ca->getOperand(i));
        if (!cs) continue;
        if (cs->getOperand(0)->stripPointerCasts() != &f) continue;

        auto* strgv = dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!strgv || !strgv->hasInitializer()) continue;

        auto* cds = dyn_cast<ConstantDataSequential>(strgv->getInitializer());
        if (!cds || !cds->isString()) continue;

        if (cds->getAsCString() == tag) return true;
    }
    return false;
}

static bool HasImportProtAnnotation(Function& f)
{
    return HasAnnotationTag(f, "importprot");
}

static bool HasNoImportProtAnnotation(Function& f)
{
    return HasAnnotationTag(f, "noimportprot");
}

static bool WantsImportProt(Function& f)
{
    if (HasNoImportProtAnnotation(f)) return false;
    return HasImportProtAnnotation(f);
}

static std::unordered_map<std::string, GlobalVariable*> HostNameGVs;

static GlobalVariable* GetOrCreateHostNameGV(Module& m, const std::string& host)
{
    auto it = HostNameGVs.find(host);
    if (it != HostNameGVs.end()) return it->second;
    LLVMContext& c = m.getContext();
    Constant* name = ConstantDataArray::getString(c, host, true);
    GlobalVariable* gv = new GlobalVariable(m, name->getType(), true, GlobalValue::PrivateLinkage, name, "__ip_host_name");
    gv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    HostNameGVs[host] = gv;
    return gv;
}

static FunctionCallee GetModuleHandleADecl(Module& m)
{
    LLVMContext& c = m.getContext();
    PointerType* ptrty = PointerType::get(c, 0);
    FunctionType* ft = FunctionType::get(ptrty, {ptrty}, false);
    FunctionCallee cal = m.getOrInsertFunction("GetModuleHandleA", ft);
    if (Function* f = dyn_cast<Function>(cal.getCallee()))
    {
        f->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
        f->setLinkage(GlobalValue::ExternalLinkage);
    }
    return cal;
}

static Function* GetOrCreateHashHelper(Module& m)
{
    if (Function* existing = m.getFunction("IntegrityHashWindow")) return existing;
    LLVMContext& c = m.getContext();
    Type* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);
    PointerType* ptrty = PointerType::get(c, 0);
    FunctionType* fty = FunctionType::get(i64, {ptrty, i32}, false);
    Function* f = Function::Create(fty, GlobalValue::ExternalLinkage, "IntegrityHashWindow", &m);
    f->addFnAttr(Attribute::NoInline);
    f->addFnAttr(Attribute::NoUnwind);
    f->addFnAttr(Attribute::WillReturn);
    return f;
}

static void PinImportIAT(Module& m, Function* callee)
{
    LLVMContext& c = m.getContext();
    const std::string pinname = "__ip_pin_" + callee->getName().str();
    if (m.getGlobalVariable(pinname)) return;
    GlobalVariable* pin = new GlobalVariable(m, PointerType::get(c, 0), true, GlobalValue::PrivateLinkage, callee, pinname);
    pin->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
    appendToUsed(m, {pin});
}

struct Resolved
{
    std::string host;
    uint32_t rva;
    uint32_t length;
    uint64_t hexpected;
};

struct SiteInfo
{
    CallBase* call;
    Function* callee;
    std::string host;
    uint32_t rva;
    uint32_t length;
    uint64_t hexpected;
};

bool RunImportProtection(Module& m)
{
    if (!ImportProtectionEnable) return false;

    HostNameGVs.clear();

    LLVMContext& c = m.getContext();
    Type* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);
    PointerType* ptrty = PointerType::get(c, 0);

    std::map<std::string, HostCache> hosts;
    DenseMap<Function*, Resolved> resolvedmap;

    for (Function& f : m)
    {
        if (!IsEligibleDLLImport(f)) continue;
        const std::string cname = UnmangleCName(f.getName());

        for (unsigned s = 0; s < SeedHostsCount; ++s)
        {
            const std::string host = SeedHosts[s];
            auto it = hosts.find(host);
            if (it == hosts.end())
            {
                HostCache hc;
                SourceHost(host, hc);
                auto ins = hosts.emplace(host, std::move(hc));
                it = ins.first;
            }
            if (!it->second.sourced) continue;
            if (!it->second.exports.NameToIndex.count(cname)) continue;

            std::string termhost;
            uint32_t termrva = 0;
            if (!ResolveImport(host, cname, hosts, termhost, termrva)) continue;

            HostCache& th = hosts[termhost];
            uint32_t length = 0;
          
            if (!GetExportByteSpan(th.exports, termrva, MaxWindowBytes, length)) continue;

            std::vector<uint8_t> bytes;
            if (!ReadCodeBytes(th.canonicalpath, termrva, length, bytes) || bytes.empty()) continue;

            uint64_t hexpected = HashLow64(bytes.data(), bytes.size());
            resolvedmap[&f] = { termhost, termrva, static_cast<uint32_t>(bytes.size()), hexpected };
            break;
        }
    }

    if (resolvedmap.empty()) return false;

    std::unordered_map<Function*, std::vector<SiteInfo>> perfnsites;

    for (Function& f : m)
    {
        if (f.isDeclaration()) continue;
        if (!WantsImportProt(f)) continue;

        for (Instruction& i : instructions(f))
        {
            auto* cb = dyn_cast<CallBase>(&i);
            if (!cb) continue;
            if (cb->isInlineAsm()) continue;
            Function* callee = cb->getCalledFunction();
            if (!callee) continue;
            auto rm = resolvedmap.find(callee);
            if (rm == resolvedmap.end()) continue;

           
            if (isa<InvokeInst>(cb)) continue;

            SiteInfo si;
            si.call = cb;
            si.callee = callee;
            si.host = rm->second.host;
            si.rva = rm->second.rva;
            si.length = rm->second.length;
            si.hexpected = rm->second.hexpected;
            perfnsites[&f].push_back(si);
        }
    }

    if (perfnsites.empty()) return false;

    FunctionCallee getmoda = GetModuleHandleADecl(m);
    Function* hasher = GetOrCreateHashHelper(m);

    bool mutated = false;

    for (auto& kv : perfnsites)
    {
        Function* f = kv.first;
        std::vector<SiteInfo>& sites = kv.second;

        std::vector<std::string> orderedhosts;
        std::unordered_map<std::string, uint32_t> hostslot;
        for (const SiteInfo& si : sites)
        {
            if (!hostslot.count(si.host))
            {
                hostslot[si.host] = static_cast<uint32_t>(orderedhosts.size());
                orderedhosts.push_back(si.host);
            }
        }
        const uint32_t n = static_cast<uint32_t>(orderedhosts.size());

        BasicBlock& entry = f->getEntryBlock();
        IRBuilder<> eb(&*entry.getFirstInsertionPt());

        AllocaInst* tbl = eb.CreateAlloca(i64, ConstantInt::get(i64, static_cast<uint64_t>(n)), "IPTbl");
        tbl->setAlignment(Align(8));

        for (uint32_t k = 0; k < n; ++k)
        {
            const std::string& host = orderedhosts[k];
            GlobalVariable* hname = GetOrCreateHostNameGV(m, host);
            Value* h = eb.CreateCall(getmoda, {hname}, "IPHandle");
            Value* hi = eb.CreatePtrToInt(h, i64, "IPHandleInt");
            Value* slot = eb.CreateGEP(i64, tbl, ConstantInt::get(i64, static_cast<uint64_t>(k)), "IPSlot");
            eb.CreateStore(hi, slot);
        }

        for (const SiteInfo& si : sites)
        {
            PinImportIAT(m, si.callee);

            const uint32_t k = hostslot[si.host];
            IRBuilder<> sb(si.call);

            Value* slot = sb.CreateGEP(i64, tbl, ConstantInt::get(i64, static_cast<uint64_t>(k)), "IPSlot");
            Value* base = sb.CreateLoad(i64, slot, "IPBase");

            Value* hinta = sb.CreateAdd(base, ConstantInt::get(i64, static_cast<uint64_t>(si.rva)), "IPHint");
            Value* hintp = sb.CreateIntToPtr(hinta, ptrty, "IPHintP");

            Value* hrt = sb.CreateCall(hasher, {hintp, ConstantInt::get(i32, static_cast<uint64_t>(si.length))}, "IPHashRT");

           
            uint64_t encrva = static_cast<uint64_t>(si.rva) ^ si.hexpected;
            Value* drva = sb.CreateXor(ConstantInt::get(i64, encrva), hrt, "IPDRVA");

            Value* calla = sb.CreateAdd(base, drva, "IPCallAddr");
            Value* fp = sb.CreateIntToPtr(calla, ptrty, "IPFP");
            si.call->setCalledOperand(fp);

            mutated = true;
        }
    }

    return mutated;
}

PreservedAnalyses ImportProtectionPass::run(Module& m, ModuleAnalysisManager&)
{
    return RunImportProtection(m) ? PreservedAnalyses::none() : PreservedAnalyses::all();
}