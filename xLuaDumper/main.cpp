#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>

struct lua_State;
typedef int (__cdecl *lua_Writer)(lua_State* L, const void* p, size_t sz, void* ud);

#define LUA_FUNC(RET, NAME, ...) \
  typedef RET (__cdecl * _##NAME##F)(__VA_ARGS__); \
  _##NAME##F NAME = nullptr;

static std::string format_winerr(DWORD err) {
    LPSTR buf = nullptr;
    DWORD n = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, 0, (LPSTR)&buf, 0, nullptr);
    std::string s = (n && buf) ? std::string(buf) : std::string("Unknown error");
    if (buf) LocalFree(buf);
    return s;
}

struct PEInfo {
    bool is_pe = false;
    WORD machine = 0;        // IMAGE_FILE_MACHINE_*
    WORD magic = 0;          // 0x10B (PE32) / 0x20B (PE32+)
    std::string machineStr;
    std::string magicStr;
};

static PEInfo read_pe_info(const char* path) {
    PEInfo info;
    std::ifstream f(path, std::ios::binary);
    if (!f) return info;

    IMAGE_DOS_HEADER dos{};
    f.read((char*)&dos, sizeof(dos));
    if (!f || dos.e_magic != 0x5A4D) return info; // 'MZ'

    f.seekg(dos.e_lfanew, std::ios::beg);
    DWORD sig = 0; f.read((char*)&sig, sizeof(sig));
    if (!f || sig != 0x4550) return info; // 'PE\0\0'

    IMAGE_FILE_HEADER fh{};
    f.read((char*)&fh, sizeof(fh));
    IMAGE_OPTIONAL_HEADER32 oh32{};
    f.read((char*)&oh32, sizeof(oh32));
    info.is_pe = true;
    info.machine = fh.Machine;
    info.magic   = oh32.Magic;

    switch (info.machine) {
        case 0x014c: info.machineStr = "x86 (IMAGE_FILE_MACHINE_I386)"; break;
        case 0x8664: info.machineStr = "x64 (IMAGE_FILE_MACHINE_AMD64)"; break;
        case 0x01c4: info.machineStr = "ARMv7"; break;
        case 0xAA64: info.machineStr = "ARM64"; break;
        default:     info.machineStr = "Unknown: " + std::to_string(info.machine); break;
    }
    if (info.magic == 0x10B) info.magicStr = "PE32";
    else if (info.magic == 0x20B) info.magicStr = "PE32+ (x64)";
    else info.magicStr = "Unknown: 0x" + std::to_string(info.magic);
    return info;
}

// Enumerasi ekspor dengan LoadLibraryEx(DONT_RESOLVE_DLL_REFERENCES)
static std::vector<std::string> list_exports_noresolve(const char* full) {
    std::vector<std::string> names;
    HMODULE h = LoadLibraryExA(full, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) return names;

    // Walk export directory
    auto base = (uint8_t*)h;
    auto dos = (IMAGE_DOS_HEADER*)base;
    auto nt  = (IMAGE_NT_HEADERS*)((uint8_t*)base + dos->e_lfanew);
    auto& opt = nt->OptionalHeader;
    DWORD rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rva) { FreeLibrary(h); return names; }

    auto expDir = (IMAGE_EXPORT_DIRECTORY*)((uint8_t*)base + rva);
    DWORD* nameRVAs = (DWORD*)((uint8_t*)base + expDir->AddressOfNames);
    for (DWORD i = 0; i < expDir->NumberOfNames; ++i) {
        const char* nm = (const char*)base + nameRVAs[i];
        if (nm) names.emplace_back(nm);
    }
    FreeLibrary(h);
    return names;
}

static HMODULE safeLoadDll(const char* path, std::string& fullOut) {
    char full[MAX_PATH];
    DWORD len = GetFullPathNameA(path, MAX_PATH, full, nullptr);
    if (!len || len >= MAX_PATH) {
        std::cerr << "[xLuaDumper-debug] Bad path: " << path << "\n";
        return nullptr;
    }
    fullOut = full;

    // Pastikan search path modern
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    HMODULE h = LoadLibraryExA(
        full, nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
    );
    if (!h) {
        DWORD e = GetLastError();
        std::cerr << "[xLuaDumper-debug] LoadLibraryEx failed (" << e << "): "
                  << format_winerr(e) << "Path: " << full << "\n";
    }
    return h;
}

template<typename T>
static void loadFunc(HMODULE dll, T& fn, const char* name) {
    fn = (T)GetProcAddress(dll, name);
    std::cerr << "  GetProcAddress(\"" << name << "\"): " << (fn ? "OK" : "NOT FOUND") << "\n";
}

static int writer(lua_State* /*L*/, const void* p, size_t sz, void* ud) {
    ((std::ofstream*)ud)->write((const char*)p, sz);
    return 0;
}

int main(int argc, char* argv[]) {
    std::cout << "=== xLuaDumper-debug ===\n";
#if defined(_WIN64)
    std::cout << "Build arch: x64\n";
#else
    std::cout << "Build arch: x86\n";
#endif

    if (argc < 2) {
        std::cout << "Usage: xLuaDumper-debug.exe <Dll> [Lua=opcode.lua] [Out=out.luac]\n";
        return 0;
    }

    const char* dllPath = argv[1];

    // 1) PE quick check
    auto info = read_pe_info(dllPath);
    std::cout << "[PE] is_pe=" << (info.is_pe ? "yes" : "no")
              << " machine=" << info.machineStr
              << " magic=" << info.magicStr << "\n";

    if (!info.is_pe) {
        std::cout << "=> Bukan PE Windows DLL (mungkin .so yang di-rename). Stop.\n";
        return 1;
    }

    std::string full;
    HMODULE dll = safeLoadDll(dllPath, full);

    // 2) Kalau gagal load, tetap list exports via no-resolve
    if (!dll) {
        std::cout << "[Info] Coba enumerasi export tanpa resolve dependencies...\n";
        auto exps = list_exports_noresolve(full.c_str());
        std::cout << "  Exports found: " << exps.size() << "\n";
        size_t shown = 0;
        for (auto& n : exps) {
            if (shown++ >= 50) { std::cout << "  ... (truncated)\n"; break; }
            std::cout << "    " << n << "\n";
        }
        std::cout << "=> Perbaiki error load dulu (bitness / dependency). Lihat pesan di atas.\n";
        return 1;
    }

    std::cout << "[OK] DLL loaded: " << full << "\n";

    // 3) Cek simbol Lua inti
    LUA_FUNC(void, lua_close, lua_State* L);
    LUA_FUNC(void, lua_settop, lua_State* L, int index);
    LUA_FUNC(int, lua_dump, lua_State* L, lua_Writer writer, void* data, int strip);
    LUA_FUNC(lua_State*, luaL_newstate, void);
    LUA_FUNC(int, luaL_loadfilex, lua_State* L, const char* file, const char* mode);

    std::cout << "[Check] Resolving Lua symbols...\n";
    loadFunc(dll, lua_close,     "lua_close");
    loadFunc(dll, lua_settop,    "lua_settop");
    loadFunc(dll, lua_dump,      "lua_dump");
    loadFunc(dll, luaL_newstate, "luaL_newstate");
    loadFunc(dll, luaL_loadfilex,"luaL_loadfilex");

    bool hasAll =
        lua_close && lua_settop && lua_dump && luaL_newstate && luaL_loadfilex;

    if (!hasAll) {
        std::cout << "=> Tidak semua simbol Lua tersedia di DLL ini.\n"
                     "   Mungkin ini bukan build yang mengekspor API Lua standar.\n";
        // Tetap keluar dengan kode error ringan supaya kamu tahu ini masalah simbol.
        return 2;
    }

    // 4) Tes minimal pipeline dump
    const char* luaFile = (argc >= 3) ? argv[2] : "opcode.lua";
    const char* outPath = (argc >= 4) ? argv[3] : "out.luac";

    std::cout << "[Run] luaL_newstate -> luaL_loadfilex('" << luaFile << "') -> lua_dump('" << outPath << "')\n";
    lua_State* L = luaL_newstate();
    if (!L) { std::cerr << "luaL_newstate failed\n"; return 3; }

    if (luaL_loadfilex(L, luaFile, nullptr)) {
        std::cerr << "Failed to load lua: " << luaFile << "\n";
        lua_close(L);
        return 4;
    }

    std::ofstream of(outPath, std::ios::binary);
    if (!of) {
        std::cerr << "Failed to open output: " << outPath << "\n";
        lua_close(L);
        return 5;
    }

    if (lua_dump(L, writer, &of, 1)) {
        std::cerr << "Failed to dump lua\n";
        of.close();
        lua_close(L);
        return 6;
    }
    of.close();
    lua_close(L);

    std::cout << "[Success] " << luaFile << " => " << outPath << " via " << full << "\n";
    return 0;
}
