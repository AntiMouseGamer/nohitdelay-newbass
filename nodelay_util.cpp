// nodelay_util.cpp
// Path resolution, INI access, hex codecs and the diagnostic logger.
// Reconstructed from 0x17f0, 0x33d0, 0x40e0, 0x4420, 0x5350, 0x5e10, 0xa9910, 0xa9a50.

#include "nodelay_types.h"

#include <cstdio>
#include <cstring>

namespace nodelay {

// ---------------------------------------------------------------------------
// Globals accessor
// ---------------------------------------------------------------------------
Globals& g() {
    static Globals instance;
    return instance;
}

// ---------------------------------------------------------------------------
// 0x33d0 -- std::string::assign(const char* first, const char* last)
// Constructs a string from an iterator range. Equivalent to:
//     out.assign(first, last);
// ---------------------------------------------------------------------------
static void StringAssignRange(std::string& out, const char* first, const char* last) {
    out.assign(first, static_cast<size_t>(last - first));
}

// ---------------------------------------------------------------------------
// 0xa9910 -- std::string::reserve(size_t)
// Grows capacity when the requested size exceeds the current capacity.
// ---------------------------------------------------------------------------
static void StringReserve(std::string& s, size_t n) {
    if (s.capacity() < n) s.reserve(n);
}

// ---------------------------------------------------------------------------
// 0xa9a50 -- std::string::append(const char* s, size_t n)
// ---------------------------------------------------------------------------
static std::string& StringAppend(std::string& s, const char* data, size_t len) {
    s.append(data, len);
    return s;
}

// ---------------------------------------------------------------------------
// 0x20fd8 -- strlen
// ---------------------------------------------------------------------------
static size_t StrLen(const char* s) { return std::strlen(s); }

// ---------------------------------------------------------------------------
// 0x2fdd0 -- std::string::find_last_of(const char* s, size_t pos, size_t n)
// Used to locate the final path separator so that a sibling file name can be
// appended to the settings directory.
// ---------------------------------------------------------------------------
static size_t FindLastSeparator(const std::string& s) {
    size_t pos = s.find_last_of(kPathSeparators);
    return pos;  // std::string::npos when absent
}

// ---------------------------------------------------------------------------
// 0x40e0 -- getSettingsPath()
//   %LOCALAPPDATA%\NoDelay189\settings.ini
// On environment failure the function still returns the literal
// "NoDelay189.ini" (0xc0221) so callers always receive a usable path.
// ---------------------------------------------------------------------------
std::string GetSettingsPath() {
    char buf[MAX_PATH + 1] = {};          // 0x104 bytes at [rsp+0x60]
    DWORD n = GetEnvironmentVariableA(kEnvLocalAppData, buf, MAX_PATH);

    // `sub eax,1 ; cmp eax,0xd1 ; jbe`  =>  accept 0 .. MAX_PATH chars.
    if (n == 0 || n > MAX_PATH) {
        // Fallback: the embedded legacy file name at 0xc0221.
        std::string fallback;
        StringAssignRange(fallback, kLegacyIniName, kLegacyIniName + StrLen(kLegacyIniName));
        return fallback;
    }

    std::string dir;
    StringAssignRange(dir, buf, buf + StrLen(buf));   // LOCALAPPDATA value

    StringReserve(dir, dir.size() + 0xb);
    StringAppend(dir, kAppDirName, StrLen(kAppDirName));   // "\NoDelay189"

    CreateDirectoryA(dir.c_str(), nullptr);

    StringReserve(dir, dir.size() + 0xd);
    StringAppend(dir, kSettingsFileName, StrLen(kSettingsFileName)); // "\settings.ini"
    return dir;
}

// ---------------------------------------------------------------------------
// 0x4420 -- getDiagnosticLogPath()
//   <directory of settings path>\diagnostic.log
// ---------------------------------------------------------------------------
std::string GetDiagnosticLogPath() {
    std::string settings = GetSettingsPath();

    size_t sep = FindLastSeparator(settings);
    std::string dir;
    if (sep == std::string::npos) {
        dir = settings;                       // no separator: use as-is
    } else {
        // keep everything up to and including the separator
        StringAssignRange(dir, settings.c_str(),
                          settings.c_str() + ((sep + 1 > settings.size()) ? settings.size()
                                                                         : sep + 1));
    }

    StringReserve(dir, dir.size() + 0xe);
    StringAppend(dir, kDiagnosticFileName, StrLen(kDiagnosticFileName)); // "diagnostic.log"
    return dir;
}

// ---------------------------------------------------------------------------
// Settings path cache (.bss std::string at 0xea0a0)
// ---------------------------------------------------------------------------
std::string& SettingsPath() {
    static std::string cached;
    static bool init = false;
    if (!init) {
        cached = GetSettingsPath();
        init = true;
    }
    return cached;
}

// ---------------------------------------------------------------------------
// 0x5e10 -- writeDiagnosticLog(msg)
//   Opens <logdir>\diagnostic.log, appends msg + '\n', closes.
// ---------------------------------------------------------------------------
void WriteDiagnosticLog(const std::string& message) {
    std::string path = GetDiagnosticLogPath();

    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    LARGE_INTEGER sz{};
    if (GetFileSizeEx(h, &sz)) {
        LARGE_INTEGER off{};
        SetFilePointerEx(h, sz, &off, FILE_BEGIN);   // append
    }

    DWORD written = 0;
    if (!message.empty()) {
        WriteFile(h, message.data(), static_cast<DWORD>(message.size()), &written, nullptr);
    }
    WriteFile(h, &kLogNewline, 1, &written, nullptr);  // '\n' (0xc03fb)

    CloseHandle(h);
}

// ---------------------------------------------------------------------------
// 0x5350 -- readIniString(out, file, section, key)
//   GetPrivateProfileStringA with a 0x200-byte scratch buffer and "" default.
// ---------------------------------------------------------------------------
std::string ReadIniString(const std::string& file, const char* section, const char* key) {
    char buf[0x200] = {};
    GetPrivateProfileStringA(section, key, "", buf, 0x200, file.c_str());
    std::string out;
    StringAssignRange(out, buf, buf + StrLen(buf));
    return out;
}

// ---------------------------------------------------------------------------
// 0x5400 -- loadProfiles()
// Reads the built-in Lunar/Badlion sections from profiles.ini. Each enabled
// section contributes one Profile; the first four fields must be non-empty.
// ---------------------------------------------------------------------------
static bool LoadOneProfile(const std::string& file, const char* section,
                           std::vector<Profile>& out) {
    if (GetPrivateProfileIntA(section, kKeyEnabled, 0, file.c_str()) != 1) return false;

    Profile p;
    p.title          = ReadIniString(file, section, kKeyTitle);
    p.mcClass        = ReadIniString(file, section, kKeyMcClass);
    p.mcGetter       = ReadIniString(file, section, kKeyMcGetter);
    p.hitField       = ReadIniString(file, section, kKeyHitField);
    p.hitAlternative = ReadIniString(file, section, kKeyHitAlternative);

    if (p.title.empty() || p.mcClass.empty() || p.mcGetter.empty() || p.hitField.empty()) {
        return false;   // incomplete profile: skipped
    }
    out.push_back(p);   // copied through 0x2180 (element size 0xa0)
    return true;
}

std::vector<Profile> LoadProfiles() {
    std::vector<Profile> profiles;

    std::string path = SettingsPath();
    std::string ini;
    size_t sep = FindLastSeparator(path);
    if (sep == std::string::npos) {
        // fallback literal built from the immediates at 0xc0234:
        //   "profiles" + ".ini"
        ini = kProfilesFileName;
    } else {
        StringAssignRange(ini, path.c_str(), path.c_str() + sep + 1);
        StringAppend(ini, kProfilesFileName, StrLen(kProfilesFileName));
    }

    LoadOneProfile(ini, kSectionLunar,   profiles);
    LoadOneProfile(ini, kSectionBadlion, profiles);
    return profiles;
}

// ---------------------------------------------------------------------------
// 0x17f0 -- hex decoder
//   Converts a hex string into a byte vector. Returns false on any
//   non-hex character or odd length.
// ---------------------------------------------------------------------------
bool HexDecode(const std::string& hex, std::vector<uint8_t>& out) {
    out.clear();
    if (hex.size() % 2 != 0) return false;
    out.reserve(hex.size() / 2);

    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) { out.clear(); return false; }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

// ---------------------------------------------------------------------------
// 0xab92 -- hex encoder
//   Uses the alphabet "0123456789ABCDEF" (immediates 0x3736353433323130 /
//   0x4645444342413938 at 0x3992 / 0xab92).
// ---------------------------------------------------------------------------
std::string HexEncode(const uint8_t* data, size_t len) {
    static const char* kAlphabet = "0123456789ABCDEF";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kAlphabet[data[i] >> 4]);
        out.push_back(kAlphabet[data[i] & 0x0f]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// 0x30680 / 0x30770 -- std::string::find_first_not_of / compare
//   0x30680: find_first_not_of(" \t\r\n", 0)  -> leading-trim helper
//   0x30770: string::compare(pos, n1, s, n2) -> prefix comparison
// ---------------------------------------------------------------------------
size_t FindFirstNotOfWhitespace(const std::string& s) {
    return s.find_first_not_of(kWhitespace);
}

int ComparePrefix(const std::string& s, size_t pos, const char* cmp, size_t n) {
    return s.compare(pos, std::string::npos, cmp, n);
}

// ---------------------------------------------------------------------------
// 0x30770 call sites use this shape: compare the command word against a
// literal of a known length. Convenience wrapper used by the pipe server.
// ---------------------------------------------------------------------------
bool StartsWith(const std::string& s, const char* prefix, size_t n) {
    return s.size() >= n && s.compare(0, n, prefix, n) == 0;
}

}  // namespace nodelay
