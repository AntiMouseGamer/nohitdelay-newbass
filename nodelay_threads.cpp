// nodelay_threads.cpp
// DllMain, the control thread (0x58e0) and the JVM worker thread (0x60d0).

#include "nodelay_types.h"

#include <jni.h>

#include <atomic>
#include <string>
#include <vector>

namespace nodelay {

// Forward declarations from the other units.
std::string GetSettingsPath();
std::string GetDiagnosticLogPath();
std::string GetDeviceId();
std::vector<Profile> LoadProfiles();
std::vector<std::string> EnumerateClassLoaders(JNIEnv* env);
bool ResolveProfile(JNIEnv* env, const std::vector<Profile>& profiles,
                    JniBinding& out, std::string& err);

// ---------------------------------------------------------------------------
// TLS callbacks 0x16a70 / 0x16aa0
// These run before DllMain. They only establish the CRT TLS state; no
// application logic lives here.
// ---------------------------------------------------------------------------
#if defined(_MSC_VER)
#pragma section(".CRT$XLB", long, read)
#endif

// ---------------------------------------------------------------------------
// 0x58e0 -- control thread
//
//   1. settingsPath = getSettingsPath();  store into .bss:0xea0a0
//   2. WritePrivateProfileStringA("general", "right", NULL, path)
//      WritePrivateProfileStringA("general", "block", NULL, path)
//      (both delete those keys)
//   3. logPath = getDiagnosticLogPath()
//   4. writeDiagnosticLog("NoDelay189 - JNI e controle local sem menu ingame\n")
//   5. .data:0xbe000 = 1 (enabled);  .bss:0xea080 = 0
//   6. g_startTime  = _time64(NULL)          -> 0xea020
//      g_startTick  = GetTickCount64()       -> 0xea028
//   7. CreateThread(jvmThread, 0x60d0);  CreateThread(pipeThread, 0x9a80)
//   8. CloseHandle both
// ---------------------------------------------------------------------------
static void DeleteIniKey(const std::string& file, const char* section,
                         const char* key) {
    // Passing NULL as the value removes the key.
    WritePrivateProfileStringA(section, key, nullptr, file.c_str());
}

static DWORD WINAPI ControlThread(LPVOID) {
    Globals& G = g();

    // 1
    std::string settings = GetSettingsPath();
    G.settingsPath = settings;

    // 2
    DeleteIniKey(settings, kSectionGeneral, kKeyRight);
    DeleteIniKey(settings, kSectionGeneral, kKeyBlock);

    // 3 / 4
    WriteDiagnosticLog(kBanner);

    // 5
    G.enabled = true;          // .data:0xbe000 = 1
    G.license.active = false;  // .bss:0xea080 = 0

    // 6
    G.startTime = _time64(nullptr);   // 0xea020
    G.startTick = GetTickCount64();   // 0xea028

    // 7 / 8
    HANDLE jvm  = CreateThread(nullptr, 0, JvmThread, nullptr, 0, nullptr);
    HANDLE pipe = CreateThread(nullptr, 0, PipeThread, nullptr, 0, nullptr);
    if (jvm)  CloseHandle(jvm);
    if (pipe) CloseHandle(pipe);

    return 0;
}

// ---------------------------------------------------------------------------
// 0x60d0 -- JVM worker thread
//
//   poll .data:0xbe001 (run flag)
//   GetModuleHandleW(L"jvm.dll") -> GetProcAddress("JNI_GetCreatedJavaVMs")
//   JNI_GetCreatedJavaVMs(&vm, 1, &n)
//   AttachCurrentThread (vtable + 0x30); on JNI_EDETACHED use + 0x20
//   EnumerateClassLoaders()
//   decode the obfuscated profile table at 0xc0700 (len 0x2d2) with the
//     32-byte XOR key at 0xc06e0 and the rolling 0x29 + 0x49*i mask
//   loadProfiles(); match / resolve
//   on success  .bss:0xea081 = 1  and log "Conectado. ..."
//   on failure  Sleep(5000) and retry
// ---------------------------------------------------------------------------
static JavaVM* g_vm = nullptr;
static JNIEnv* g_env = nullptr;

static FARPROC ResolveJvmExport() {
    HMODULE jvm = GetModuleHandleW(L"jvm.dll");
    if (!jvm) return nullptr;
    return GetProcAddress(jvm, kJvmGetCreated);
}

// 0xc0700 table decode: XOR with key[i & 0x1f] then XOR with (0x29 + 0x49*i).
std::vector<std::string> DecodeProfileTable() {
    static const uint8_t kKey[32] = {
        0x56,0x63,0x6c,0x0b,0xe2,0x9f,0x15,0x85,0x5a,0x80,0xcc,0xe5,0x4c,0xb9,0xc2,0xe2,
        0xa3,0xba,0x85,0x9a,0xba,0x5f,0xd0,0xb5,0xe9,0xfa,0x8e,0xf7,0x8a,0xa5,0xeb,0xf1
    };
    // The encoded blob itself is emitted by the build into .rdata at 0xc0700;
    // it is reproduced as a byte array in nodelay_table.cpp.
    extern const uint8_t kEncodedTable[0x2d2];
    extern const size_t  kEncodedTableLen;

    std::string raw;
    raw.reserve(kEncodedTableLen);
    for (size_t i = 0; i < kEncodedTableLen; ++i) {
        uint8_t d = kEncodedTable[i] ^ kKey[i & 0x1f];
        uint8_t m = static_cast<uint8_t>(0x29 + 0x49 * i);
        raw.push_back(static_cast<char>(d ^ m));
    }

    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i <= raw.size(); ++i) {
        if (i == raw.size() || raw[i] == '\0') {
            if (i > start) out.emplace_back(raw.substr(start, i - start));
            start = i + 1;
        }
    }
    return out;
}

DWORD WINAPI JvmThread(LPVOID) {
    while (g().running) {
        FARPROC proc = ResolveJvmExport();
        if (!proc) { Sleep(static_cast<DWORD>(kRetrySleepMs)); continue; }

        using GetCreatedJavaVMs = jint(JNICALL*)(JavaVM**, jsize*, jsize*);
        auto getVms = reinterpret_cast<GetCreatedJavaVMs>(proc);

        JavaVM* vm = nullptr;
        jsize count = 0;
        if (getVms(&vm, 1, &count) != JNI_OK || count < 1 || !vm) {
            Sleep(static_cast<DWORD>(kRetrySleepMs));
            continue;
        }
        g_vm = vm;

        JNIEnv* env = nullptr;
        jint rc = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);
        if (rc == JNI_EDETACHED) {
            // vtable + 0x20 in the binary; AttachCurrentThreadAsDaemon here.
            if (vm->AttachCurrentThreadAsDaemon(reinterpret_cast<void**>(&env),
                                                nullptr) != JNI_OK) {
                Sleep(static_cast<DWORD>(kRetrySleepMs));
                continue;
            }
        } else if (rc != JNI_OK || !env) {
            Sleep(static_cast<DWORD>(kRetrySleepMs));
            continue;
        }
        g_env = env;

        std::vector<Profile> profiles = LoadProfiles();

        JniBinding binding;
        std::string err;
        if (ResolveProfile(env, profiles, binding, err)) {
            g().jniReady = true;                    // 0xea081 = 1
            g().statusText = kConnected;
            WriteDiagnosticLog(kConnected);
            // The worker then parks; the pipe server gates ACTIVATE on
            // 0xea081 being set.
            break;
        }

        WriteDiagnosticLog(err);
        Sleep(static_cast<DWORD>(kRetrySleepMs));
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Entry points used by DllMain / the control thread
// ---------------------------------------------------------------------------
DWORD WINAPI PipeThread(LPVOID);   // defined in nodelay_pipe.cpp

}  // namespace nodelay

using namespace nodelay;

// ---------------------------------------------------------------------------
// 0x9940 -- _CRT_INIT
// ---------------------------------------------------------------------------
extern "C" BOOL WINAPI
_DllMainCRTStartup(HINSTANCE hDLL, DWORD dwReason, LPVOID lpReserved);

// ---------------------------------------------------------------------------
// 0x1010 -- DllMain
//
//   DisableThreadLibraryCalls(hDLL)
//   CreateThread(0x58e0)
//
// The DLL does all of its work from the thread it spawns; DllMain itself
// performs no JNI or pipe work.
// ---------------------------------------------------------------------------
extern "C" BOOL WINAPI DllMain(HINSTANCE hDLL, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hDLL);

        g().running = true;   // .data:0xbe001 = 1

        HANDLE h = CreateThread(nullptr, 0, ControlThread, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
    } else if (dwReason == DLL_PROCESS_DETACH) {
        g().running = false;
    }
    return TRUE;
}
