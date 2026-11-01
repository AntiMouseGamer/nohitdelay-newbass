// nodelay_types.h
// Shared types, globals and constants reconstructed from NoDelay189.dll.
//
// The DLL is a MinGW-w64 / GCC x64 build with libstdc++ statically linked.
// Application code occupies .text 0x1010 .. 0x10000; globals live in .data/.bss.
//
// Layout of the reconstructed translation units:
//   nodelay_types.h      - this file (globals, structs, constants)
//   nodelay_util.cpp     - hex codecs, INI helpers, path helpers, log writer
//   nodelay_device.cpp   - MachineGuid device fingerprint + SHA-256
//   nodelay_license.cpp  - ECDSA P-256 license verification (BCrypt)
//   nodelay_jni.cpp      - JNI glue, class-loader enumeration, profile matching
//   nodelay_threads.cpp  - DllMain, control thread, JVM thread
//   nodelay_pipe.cpp     - named-pipe control server + protocol

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <string>
#include <vector>

namespace nodelay {

// ---------------------------------------------------------------------------
// Module identity
// ---------------------------------------------------------------------------
inline constexpr const char* kModuleName    = "NoDelay189";
inline constexpr const char* kModuleVersion = "Alpha2.14";

// ---------------------------------------------------------------------------
// Path / config constants (rdata 0xc0214 .. 0xc03ae)
// ---------------------------------------------------------------------------
inline constexpr const char* kEnvLocalAppData    = "LOCALAPPDATA";
inline constexpr const char* kAppDirName         = "\\NoDelay189";
inline constexpr const char* kSettingsFileName   = "\\settings.ini";  // 0xc023c
inline constexpr const char* kLegacyIniName      = "NoDelay189.ini";  // 0xc0221
inline constexpr const char* kProfilesFileName   = "profiles.ini";    // 0xc0350
inline constexpr const char* kDiagnosticFileName = "diagnostic.log";  // 0xc024e
inline constexpr const char* kPathSeparators     = "\\/";             // 0xc024a
inline constexpr const char* kWhitespace         = " \t\r\n";         // 0xc00e8

// settings.ini keys
inline constexpr const char* kSectionGeneral = "general";  // 0xc03b4
inline constexpr const char* kKeyRight       = "right";    // 0xc03ae
inline constexpr const char* kKeyBlock       = "block";    // 0xc03bc

// profiles.ini keys
inline constexpr const char* kKeyEnabled        = "enabled";       // 0xc0377
inline constexpr const char* kKeyTitle          = "title";         // 0xc037f
inline constexpr const char* kKeyMcClass        = "mcClass";       // 0xc0385
inline constexpr const char* kKeyMcGetter       = "mcGetter";      // 0xc038d
inline constexpr const char* kKeyHitField       = "hitField";      // 0xc0396
inline constexpr const char* kKeyHitAlternative = "hitAlternative";// 0xc039f

// Built-in profile section names recognised in profiles.ini
inline constexpr const char* kSectionLunar   = "Lunar_1.8.9";   // 0xc035d
inline constexpr const char* kSectionBadlion = "Badlion_1.8.9"; // 0xc0369

// ---------------------------------------------------------------------------
// Device fingerprint + crypto constants (rdata 0xc00b7 .. 0xc0210)
// ---------------------------------------------------------------------------
inline constexpr const char* kRegKeyCryptoPath =
    "SOFTWARE\\Microsoft\\Cryptography";                    // 0xc00c8
inline constexpr const char* kRegValueMachineGuid = "MachineGuid"; // 0xc00b7

inline constexpr const char* kDevicePrefix = "NoDelay:Device:v1:"; // 0xc013f
inline constexpr const char* kHexAlphabet  = "0123456789ABCDEF";   // 0xc0152? (see note)
inline constexpr const char* kSha256Alg    = "SHA256";             // 0xc0152
inline constexpr const char* kEccP256Alg   = "ECDSA_P256";         // 0xc01e2
inline constexpr const char* kEccPublicBlobType = "ECCPUBLICBLOB"; // 0xc01f8

// Header prepended to the imported ECC public key blob: "ECS1 " + 3 NULs.
// Interpreted as BCRYPT_ECCKEY_BLOB { dwMagic, cbKey } followed by X||Y.
inline constexpr uint8_t kEccBlobHeader[8] = { 'E','C','S','1',' ',0,0,0 }; // 0xc09d8

// Embedded ECDSA P-256 public key, 128 hex chars == 64 raw bytes (X||Y).
inline constexpr const char* kPublicKeyHex =  // 0xc0160
    "95EF7088DD007DFB93C5B07409D837235F8CBB68850A214898E7DEFBB314C783"
    "099FEA08E7C0A7FF0CED5A13BE1D8E5E4D899A3E3E730FBCD3B66A9CD8D1F238";

inline constexpr size_t kPublicKeyBytes = 64;  // 0x40
inline constexpr size_t kSignatureBytes = 64;  // 0x40
inline constexpr size_t kEccBlobBytes   = 0x48;// 72 = 8 + 64
inline constexpr size_t kDeviceIdBytes  = 0x20;// 32 (SHA-256 digest, hex -> 64)

// ---------------------------------------------------------------------------
// Diagnostic strings (rdata 0xc03c8 .. 0xc06cf)
// ---------------------------------------------------------------------------
inline constexpr const char* kBanner =
    "NoDelay189 - JNI e controle local sem menu ingame\n";   // 0xc03c8
inline constexpr const char* kJvmDllName = "jvm.dll";        // 0xc03fe
inline constexpr const char* kJvmGetCreated = "JNI_GetCreatedJavaVMs"; // 0xc040e

inline constexpr const char* kErrClassNotVisible   = "Minecraft class nao visivel no loader"; // 0xc0448
inline constexpr const char* kErrGetterNotFound    = "Metodo de acesso ao jogo nao localizado"; // 0xc0478
inline constexpr const char* kErrSingletonMissing  = "Minecraft singleton indisponivel";      // 0xc04a0
inline constexpr const char* kErrHitFieldNotFound  = "Campo de clique nao localizado";        // 0xc04c8
inline constexpr const char* kErrRefCreateFailed   = "Falha ao criar referencia JNI";         // 0xc04e7
inline constexpr const char* kErrNotFoundPrefix    = "Nao encontrado: ";                      // 0xc0505
inline constexpr const char* kErrNoCompleteProfile =
    " carregador(es) pesquisado(s); nenhum perfil completo."; // 0xc0518
inline constexpr const char* kErrUnrecognisedClasses = "Nao reconheceu classes; ";            // 0xc054f
inline constexpr const char* kErrSeeLog            = " loader(s). Veja diagnostic.log.";     // 0xc0568
inline constexpr const char* kErrJniRead           = ": falha na leitura JNI.";              // 0xc0589
inline constexpr const char* kErrJniWrite          = ": falha na escrita JNI.";              // 0xc05a1
inline constexpr const char* kThreadContextPrefix  = "thread-context-";                      // 0xc0340
inline constexpr const char* kStatusWaiting        = "Aguardando JVM do Minecraft...";       // 0xc06b0
inline constexpr const char* kStatusUnknown        = "Nao identificado";                     // 0xc06cf
inline constexpr const char* kConnected =
    "Conectado. Hit Delay Fix pronto; sem alteracao de mineracao.";

// ---------------------------------------------------------------------------
// Pipe protocol responses (rdata 0xc05b9 .. 0xc068a)
// ---------------------------------------------------------------------------
inline constexpr const char* kPipePrefix         = "\\\\.\\pipe\\NoDelay189-"; // 0xc05e6
inline constexpr const char* kSddlPrefix         = "D:P(A;;GA;;;";             // 0xc05fc
inline constexpr const char* kRespOkReady        = "OK READY";                 // 0xc05b9
inline constexpr const char* kRespErrNotReady    = "ERR NOT_READY";            // 0xc05c2
inline constexpr const char* kRespOkActive       = "OK ACTIVE";                // 0xc05d0
inline constexpr const char* kRespOkInactive     = "OK INACTIVE";              // 0xc05da
inline constexpr const char* kRespErrCommand     = "ERR COMMAND";              // 0xc061a
inline constexpr const char* kRespOkModule       = "OK MODULE Alpha2.14";      // 0xc062e
inline constexpr const char* kRespOkChallenge    = "OK CHALLENGE ";            // 0xc0652
inline constexpr const char* kRespErrLicense     = "ERR LICENSE";              // 0xc0673
inline constexpr const char* kRespErrSignedLease = "ERR SIGNED_LEASE_REQUIRED";// 0xc068a
inline constexpr const char* kRespErrLicenseDetail =
    "ERR LICENSE: assinatura, prazo ou desafio recusado";

inline constexpr const char* kCmdVersion    = "VERSION";    // 0xc0626
inline constexpr const char* kCmdReady      = "READY";      // 0xc0642
inline constexpr const char* kCmdChallenge  = "CHALLENGE";  // 0xc0648
inline constexpr const char* kCmdActivate   = "ACTIVATE ";  // 0xc0660
inline constexpr const char* kCmdRenew      = "RENEW ";     // 0xc066a
inline constexpr const char* kCmdDeactivate = "DEACTIVATE"; // 0xc067f
inline constexpr const char* kCmdStatus     = "STATUS";     // 0xc06a4
inline constexpr const char* kFieldSeparator = "|";         // 0xc0671

inline constexpr char kLogNewline = '\n'; // 0xc03fb

// ---------------------------------------------------------------------------
// Timing constants
// ---------------------------------------------------------------------------
inline constexpr uint64_t kChallengeWindowMs = 0xafc8;    // 45000 ms lease window
inline constexpr uint64_t kMaxLeaseMs        = 0x5c4900;  // 6_000_000 ms (100 min)
inline constexpr uint64_t kMinLeaseMs        = 0x2c;      // 44 ms floor
inline constexpr uint64_t kRetrySleepMs      = 5000;      // JVM poll interval
inline constexpr size_t   kChallengeBytes    = 0x10;      // 16 random bytes
inline constexpr size_t   kLicenseFieldCount = 0xc0;      // 192 fields expected? (see note)
inline constexpr size_t   kLicenseFieldTotal = 0xc0;      // total payload byte budget

// ---------------------------------------------------------------------------
// Profile descriptor (element size 0xa0 == 5 std::string)
// ---------------------------------------------------------------------------
struct Profile {
    std::string title;          // 0x00
    std::string mcClass;        // 0x20
    std::string mcGetter;       // 0x40
    std::string hitField;       // 0x60
    std::string hitAlternative; // 0x80
};                               // sizeof == 0xa0

// A resolved JNI binding for one profile.
struct JniBinding {
    jobject loader  = nullptr;  // global ref to the ClassLoader
    jclass   mcCls  = nullptr;  // global ref to the Minecraft class
    jmethodID getter = nullptr; // static getMinecraft()
    jfieldID  hitField = nullptr;
    jfieldID  hitAlt   = nullptr;
    int      profileIndex = -1;
};

// ---------------------------------------------------------------------------
// License / lease state (bss 0xea040 .. 0xea081)
// ---------------------------------------------------------------------------
struct LicenseState {
    std::string licenseBlob;  // 0xea040 / 0xea048 (length must be 0x20 when set)
    bool        present    = false; // 0xea048 != 0
    uint64_t    leaseStart = 0;     // 0xea060  (GetTickCount64 base)
    bool        challengeIssued = false; // 0xea068
    uint64_t    expiry     = 0;     // 0xea078  (GetTickCount64 deadline)
    bool        active     = false; // 0xea080
};

// ---------------------------------------------------------------------------
// Process-wide globals (bss 0xea000 ..)
// ---------------------------------------------------------------------------
struct Globals {
    bool         enabled        = false; // .data:0xbe000
    bool         running        = false; // .data:0xbe001
    int64_t      startTime      = 0;     // 0xea020  _time64 at boot
    uint64_t     startTick      = 0;     // 0xea028  GetTickCount64 at boot
    LicenseState license;                // 0xea040 ..
    bool         jniReady       = false; // 0xea081
    std::string  settingsPath;           // 0xea0a0 / 0xea0a8 / 0xea0b0
    std::string  statusText;             // 0xea0c0
    std::string  classLoaderName;        // 0xea0e0
    std::string  profileTitle;           // 0xea0f0
    std::string  lastError;              // 0xea100
};

Globals& g();

// Guarded global-string setter (0x1b40): stores into one of the three
// bss strings 0xea0e0 / 0xea0f0 / 0xea100 under a one-shot init guard
// (guard variable at 0xc5ee0).
void SetGlobalString(int slot, const std::string& value);

// ---------------------------------------------------------------------------
// Small helpers used across the module
// ---------------------------------------------------------------------------
std::string& SettingsPath();      // cached .bss std::string
void          WriteDiagnosticLog(const std::string& message); // 0x5e10

}  // namespace nodelay
