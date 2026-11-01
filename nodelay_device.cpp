// nodelay_device.cpp
// Machine identity: reads HKLM MachineGuid, salts it, hashes with SHA-256 and
// hex-encodes the digest to a 64-character device id.
// Reconstructed from 0x3480 (getDeviceId).

#include "nodelay_types.h"

#include <cstring>
#include <string>
#include <vector>

namespace nodelay {

// ---------------------------------------------------------------------------
// BCrypt thin wrappers (thunks at 0xcd80 .. 0xcdb0)
// ---------------------------------------------------------------------------
struct AlgHandle {
    BCRYPT_ALG_HANDLE h = nullptr;
    ~AlgHandle() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
};

struct KeyHandle {
    BCRYPT_KEY_HANDLE h = nullptr;
    ~KeyHandle() { if (h) BCryptDestroyKey(h); }
};

// 0xcd88 -> BCryptOpenAlgorithmProvider
static bool OpenAlg(AlgHandle& out, const wchar_t* name, ULONG flags = 0) {
    return NT_SUCCESS(BCryptOpenAlgorithmProvider(&out.h, name, nullptr, flags));
}

// 0xcd98 -> BCryptHash
static bool Sha256(const uint8_t* data, size_t len, uint8_t digest[32]) {
    AlgHandle alg;
    if (!OpenAlg(alg, BCRYPT_SHA256_ALGORITHM)) return false;

    ULONG result = 0;
    return NT_SUCCESS(BCryptHash(alg.h, nullptr, 0,
                                 const_cast<PUCHAR>(data), static_cast<ULONG>(len),
                                 digest, 32, &result)) && result == 32;
}

// ---------------------------------------------------------------------------
// 0x3480 -- getDeviceId()
//
//   1. RegGetValueA(HKLM, "SOFTWARE\Microsoft\Cryptography", "MachineGuid")
//   2. Build "NoDelay:Device:v1:" + <delimiter 'S'? no: prefix then value>
//      The construction is: prefix (0xc013f) ++ value, where the value is
//      appended after the prefix. A delimiter of ' ' (0xc00e8 table) is used
//      only for trimming.
//   3. SHA-256 over the assembled UTF-8 bytes
//   4. Hex encode with "0123456789ABCDEF"
//
// Returns a 64-character uppercase hex string (length 0x20 when decoded).
// ---------------------------------------------------------------------------
std::string GetDeviceId() {
    char guid[256] = {};
    DWORD cb = sizeof(guid) - 1;
    LONG rc = RegGetValueA(HKEY_LOCAL_MACHINE,
                           kRegKeyCryptoPath,
                           kRegValueMachineGuid,
                            RRF_RT_REG_SZ,
                           nullptr,
                           guid,
                           &cb);
    if (rc != ERROR_SUCCESS) return std::string();

    // Trim surrounding whitespace using the " \t\r\n" table at 0xc00e8.
    std::string value(guid);
    size_t begin = value.find_first_not_of(kWhitespace);
    size_t end   = value.find_last_not_of(kWhitespace);
    if (begin == std::string::npos) return std::string();
    value = value.substr(begin, end - begin + 1);

    // "NoDelay:Device:v1:" ++ guid
    std::string material;
    material.reserve(std::strlen(kDevicePrefix) + value.size());
    material.append(kDevicePrefix);
    material.append(value);

    uint8_t digest[32] = {};
    if (!Sha256(reinterpret_cast<const uint8_t*>(material.data()),
                material.size(), digest)) {
        return std::string();
    }

    return HexEncode(digest, sizeof(digest));
}

}  // namespace nodelay
