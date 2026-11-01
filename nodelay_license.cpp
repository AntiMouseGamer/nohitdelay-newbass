// nodelay_license.cpp
// ECDSA P-256 license verification via BCrypt.
// Reconstructed from 0x3d30 (verifyLicense) and the ACTIVATE/RENEW handler
// at 0xa830 .. 0xbc17 in the pipe server.

#include "nodelay_types.h"

#include <cstring>
#include <string>
#include <vector>

namespace nodelay {

// --- BCrypt helpers (see nodelay_device.cpp for the handle RAII types) ------

namespace {

struct AlgHandle {
    BCRYPT_ALG_HANDLE h = nullptr;
    ~AlgHandle() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
    operator BCRYPT_ALG_HANDLE() const { return h; }
};

struct KeyHandle {
    BCRYPT_KEY_HANDLE h = nullptr;
    ~KeyHandle() { if (h) BCryptDestroyKey(h); }
};

bool OpenAlg(AlgHandle& out, const wchar_t* name) {
    return NT_SUCCESS(BCryptOpenAlgorithmProvider(&out.h, name, nullptr, 0));
}

// 0xcd98 -> BCryptHash (SHA-256)
bool Sha256(const uint8_t* data, size_t len, uint8_t digest[32]) {
    AlgHandle alg;
    if (!OpenAlg(alg, BCRYPT_SHA256_ALGORITHM)) return false;
    ULONG result = 0;
    return NT_SUCCESS(BCryptHash(alg, nullptr, 0,
                                 const_cast<PUCHAR>(data), static_cast<ULONG>(len),
                                 digest, 32, &result)) && result == 32;
}

// 0xcd90 -> BCryptImportKeyPair with BCRYPT_ECCPUBLICBLOB
bool ImportEccPublicKey(BCRYPT_ALG_HANDLE alg, const uint8_t blob[72],
                        BCRYPT_KEY_HANDLE* key) {
    return NT_SUCCESS(
        BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLICBLOB,
                            const_cast<PUCHAR>(blob), 0x48, key, 0));
}

// 0xcd80 -> BCryptVerifySignature
bool VerifySignature(BCRYPT_KEY_HANDLE key, const uint8_t digest[32],
                     const uint8_t sig[64]) {
    return !!NT_SUCCESS(
        BCryptVerifySignature(key, const_cast<PUCHAR>(digest), 32,
                              const_cast<PUCHAR>(sig), 64, 0));
}

}  // namespace

// ---------------------------------------------------------------------------
// BuildEccPublicKeyBlob
//
// The imported key blob is laid out as:
//   [0 .. 7]   8-byte BCRYPT_ECCKEY_BLOB header, stored as the literal
//              "ECS1 " + 3 NULs (dwMagic / cbKey), at rdata 0xc09d8
//   [8 .. 71]  the 64-byte uncompressed point X||Y
//
// Total 0x48 bytes, matching the cbInput immediate at 0x4044.
// ---------------------------------------------------------------------------
static void BuildEccPublicKeyBlob(const uint8_t point[64], uint8_t out[72]) {
    std::memset(out, 0, 72);
    std::memcpy(out, kEccBlobHeader, sizeof(kEccBlobHeader));
    std::memcpy(out + 8, point, 64);
}

// ---------------------------------------------------------------------------
// 0x3d30 -- verifyLicense(blob, sig)
//
//   rcx = rsi = blob  (std::string)
//   rdx = r14 = sig   (std::string)
//
// Steps:
//   1. Hex-decode the embedded 128-char public key (0xc0160). Require 0x40 bytes.
//   2. Hex-decode `blob`. Require 0x40 bytes.
//   3. SHA-256 over `blob`.
//   4. Prepend the "ECS1 " header to the public key point -> 0x48-byte blob.
//   5. BCryptOpenAlgorithmProvider(ECDSA_P256) -> BCryptImportKeyPair
//      (ECCPUBLICBLOB) -> BCryptVerifySignature(hash, sig).
//   6. Return true iff the signature is valid.
// ---------------------------------------------------------------------------
bool VerifyLicense(const std::string& blob, const std::string& sig) {
    // 1. public key
    std::vector<uint8_t> pubPoint;
    if (!HexDecode(kPublicKeyHex, pubPoint) || pubPoint.size() != kPublicKeyBytes) {
        return false;
    }

    // 2. signed blob
    std::vector<uint8_t> blobBytes;
    if (!HexDecode(blob, blobBytes) || blobBytes.size() != kPublicKeyBytes) {
        return false;
    }

    // 3. signature
    std::vector<uint8_t> sigBytes;
    if (!HexDecode(sig, sigBytes) || sigBytes.size() != kSignatureBytes) {
        return false;
    }

    // 4. hash the blob
    uint8_t digest[32] = {};
    if (!Sha256(blobBytes.data(), blobBytes.size(), digest)) return false;

    // 5. assemble and import
    uint8_t keyBlob[72] = {};
    BuildEccPublicKeyBlob(pubPoint.data(), keyBlob);

    AlgHandle alg;
    if (!OpenAlg(alg, BCRYPT_ECDSA_P256_ALGORITHM)) return false;

    KeyHandle key;
    if (!ImportEccPublicKey(alg, keyBlob, &key.h)) return false;

    // 6. verify
    return VerifySignature(key.h, digest, sigBytes.data());
}

// ---------------------------------------------------------------------------
// License / lease state helpers (bss 0xea040 .. 0xea081)
// ---------------------------------------------------------------------------
LicenseState& License() { return g().license; }

bool LicensePresent() { return License().present && License().licenseBlob.size() == 0x20; }

uint64_t NowTick() { return GetTickCount64(); }

int64_t NowTime() { return _time64(nullptr); }

// Reconstruct an approximate wall-clock "now" by advancing the boot-time
// timestamp (0xea020) by the monotonic elapsed milliseconds (0xea028),
// clamped so it never runs ahead of the real clock.
int64_t LeaseNow() {
    uint64_t tick = NowTick();
    int64_t  t    = NowTime();

    const uint64_t startTick = g().startTick;
    const int64_t  startTime = g().startTime;

    if (tick < startTick || startTime < 0) return t;

    uint64_t elapsedSec = (tick - startTick) / 1000;      // 0x20c49ba5e353f7cf magic
    int64_t  candidate  = startTime + static_cast<int64_t>(elapsedSec);
    if (candidate < t) candidate = t;
    return candidate;
}

// ---------------------------------------------------------------------------
// 0xa830 -- ACTIVATE / RENEW handler
//
// The payload after the "ACTIVATE " / "RENEW " prefix is split on '|' into
// exactly six fields (total vector byte-span 0xc0 == 6 * 0x20):
//
//   [0] "V2"                       version tag
//   [1] device id (32 hex chars)   must match the local device id
//   [2] decimal expiry (1..12)     must be in the future, <= 100 minutes
//   [3] signature (hex)
//   [4] license blob (hex)
//   [5] (unused / trailing)
//
// The signed message is rebuilt as:
//      "V2" + '|' + device + '|' + expiry
// and handed to verifyLicense along with field [3].
//
// On success the lease is stored at 0xea040 (blob), 0xea048 (len 0x20),
// 0xea060 (lease start tick), 0xea078 (expiry tick) and 0xea080 (active).
// ---------------------------------------------------------------------------
struct ActivatePayload {
    std::vector<std::string> fields;
    bool ok = false;
};

static bool SplitOnPipe(const std::string& in, std::vector<std::string>& out) {
    out.clear();
    size_t start = 0;
    while (start <= in.size()) {
        size_t pos = in.find('|', start);
        if (pos == std::string::npos) pos = in.size();
        out.emplace_back(in.substr(start, pos - start));
        start = pos + 1;
        if (pos == in.size()) break;
    }
    return out.size() == 6;
}

static bool AllDigits(const std::string& s) {
    if (s.empty() || s.size() > 12) return false;
    for (char c : s) if (c < '0' || c > '9') return false;
    return true;
}

static int64_t ParseDecimal(const std::string& s) {
    int64_t v = 0;
    for (char c : s) v = v * 10 + (c - '0');
    return v;
}

// Returns true when the lease was accepted; fills `reason` on failure.
bool HandleActivate(const std::string& payload, std::string& reason) {
    std::vector<std::string> f;
    if (!SplitOnPipe(payload, f)) {
        reason = kRespErrLicenseDetail;
        return false;
    }

    // [0] version tag
    if (f[0].size() != 2 || static_cast<uint8_t>(f[0][0]) != 'V' ||
        static_cast<uint8_t>(f[0][1]) != '2') {
        reason = kRespErrLicenseDetail;
        return false;
    }

    // [1] device id must match and be 32 hex chars
    const std::string device = GetDeviceId();
    if (f[1].size() != device.size() || f[1] != device) {
        reason = kRespErrLicenseDetail;
        return false;
    }

    // [2] expiry, decimal, 1..12 digits
    if (!AllDigits(f[2])) {
        reason = kRespErrLicenseDetail;
        return false;
    }
    const int64_t expiry = ParseDecimal(f[2]);
    if (expiry <= 0) {
        reason = kRespErrLicenseDetail;
        return false;
    }

    const int64_t now = LeaseNow();
    if (expiry <= now) {                                  // already expired
        reason = kRespErrLicenseDetail;
        return false;
    }
    if (static_cast<uint64_t>(expiry - now) > kMaxLeaseMs) {  // > 100 minutes
        reason = kRespErrLicenseDetail;
        return false;
    }

    // Rebuild the signed message and verify.
    std::string message;
    message.reserve(3);
    message.append(f[0]);          // "V2"
    message.push_back('|');
    message.append(f[1]);          // device id
    message.push_back('|');
    message.append(f[2]);          // expiry

    if (!VerifyLicense(message, f[3])) {
        reason = kRespErrLicenseDetail;
        return false;
    }

    // Accept: persist the lease. Field [4] carries the opaque license blob.
    LicenseState& ls = License();
    ls.licenseBlob   = f[4].empty() ? message : f[4];
    ls.present       = true;
    ls.leaseStart    = NowTick();
    ls.challengeIssued = false;
    ls.active        = true;

    // 0xb191: expiry tick = lease start + 0xafc8 (45 s) capped, stored at 0xea078
    uint64_t leaseTicks = static_cast<uint64_t>(expiry - now) * 1000;
    if (leaseTicks > kChallengeWindowMs) leaseTicks = kChallengeWindowMs;
    ls.expiry = ls.leaseStart + leaseTicks;

    // 0xb1c6: when the module-wide enable flag (0xbe000) is clear, activation
    // also sets it, so the hit-delay fix becomes live.
    if (!g().enabled) g().enabled = true;

    reason.clear();
    return true;
}

// ---------------------------------------------------------------------------
// DEACTIVATE (0xb19f .. 0xb1da)
// ---------------------------------------------------------------------------
void HandleDeactivate() {
    LicenseState& ls = License();
    ls.licenseBlob.clear();
    ls.present         = false;
    ls.leaseStart      = 0;
    ls.expiry          = 0;
    ls.challengeIssued = false;
    ls.active          = false;
}

// ---------------------------------------------------------------------------
// Lease validity check used by the CHALLENGE path (0xa4e7 .. 0xa976):
//   - a blob is present (0xea048 != 0)
//   - now >= lease start (0xea060)
//   - now - lease start <= 0xafc7 (45 s)
//   - blob length == 0x20
// ---------------------------------------------------------------------------
bool LeaseFresh() {
    const LicenseState& ls = License();
    if (!ls.present || ls.licenseBlob.size() != kDeviceIdBytes) return false;

    const uint64_t now = NowTick();
    if (now < ls.leaseStart) return false;
    return (now - ls.leaseStart) <= (kChallengeWindowMs - 1);
}

}  // namespace nodelay
