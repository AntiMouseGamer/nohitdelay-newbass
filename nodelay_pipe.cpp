// nodelay_pipe.cpp
// Named-pipe control server and text protocol.
// Reconstructed from 0x9a80 (server thread) and 0xa23d .. 0xcd00 (dispatch).

#include "nodelay_types.h"

#include <sddl.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace nodelay {

// ---------------------------------------------------------------------------
// Prototypes provided by the other units.
// ---------------------------------------------------------------------------
std::string GetDeviceId();
bool HandleActivate(const std::string& payload, std::string& reason);
void HandleDeactivate();
bool LeaseFresh();
LicenseState& License();

// ---------------------------------------------------------------------------
// 0x1390 -- integral -> decimal string (std::to_string equivalent)
// ---------------------------------------------------------------------------
static std::string ToDecimal(uint32_t v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u", v);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// 0xa7200 -- format a protocol response and hand it to the writer.
// The binary builds it as "<status-code>|<payload>" where the status code is
// carried in a stack slot at [rsp+0x20] and the payload pointer/length in
// r9/r8.
// ---------------------------------------------------------------------------
struct Response {
    int         code = 0;
    std::string body;
};

// ---------------------------------------------------------------------------
// Pipe name: "\\\\.\\pipe\\NoDelay189-<pid>"  (0x9b57 / 0x1390)
// ---------------------------------------------------------------------------
static std::string BuildPipeName() {
    std::string name = kPipePrefix;
    name += ToDecimal(GetCurrentProcessId());
    return name;
}

// ---------------------------------------------------------------------------
// SDDL: "D:P(A;;GA;;;<sid>)"  built from the process token (0x9c0b / 0x9c82).
// Restricted to the current user so no other local account can drive the
// protocol.
// ---------------------------------------------------------------------------
static std::string BuildSecurityDescriptor() {
    std::string sddl = kSddlPrefix;   // "D:P(A;;GA;;;"

    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcessToken(), TOKEN_QUERY, &token)) {
        return std::string();
    }

    DWORD len = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &len);
    std::vector<uint8_t> buf(len);
    BOOL ok = len && GetTokenInformation(token, TokenUser, buf.data(), len, &len);
    CloseHandle(token);
    if (!ok) return std::string();

    LPSTR sidText = nullptr;
    if (!ConvertSidToStringSidA(reinterpret_cast<PSID>(buf.data()), &sidText)) {
        return std::string();
    }
    sddl += sidText;
    sddl += ")";
    LocalFree(sidText);
    return sddl;
}

// ---------------------------------------------------------------------------
// 0xcda0 -> BCryptGenRandom: 16 bytes for the CHALLENGE nonce (0xa6a6).
// ---------------------------------------------------------------------------
static bool RandomBytes(uint8_t* out, size_t n) {
    AlgHandle alg;   // see nodelay_device.cpp
    if (!OpenAlg(alg, BCRYPT_RNG_ALGORITHM)) return false;
    return NT_SUCCESS(BCryptGenRandom(alg, out, static_cast<ULONG>(n),
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

// ---------------------------------------------------------------------------
// Command matching, mirroring the immediate compares in the binary:
//
//   len 5  && memcmp(p,"READY",5)      == 0     -> READY
//   len 7  && memcmp(p,"VERSION",7)    == 0     -> VERSION
//   len 9  && memcmp(p,"CHALLENGE",9)  == 0     -> CHALLENGE
//   len 10 && memcmp(p,"DEACTIVATE",10)== 0     -> DEACTIVATE
//   len 6  && memcmp(p,"STATUS",6)     == 0     -> STATUS
//   prefix "ACTIVATE " (9) or "RENEW " (6)      -> license path
//   len 4  && memcmp(p,"PING",4)       == 0     -> rejected
// ---------------------------------------------------------------------------
enum class Command {
    Ready, Version, Challenge, Deactivate, Status,
    Activate, Renew, Ping, Unknown
};

struct ParsedCommand {
    Command     kind = Command::Unknown;
    std::string argument;   // everything after an "ACTIVATE " / "RENEW " prefix
};

static bool Equals(const std::string& s, const char* lit, size_t n) {
    return s.size() == n && std::memcmp(s.data(), lit, n) == 0;
}

static ParsedCommand ParseCommand(const std::string& raw) {
    ParsedCommand c;

    std::string cmd = raw;
    // Trim trailing whitespace (0x100002400 mask == "\t\n\v\f\r ").
    while (!cmd.empty()) {
        unsigned char ch = static_cast<unsigned char>(cmd.back());
        bool isWs = (ch <= 0x20) && (((0x100002400ULL) >> ch) & 1);
        if (!isWs) break;
        cmd.pop_back();
    }

    if (Equals(cmd, kCmdActivate, std::strlen(kCmdActivate))) {
        c.kind = Command::Activate;
        c.argument = cmd.substr(std::strlen(kCmdActivate));
        return c;
    }
    if (Equals(cmd, kCmdRenew, std::strlen(kCmdRenew))) {
        c.kind = Command::Renew;
        c.argument = cmd.substr(std::strlen(kCmdRenew));
        return c;
    }
    if (Equals(cmd, kCmdReady,      5)) { c.kind = Command::Ready;      return c; }
    if (Equals(cmd, kCmdVersion,    7)) { c.kind = Command::Version;    return c; }
    if (Equals(cmd, kCmdChallenge,  9)) { c.kind = Command::Challenge;  return c; }
    if (Equals(cmd, kCmdDeactivate,10)) { c.kind = Command::Deactivate; return c; }
    if (Equals(cmd, kCmdStatus,     6)) { c.kind = Command::Status;     return c; }
    if (Equals(cmd, "PING",         4)) { c.kind = Command::Ping;       return c; }
    return c;
}

// ---------------------------------------------------------------------------
// 0xa4e7 -- CHALLENGE handler
//
//   if the lease is fresh (0xa4ed .. 0xa976):
//       "OK CHALLENGE " + <license blob>
//   else:
//       16 random bytes, hex-encoded -> "OK CHALLENGE <hex>"
//       and reset 0xea040 / 0xea048 (0xa6c3 .. 0xa6d9)
// ---------------------------------------------------------------------------
static Response HandleChallenge() {
    Response r;

    if (LeaseFresh()) {
        r.code = static_cast<int>(License().licenseBlob.size()) + 0xd;
        r.body = kRespOkChallenge;
        r.body += License().licenseBlob;
        return r;
    }

    uint8_t nonce[kChallengeBytes] = {};
    if (!RandomBytes(nonce, sizeof(nonce))) {
        // BCryptGenRandom failed: clear the stored blob and report it.
        HandleDeactivate();
        r.body.clear();
        return r;
    }

    LicenseState& ls = License();
    ls.licenseBlob = HexEncode(nonce, sizeof(nonce));
    ls.present         = true;
    ls.leaseStart      = GetTickCount64();
    ls.challengeIssued = true;

    r.body = kRespOkChallenge;
    r.body += ls.licenseBlob;
    r.code = static_cast<int>(r.body.size());
    return r;
}

// ---------------------------------------------------------------------------
// 0xa23d -- per-connection command loop
// ---------------------------------------------------------------------------
static Response Dispatch(const std::string& raw) {
    Response r;
    ParsedCommand c = ParseCommand(raw);

    switch (c.kind) {
        case Command::Ready:
            // 0xadd6: gated on 0xea081 (jniReady)
            if (!g().jniReady) { r.body = kRespErrNotReady; return r; }
            r.body = kRespOkReady;
            return r;

        case Command::Version:
            r.body = kRespOkModule;         // "OK MODULE Alpha2.14"
            return r;

        case Command::Status:
            r.body = License().active ? kRespOkActive : kRespOkInactive;
            return r;

        case Command::Deactivate:
            HandleDeactivate();
            r.body = kRespOkInactive;
            return r;

        case Command::Challenge:
            return HandleChallenge();

        case Command::Activate:
        case Command::Renew: {
            // 0xa3b8 / 0xb233: both routes require a signed lease; the
            // unsigned form is refused outright.
            if (!g().jniReady) { r.body = kRespErrNotReady; return r; }
            if (!License().challengeIssued) {
                r.body = kRespErrSignedLease;
                return r;
            }

            std::string reason;
            if (HandleActivate(c.argument, reason)) {
                r.body = kRespOkActive;
            } else {
                r.body = kRespErrLicenseDetail;
                WriteDiagnosticLog(reason);
            }
            return r;
        }

        case Command::Ping:
            // 0xa3b8: PING is deliberately not honoured.
            r.body = kRespErrSignedLease;
            return r;

        case Command::Unknown:
        default:
            r.body = kRespErrCommand;
            return r;
    }
}

// ---------------------------------------------------------------------------
// 0x9a80 -- pipe server thread
//
//   name = \\.\pipe\NoDelay189-<pid>
//   sddl = D:P(A;;GA;;;<user sid>)
//   CreateNamedPipeA(..., PIPE_ACCESS_DUPLEX,
//                    PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT, ...)
//   loop { ConnectNamedPipe; ReadFile; Dispatch; WriteFile;
//          DisconnectNamedPipe; FlushFileBuffers; CloseHandle }
// ---------------------------------------------------------------------------
DWORD WINAPI PipeThread(LPVOID) {
    const std::string name = BuildPipeName();
    const std::string sddl = BuildSecurityDescriptor();

    SECURITY_ATTRIBUTES sa{};
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (!sddl.empty() && ConvertStringSecurityDescriptorToSecurityDescriptorA(
                             sddl.c_str(), SDDL_REVISION_1, &psd, nullptr)) {
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = psd;
        sa.bInheritHandle = FALSE;
    }

    for (;;) {
        if (!g().running) break;

        HANDLE hPipe = CreateNamedPipeA(
            name.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,                 // max instances
            0x1000,            // out buffer
            0x1000,            // in buffer
            0,                 // default timeout
            psd ? &sa : nullptr);

        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(static_cast<DWORD>(kRetrySleepMs));
            continue;
        }

        // Wait for a client; while blocked the run flag can end the loop.
        BOOL connected = ConnectNamedPipe(hPipe, nullptr)
                             ? TRUE
                             : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (connected) {
            char buf[0x1000] = {};
            DWORD read = 0;
            if (ReadFile(hPipe, buf, sizeof(buf) - 1, &read, nullptr) && read > 0) {
                std::string request(buf, read);
                while (!request.empty() &&
                       (request.back() == '\r' || request.back() == '\n' ||
                        request.back() == ' ')) {
                    request.pop_back();
                }

                Response resp = Dispatch(request);
                std::string out = resp.body;
                out.push_back('\n');

                DWORD written = 0;
                WriteFile(hPipe, out.data(), static_cast<DWORD>(out.size()),
                          &written, nullptr);
            }
        }

        DisconnectNamedPipe(hPipe);
        FlushFileBuffers(hPipe);
        CloseHandle(hPipe);
    }

    if (psd) LocalFree(psd);
    return 0;
}

}  // namespace nodelay
