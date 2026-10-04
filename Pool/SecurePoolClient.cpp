#include "PoolClient.h"
#include "Logger.h"

#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#endif

extern void logToFile(int gpuIndex, const std::string& msg);

namespace {
constexpr const char* kPuzzle71Address = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU";

std::string winnerFileName() {
    std::ostringstream ss;
    ss << "WINNER_P71_" << static_cast<long long>(std::time(nullptr)) << ".enc";
    return ss.str();
}

bool writeEncryptedWinner(const std::string& filename,
                          const std::string& address,
                          const std::string& ciphertext) {
    const std::string payload =
        std::string("BTCPUZZLE-SECURE-V1\n") +
        "puzzle=71\n" +
        "address=" + address + "\n" +
        "encryption=RSA-OAEP\n" +
        "ciphertext_base64=" + ciphertext + "\n";

#ifdef _WIN32
    std::ofstream out(filename, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) return false;
    out.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    out.flush();
    return out.good();
#else
    const int fd = ::open(filename.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd < 0) return false;

    size_t written = 0;
    while (written < payload.size()) {
        const ssize_t n = ::write(fd, payload.data() + written, payload.size() - written);
        if (n <= 0) {
            ::close(fd);
            return false;
        }
        written += static_cast<size_t>(n);
    }

    const bool ok = (::fsync(fd) == 0);
    ::close(fd);
    return ok;
#endif
}

void hardenProcess() {
#ifndef _WIN32
    // Files created from this point default to owner-only permissions.
    ::umask(0077);

    // Never leave a private key behind in a crash/core dump.
    struct rlimit coreLimit;
    coreLimit.rlim_cur = 0;
    coreLimit.rlim_max = 0;
    ::setrlimit(RLIMIT_CORE, &coreLimit);

#ifdef __linux__
    // Prevent ptrace/core-style inspection by unrelated same-user processes.
    ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
#endif
}

[[noreturn]] void secureExit(int code) {
    std::cout.flush();
    std::cerr.flush();
    std::_Exit(code);
}
} // namespace

bool PoolClient::init() {
    hardenProcess();

    if (!upstream_init()) return false;

    // Hardened v1 is intentionally scoped to Puzzle 71 only.
    if (config.targetPuzzle != 71) {
        logMessage(DANGER, "[SECURITY] btcpuzzle-secure v1 only supports Puzzle 71");
        return false;
    }

    // A real winner must be encrypted locally before touching disk.
    if (!config.untrustedComputer || config.publicKeyString.empty() || publicKey == nullptr) {
        logMessage(DANGER, "[SECURITY] Puzzle 71 secure mode requires a valid RSA public key and untrusted_computer=true");
        return false;
    }

    // Winner secrets must never be sent to third-party notification endpoints
    // or stored in the btcpuzzle.info account by this hardened build.
    if (config.telegramShare || config.apiShare || config.saveKeyToBtcPuzzle) {
        logMessage(DANGER, "[SECURITY] Disable telegram_share, api_share and save_key for btcpuzzle-secure");
        return false;
    }

    logMessage(SUCCESS, "[SECURITY] Puzzle 71 hardened mode active");
    logMessage(SUCCESS, "[SECURITY] Winner key: local encryption only, no network sharing");
    return true;
}

RangeData PoolClient::getRange(int gpuIndex) {
    RangeData result = upstream_getRange(gpuIndex);
    if (!result.success) return result;

    // Never trust the pool to define the high-value target.
    if (result.targetAddress != kPuzzle71Address) {
        result.success = false;
        result.error = "SECURITY: API targetAddress does not match hardcoded Puzzle 71 address";
        logToFile(config.gpuIndex, "SECURITY getRange(): rejected targetAddress mismatch");
        return result;
    }

    // Prevent the real target from ever being downgraded to a proof address.
    if (std::find(result.proofOfWorkAddresses.begin(),
                  result.proofOfWorkAddresses.end(),
                  kPuzzle71Address) != result.proofOfWorkAddresses.end()) {
        result.success = false;
        result.error = "SECURITY: Puzzle 71 target appeared in proofOfWorkAddresses";
        logToFile(config.gpuIndex, "SECURITY getRange(): rejected Puzzle 71 target inside proof list");
        return result;
    }

    return result;
}

void PoolClient::onKeyFound(const std::string& address, const std::string& privateKey) {
    if (address != kPuzzle71Address) {
        upstream_onKeyFound(address, privateKey);
        return;
    }

    // From this point forward, do not call any upstream target notification
    // function. Preserve the winner first; secureExit() below terminates every
    // process thread, including any in-flight ping, without waiting on network I/O.
    if (publicKey == nullptr) {
        logToFile(config.gpuIndex, "SECURITY WINNER DETECTED but encryption key is unavailable; no secret written or transmitted");
        logMessage(DANGER, "[SECURITY] TARGET FOUND but local encryption is unavailable. Process terminating; plaintext was NOT saved.");
        secureExit(111);
    }

    const std::string encrypted = encryptData(privateKey);

    // Fail closed. encryptData() in upstream historically returned plaintext
    // when no key was loaded, so explicitly reject equality as well as empty output.
    if (encrypted.empty() || encrypted == privateKey) {
        logToFile(config.gpuIndex, "SECURITY WINNER DETECTED but encryption failed; no secret written or transmitted");
        logMessage(DANGER, "[SECURITY] TARGET FOUND but encryption failed. Process terminating; plaintext was NOT saved.");
        secureExit(112);
    }

    const std::string filename = winnerFileName();
    if (!writeEncryptedWinner(filename, address, encrypted)) {
        logToFile(config.gpuIndex, "SECURITY WINNER DETECTED but encrypted winner file could not be created; no secret transmitted");
        logMessage(DANGER, "[SECURITY] TARGET FOUND but encrypted winner file could not be created. Process terminating.");
        secureExit(113);
    }

    // Intentionally log only the event and public address. Never the ciphertext
    // and never the plaintext private key.
    logToFile(config.gpuIndex, std::string("SECURITY TARGET FOUND: ") + address + " | encrypted locally and fsynced | process terminating");

    std::cout << "\n========================================\n";
    std::cout << "[SECURITY] PUZZLE 71 TARGET FOUND\n";
    std::cout << "[SECURITY] Winner secret encrypted locally.\n";
    std::cout << "[SECURITY] Saved and fsynced to: " << filename << "\n";
    std::cout << "[SECURITY] Process terminating immediately.\n";
    std::cout << "========================================\n";

    // Immediate process termination ensures the unsafe upstream target branch in
    // main.cpp is never reached after this callback returns and avoids waiting
    // for ping/network threads before winner persistence.
    secureExit(0);
}
