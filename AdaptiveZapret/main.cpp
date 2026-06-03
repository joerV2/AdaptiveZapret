#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <windows.h>
#include <d3d11.h>
#include <tchar.h>
#include <string>
#include <thread>
#include <vector>
#include <map>
#include <atomic>
#include <fstream>
#include <filesystem>
#include <regex>
#include <sstream>
#include <ws2tcpip.h>
#include <securitybaseapi.h>
#include <shlwapi.h>
#include <random>
#include <chrono>
#include <mutex>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

#include "WinDivert.h"
#pragma comment(lib, "WinDivert.lib")

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include "sqlite3.h"

#include "Database.h"
#include "TrayIcon.h"

namespace fs = std::filesystem;

// -------------------------------------------------------------------
// Глобальные переменные
// -------------------------------------------------------------------
static HWND g_hWnd = nullptr;
static std::map<std::string, bool> scanningDomains;
static std::mutex blockcheckMutex;
static bool logAutoScroll = true;

// Очередь отложенных действий (чтобы не менять коллекции во время отрисовки)
enum class PendingAction { None, Delete, Cancel, Recheck };
static PendingAction g_PendingAction = PendingAction::None;
static std::string g_PendingActionDomain = "";

// -------------------------------------------------------------------
// Вспомогательная функция для получения пути к папке, где лежит .exe
// -------------------------------------------------------------------
static fs::path GetExeDirectory() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    return fs::path(path).parent_path();
}

// -------------------------------------------------------------------
// Установка / запуск драйвера WinDivert (из zapret-win-bundle-master)
// -------------------------------------------------------------------
static bool EnsureWinDivertDriver() {
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!schSCManager) return false;
    SC_HANDLE schService = OpenServiceA(schSCManager, "WinDivert", SERVICE_QUERY_STATUS | SERVICE_START);
    bool needCreate = false;
    if (!schService) needCreate = true;
    else {
        SERVICE_STATUS status;
        if (QueryServiceStatus(schService, &status) && status.dwCurrentState == SERVICE_RUNNING) {
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return true;
        }
        CloseServiceHandle(schService);
    }

    fs::path exeDir = GetExeDirectory();
    fs::path zapretDir = exeDir / "zapret-win-bundle-master";
    fs::path driverPath = zapretDir / "zapret-winws" / "WinDivert64.sys";
    if (!fs::exists(driverPath)) {
        MessageBoxW(NULL, L"WinDivert64.sys не найден в zapret-win-bundle-master/zapret-winws", L"Ошибка", MB_ICONERROR);
        CloseServiceHandle(schSCManager);
        return false;
    }

    if (needCreate) {
        schService = CreateServiceA(schSCManager, "WinDivert", "WinDivert",
            SERVICE_START | SERVICE_QUERY_STATUS, SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driverPath.string().c_str(),
            NULL, NULL, NULL, NULL, NULL);
        if (!schService) {
            MessageBoxW(NULL, L"Не удалось создать службу WinDivert.", L"Ошибка", MB_ICONERROR);
            CloseServiceHandle(schSCManager);
            return false;
        }
    }
    else {
        schService = OpenServiceA(schSCManager, "WinDivert", SERVICE_START | SERVICE_QUERY_STATUS);
        if (!schService) {
            CloseServiceHandle(schSCManager);
            return false;
        }
    }
    if (!StartServiceA(schService, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            MessageBoxW(NULL, L"Не удалось запустить драйвер WinDivert.", L"Ошибка", MB_ICONERROR);
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return false;
        }
    }
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return true;
}

// -------------------------------------------------------------------
// Работа с реестром (DoH, ZAPRET, встроенный DNS браузеров)
// -------------------------------------------------------------------
static void SaveZapretState(bool enabled) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\AdaptiveZapret", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD val = enabled ? 1 : 0;
        RegSetValueExA(hKey, "ZapretEnabled", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
}

static bool LoadZapretState() {
    HKEY hKey;
    DWORD val = 0;
    DWORD size = sizeof(val);
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\AdaptiveZapret", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "ZapretEnabled", NULL, NULL, (BYTE*)&val, &size);
        RegCloseKey(hKey);
    }
    return val == 1;
}

static void SaveDoHState(bool enabled) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\AdaptiveZapret", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD val = enabled ? 1 : 0;
        RegSetValueExA(hKey, "DoHEnabled", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
}

static bool LoadDoHState() {
    HKEY hKey;
    DWORD val = 1;
    DWORD size = sizeof(val);
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\AdaptiveZapret", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "DoHEnabled", NULL, NULL, (BYTE*)&val, &size);
        RegCloseKey(hKey);
    }
    return val == 1;
}

static void SetSystemDoH(bool enable) {
    HKEY hKey;
    DWORD value = enable ? 2 : 1;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "EnableAutoDoh", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hKey);
    }
    system("net stop dnscache > nul 2>&1 & net start dnscache > nul 2>&1");
    system("ipconfig /flushdns > nul 2>&1");
}

static void FlushDnsCache() {
    system("ipconfig /flushdns > nul 2>&1");
}

static void DisableBrowserBuiltInDns() {
    HKEY hKey;
    DWORD val = 0;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Policies\\Google\\Chrome", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "BuiltInDnsClientEnabled", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Edge", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "BuiltInDnsClientEnabled", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
}

static void RestoreBrowserBuiltInDns() {
    RegDeleteKeyValueA(HKEY_CURRENT_USER, "Software\\Policies\\Google\\Chrome", "BuiltInDnsClientEnabled");
    RegDeleteKeyValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Edge", "BuiltInDnsClientEnabled");
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Policies\\Google\\Chrome");
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Edge");
}

// -------------------------------------------------------------------
// Структура для отслеживания состояния конкретного сканирования домена
// -------------------------------------------------------------------
struct ScanContext {
    HANDLE hProcess = nullptr;
    HANDLE hJob = nullptr;
    bool cancelRequested = false;
};

// -------------------------------------------------------------------
// Scanner (запуск blockcheck с поддержкой отмены и Job Objects)
// -------------------------------------------------------------------
class Scanner {
public:
    static std::map<std::string, ScanContext> activeScans;
    static std::mutex scanMutex;
    static std::mutex blockcheckMutex;

    static void CancelCurrent(const std::string& domain) {
        std::lock_guard<std::mutex> lock(scanMutex);
        auto it = activeScans.find(domain);
        if (it != activeScans.end()) {
            it->second.cancelRequested = true;
            if (it->second.hJob) {
                TerminateJobObject(it->second.hJob, 0);
            }
            else if (it->second.hProcess) {
                TerminateProcess(it->second.hProcess, 0);
            }
        }
        else {
            activeScans[domain].cancelRequested = true;
        }
    }

    static std::vector<std::string> RunBlockCheck(const std::string& domain) {
        std::lock_guard<std::mutex> globalLock(blockcheckMutex);

        ScanContext* ctx = nullptr;
        {
            std::lock_guard<std::mutex> lock(scanMutex);
            if (activeScans.count(domain) && activeScans[domain].cancelRequested) {
                activeScans.erase(domain);
                return { "_CANCELLED_" };
            }
            activeScans[domain] = ScanContext();
            ctx = &activeScans[domain];
            ctx->hJob = CreateJobObjectA(NULL, NULL);
            if (ctx->hJob) {
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
                jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                SetInformationJobObject(ctx->hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
            }
        }

        OutputDebugStringA(("Scanner: starting blockcheck for " + domain + "\n").c_str());

        fs::path exeDir = GetExeDirectory();
        fs::path zapretDir = exeDir / "zapret-win-bundle-master";
        fs::path cygwinBin = zapretDir / "cygwin" / "bin";
        fs::path bashPath = cygwinBin / "bash.exe";

        fs::path curlPath = zapretDir / "cygwin" / "usr" / "local" / "bin" / "curl.exe";
        if (!fs::exists(curlPath)) {
            curlPath = cygwinBin / "curl.exe";
        }

        fs::path blockcheckDir = zapretDir / "blockcheck" / "zapret";
        fs::path blockcheckScript = blockcheckDir / "blockcheck.sh";

        fs::path tmpDir = exeDir / "tmp";
        if (!fs::exists(tmpDir)) {
            fs::create_directory(tmpDir);
            fs::permissions(tmpDir, fs::perms::all);
        }

        fs::path logPath = exeDir / "scan_result.log";
        fs::path debugPath = exeDir / "debug_log.txt";
        fs::path answersPath = exeDir / "temp_answers.txt";

        if (!fs::exists(bashPath) || !fs::exists(blockcheckScript)) {
            MessageBoxA(NULL, "bash.exe or blockcheck.sh not found in zapret-win-bundle-master", "Error", MB_ICONERROR);
            std::lock_guard<std::mutex> lock(scanMutex);
            if (ctx->hJob) CloseHandle(ctx->hJob);
            activeScans.erase(domain);
            return {};
        }

        auto toCygwinPath = [](const fs::path& p) -> std::string {
            std::string path = p.string();
            if (path.size() > 1 && path[1] == ':') {
                char drive = tolower(path[0]);
                path = "/cygdrive/" + std::string(1, drive) + path.substr(2);
                std::replace(path.begin(), path.end(), '\\', '/');
            }
            return path;
        };

        std::string cygwinScript = toCygwinPath(blockcheckScript);
        std::string cygwinLog = toCygwinPath(logPath);
        std::string cygwinBinPath = toCygwinPath(cygwinBin);
        std::string cygwinCurl = toCygwinPath(curlPath);
        std::string cygwinAnswers = toCygwinPath(answersPath);
        std::string windowsSystemPath = "/cygdrive/c/Windows/System32:/cygdrive/c/Windows/System32/WindowsPowerShell/v1.0";

        std::error_code ec;
        fs::remove(logPath, ec);
        fs::remove(answersPath, ec);

        std::ofstream outFile(answersPath);
        if (!outFile.is_open()) {
            OutputDebugStringA("Scanner: cannot create temp_answers.txt\n");
            std::lock_guard<std::mutex> lock(scanMutex);
            if (ctx->hJob) CloseHandle(ctx->hJob);
            activeScans.erase(domain);
            return {};
        }
        outFile << domain << "\n";
        outFile << "4\n";
        outFile << "Y\n";
        outFile << "Y\n";
        outFile << "N\n";
        outFile << "Y\n";
        outFile << "1\n";
        outFile << "N\n";
        outFile << "1\n";
        outFile.close();

        fs::path cygwinTmp = zapretDir / "cygwin" / "tmp";
        if (!fs::exists(cygwinTmp)) {
            fs::create_directory(cygwinTmp);
        }
        std::string createTmpCmd = "\"" + bashPath.string() + "\" -c \"mkdir -p /tmp\"";
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        CreateProcessA(NULL, (LPSTR)createTmpCmd.c_str(), NULL, NULL, FALSE, 0, NULL,
            cygwinBin.string().c_str(), &si, &pi);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        std::string command = "\"" + bashPath.string() + "\" -c \""
            "export PATH='" + cygwinBinPath + ":$PATH:" + windowsSystemPath + "'; "
            "export CURL='" + cygwinCurl + "'; "
            "export ZAPRET_BASE='" + toCygwinPath(blockcheckDir) + "'; "
            "export DOMAINS='" + domain + "'; "
            "export IPVS='4'; "
            "export ENABLE_HTTP='1'; "
            "export ENABLE_HTTPS_TLS12='1'; "
            "export ENABLE_HTTPS_TLS13='0'; "
            "export ENABLE_HTTP3='1'; "
            "export REPEATS='1'; "
            "export PARALLEL='0'; "
            "export SCANLEVEL='quic'; "
            "export BATCH='1'; "
            "export SECURE_DNS='0'; "
            "\"" + cygwinScript + "\" < \"" + cygwinAnswers + "\" > \"" + cygwinLog + "\" 2>&1\"";

        std::ofstream debug(debugPath, std::ios::app);
        debug << "=== RunBlockCheck for " << domain << " at " << time(nullptr) << "\n";
        debug << "Command: " << command << "\n";
        debug.close();

        si = { sizeof(si) };
        pi = { 0 };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        {
            std::lock_guard<std::mutex> lock(scanMutex);
            if (ctx->cancelRequested) {
                if (ctx->hJob) CloseHandle(ctx->hJob);
                activeScans.erase(domain);
                fs::remove(answersPath, ec);
                return { "_CANCELLED_" };
            }
        }

        if (!CreateProcessA(NULL, (LPSTR)command.c_str(), NULL, NULL, FALSE, 0, NULL,
            cygwinBin.string().c_str(), &si, &pi)) {
            DWORD err = GetLastError();
            debug.open(debugPath, std::ios::app);
            debug << "CreateProcess failed with error " << err << "\n";
            debug.close();

            std::lock_guard<std::mutex> lock(scanMutex);
            if (ctx->hJob) CloseHandle(ctx->hJob);
            activeScans.erase(domain);
            fs::remove(answersPath, ec);
            return {};
        }

        bool alreadyCancelled = false;
        {
            std::lock_guard<std::mutex> lock(scanMutex);
            if (ctx->cancelRequested) {
                alreadyCancelled = true;
                if (ctx->hJob) {
                    AssignProcessToJobObject(ctx->hJob, pi.hProcess);
                    TerminateJobObject(ctx->hJob, 0);
                }
                else {
                    TerminateProcess(pi.hProcess, 0);
                }
            }
            else {
                ctx->hProcess = pi.hProcess;
                if (ctx->hJob) {
                    AssignProcessToJobObject(ctx->hJob, pi.hProcess);
                }
            }
        }

        if (!alreadyCancelled) {
            while (true) {
                DWORD waitResult = WaitForSingleObject(pi.hProcess, 50);
                if (waitResult == WAIT_OBJECT_0) {
                    break;
                }
                std::lock_guard<std::mutex> lock(scanMutex);
                if (ctx->cancelRequested) {
                    alreadyCancelled = true;
                    break;
                }
            }
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        {
            std::lock_guard<std::mutex> lock(scanMutex);
            if (ctx->hJob) {
                CloseHandle(ctx->hJob);
            }
            activeScans.erase(domain);
        }

        if (alreadyCancelled) {
            fs::remove(answersPath, ec);
            return { "_CANCELLED_" };
        }

        std::ifstream logFile(logPath);
        std::string line;
        std::vector<std::string> strategies;
        bool inSummary = false;

        debug.open(debugPath, std::ios::app);
        debug << "Log file content:\n";
        while (std::getline(logFile, line)) {
            debug << line << "\n";
            if (line.find("* SUMMARY") != std::string::npos) {
                inSummary = true;
                continue;
            }
            if (inSummary && line.find("winws --") != std::string::npos) {
                if (line.find("working without bypass") != std::string::npos)
                    continue;
                size_t pos = line.find("winws --");
                if (pos != std::string::npos) {
                    std::string strategy = line.substr(pos);
                    while (!strategy.empty() && isspace(strategy.back()))
                        strategy.pop_back();
                    strategies.push_back(strategy);
                    debug << "Found strategy: " << strategy << "\n";
                }
            }
        }
        debug << "=== End of log ===\n";
        debug.close();

        fs::remove(answersPath, ec);
        return strategies;
    }
};

std::map<std::string, ScanContext> Scanner::activeScans;
std::mutex Scanner::scanMutex;
std::mutex Scanner::blockcheckMutex;

// -------------------------------------------------------------------
// DomainManager
// -------------------------------------------------------------------
class DomainManager {
private:
    static std::atomic<bool> newDataFlag;
public:
    static std::atomic<bool> isBlockcheckRunning;
    static std::vector<std::string> pendingDomains;
    static std::mutex pendingMutex;
    static std::mutex domainsMutex;
    static std::mutex databaseMutex;

    static void EmergencyReset() {
        {
            std::lock_guard<std::mutex> lock(Scanner::scanMutex);
            for (auto& pair : Scanner::activeScans) {
                pair.second.cancelRequested = true;
                if (pair.second.hJob) {
                    TerminateJobObject(pair.second.hJob, 0);
                }
                else if (pair.second.hProcess) {
                    TerminateProcess(pair.second.hProcess, 0);
                }
            }
            Scanner::activeScans.clear();
        }
        {
            std::lock_guard<std::mutex> lock(domainsMutex);
            scanningDomains.clear();
        }
        {
            std::lock_guard<std::mutex> lock(pendingMutex);
            pendingDomains.clear();
        }
        {
            std::lock_guard<std::mutex> dbLock(databaseMutex);
            std::vector<DomainRecord> allDomains = Database::GetAllDomains();
            for (const auto& dom : allDomains) {
                if (dom.status == u8"заблокирован (проверка)") {
                    Database::UpdateDomainStatus(dom.hostname, u8"остановлено (дебаг)");
                }
            }
        }
        newDataFlag = true;
        OutputDebugStringA("DomainManager: Emergency Reset completed.\n");
    }

    static void OnNewDomain(const std::string& domain, bool forceCheck = false) {
        {
            std::lock_guard<std::mutex> dbLock(databaseMutex);
            if (Database::IsDomainKnown(domain)) return;
        }
        {
            std::lock_guard<std::mutex> lock(domainsMutex);
            scanningDomains[domain] = true;
        }
        if (!forceCheck) {
            bool reachable = IsReachable(domain);
            if (reachable) {
                {
                    std::lock_guard<std::mutex> dbLock(databaseMutex);
                    Database::AddDomain(domain, u8"чистый");
                }
                newDataFlag = true;
                {
                    std::lock_guard<std::mutex> lock(domainsMutex);
                    scanningDomains.erase(domain);
                }
                return;
            }
        }
        {
            std::lock_guard<std::mutex> dbLock(databaseMutex);
            Database::AddDomain(domain, u8"заблокирован (проверка)");
        }
        newDataFlag = true;

        std::thread([domain]() {
            auto strategies = Scanner::RunBlockCheck(domain);
            {
                std::lock_guard<std::mutex> lock(domainsMutex);
                scanningDomains.erase(domain);
            }
            if (!strategies.empty() && strategies[0] == "_CANCELLED_") {
                newDataFlag = true;
                return;
            }
            {
                std::lock_guard<std::mutex> dbLock(databaseMutex);
                auto dom = Database::GetDomainByHostname(domain);
                if (dom.id != -1) {
                    Database::ClearStrategiesForDomain(dom.id);
                    for (const auto& s : strategies) {
                        Database::AddStrategy(dom.id, s);
                    }
                    if (!strategies.empty()) {
                        Database::UpdateActiveStrategy(domain, strategies[0]);
                        Database::UpdateDomainStatus(domain, u8"стратегии найдены");
                    }
                    else {
                        if (IsReachable(domain)) {
                            Database::UpdateDomainStatus(domain, u8"чистый");
                        }
                        else {
                            Database::UpdateDomainStatus(domain, u8"стратегий не найдено");
                        }
                    }
                }
            }
            newDataFlag = true;
            }).detach();
    }

    static void ForceRecheckDomain(const std::string& domain) {
        {
            std::lock_guard<std::mutex> dbLock(databaseMutex);
            auto dom = Database::GetDomainByHostname(domain);
            if (dom.id == -1) return;
            Database::ClearStrategiesForDomain(dom.id);
            Database::UpdateDomainStatus(domain, u8"заблокирован (проверка)");
            Database::UpdateActiveStrategy(domain, "");
        }
        {
            std::lock_guard<std::mutex> lock(domainsMutex);
            scanningDomains[domain] = true;
        }
        newDataFlag = true;

        std::thread([domain]() {
            auto strategies = Scanner::RunBlockCheck(domain);
            {
                std::lock_guard<std::mutex> lock(domainsMutex);
                scanningDomains.erase(domain);
            }
            if (!strategies.empty() && strategies[0] == "_CANCELLED_") {
                newDataFlag = true;
                return;
            }
            {
                std::lock_guard<std::mutex> dbLock(databaseMutex);
                auto dom = Database::GetDomainByHostname(domain);
                if (dom.id != -1) {
                    Database::ClearStrategiesForDomain(dom.id);
                    for (const auto& s : strategies) {
                        Database::AddStrategy(dom.id, s);
                    }
                    if (!strategies.empty()) {
                        Database::UpdateActiveStrategy(domain, strategies[0]);
                        Database::UpdateDomainStatus(domain, u8"решения найдены");
                    }
                    else {
                        if (IsReachable(domain)) {
                            Database::UpdateDomainStatus(domain, u8"чистый");
                        }
                        else {
                            Database::UpdateDomainStatus(domain, u8"решений не найдено");
                        }
                    }
                }
            }
            newDataFlag = true;
            }).detach();
    }

    static void CancelScan(const std::string& domain) {
        Scanner::CancelCurrent(domain);
        {
            std::lock_guard<std::mutex> lock(domainsMutex);
            scanningDomains.erase(domain);
        }
        {
            std::lock_guard<std::mutex> lock(pendingMutex);
            auto it = std::find(pendingDomains.begin(), pendingDomains.end(), domain);
            if (it != pendingDomains.end()) pendingDomains.erase(it);
        }
        {
            std::lock_guard<std::mutex> dbLock(databaseMutex);
            auto dom = Database::GetDomainByHostname(domain);
            if (dom.id != -1 && dom.status == u8"заблокирован (проверка)") {
                Database::UpdateDomainStatus(domain, u8"отменено");
            }
        }
        newDataFlag = true;
    }

    static void DeleteDomain(const std::string& domain) {
        {
            std::lock_guard<std::mutex> dbLock(databaseMutex);
            auto dom = Database::GetDomainByHostname(domain);
            if (dom.id != -1) {
                Database::ClearStrategiesForDomain(dom.id);
                Database::DeleteDomain(domain);
            }
        }
        {
            std::lock_guard<std::mutex> lock(domainsMutex);
            scanningDomains.erase(domain);
        }
        {
            std::lock_guard<std::mutex> lock(pendingMutex);
            auto it = std::find(pendingDomains.begin(), pendingDomains.end(), domain);
            if (it != pendingDomains.end()) pendingDomains.erase(it);
        }
        newDataFlag = true;
    }

    static bool HasNewData() {
        bool val = newDataFlag.load();
        if (val) newDataFlag = false;
        return val;
    }

private:
    static bool IsReachable(const std::string& hostname) {
        if (CheckHttp(hostname, 80)) return true;
        if (TcpConnect(hostname, 443)) return true;
        return false;
    }

    static bool CheckHttp(const std::string& hostname, int port) {
        SOCKET sock = CreateSocket(hostname, port);
        if (sock == INVALID_SOCKET) return false;
        std::string request = "HEAD / HTTP/1.0\r\nHost: " + hostname + "\r\nConnection: close\r\n\r\n";
        if (send(sock, request.c_str(), (int)request.size(), 0) == SOCKET_ERROR) {
            closesocket(sock);
            return false;
        }
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        int ret = select(0, &fds, NULL, NULL, &tv);
        if (ret <= 0) {
            closesocket(sock);
            return false;
        }
        char buffer[256];
        int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        closesocket(sock);
        if (received <= 0) return false;
        buffer[received] = '\0';
        return (strncmp(buffer, "HTTP/", 5) == 0);
    }

    static SOCKET CreateSocket(const std::string& hostname, int port) {
        addrinfo hints = {}, * res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(hostname.c_str(), std::to_string(port).c_str(), &hints, &res) != 0)
            return INVALID_SOCKET;
        SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock == INVALID_SOCKET) {
            freeaddrinfo(res);
            return INVALID_SOCKET;
        }
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
        connect(sock, res->ai_addr, (int)res->ai_addrlen);
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        timeval tv;
        tv.tv_sec = 4;
        tv.tv_usec = 0;
        int ret = select(0, nullptr, &fdset, nullptr, &tv);
        if (ret <= 0) {
            closesocket(sock);
            freeaddrinfo(res);
            return INVALID_SOCKET;
        }
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
        freeaddrinfo(res);
        return sock;
    }

    static bool TcpConnect(const std::string& hostname, int port) {
        SOCKET sock = CreateSocket(hostname, port);
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
            return true;
        }
        return false;
    }
};

std::atomic<bool> DomainManager::newDataFlag(false);
std::atomic<bool> DomainManager::isBlockcheckRunning(false);
std::vector<std::string> DomainManager::pendingDomains;
std::mutex DomainManager::pendingMutex;
std::mutex DomainManager::domainsMutex;
std::mutex DomainManager::databaseMutex;

// -------------------------------------------------------------------
// Sniffer (без изменений)
// -------------------------------------------------------------------
class Sniffer {
private:
    static std::atomic<bool> running;
    static std::thread worker;
    static HANDLE handle;

    static void SnifferThread() {
        handle = WinDivertOpen("(udp.DstPort == 53 or tcp.DstPort == 53)",
            WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF);
        if (handle == INVALID_HANDLE_VALUE) {
            OutputDebugStringA("Sniffer: WinDivertOpen failed\n");
            return;
        }
        char packet[4096];
        WINDIVERT_ADDRESS addr;
        UINT packetLen;
        while (running) {
            if (!WinDivertRecv(handle, packet, sizeof(packet), &packetLen, &addr)) {
                if (!running) break;
                continue;
            }
            std::string domain = ExtractDomainFromDNS(packet, packetLen);
            if (!domain.empty()) {
                OutputDebugStringA(("Sniffer: " + domain + "\n").c_str());
                DomainManager::OnNewDomain(domain, false);
            }
        }
        WinDivertClose(handle);
        handle = INVALID_HANDLE_VALUE;
    }

    static std::string ExtractDomainFromDNS(const char* packet, UINT len) {
        if (len < 28) return "";
        const unsigned char* udpPayload = (const unsigned char*)packet + 20 + 8;
        size_t payloadLen = len - 28;
        if (payloadLen < 12) return "";
        const unsigned char* dns = udpPayload + 12;
        size_t pos = 0;
        std::string domain;
        while (pos < payloadLen - 12) {
            unsigned char labelLen = dns[pos++];
            if (labelLen == 0) break;
            if (labelLen & 0xC0) break;
            if (pos + labelLen > payloadLen - 12) break;
            if (!domain.empty()) domain += '.';
            domain.append((const char*)(dns + pos), labelLen);
            pos += labelLen;
        }
        return domain;
    }

public:
    static void Start() {
        if (running) return;
        HANDLE test = WinDivertOpen("false", WINDIVERT_LAYER_NETWORK, 0, 0);
        if (test == INVALID_HANDLE_VALUE) {
            MessageBoxW(NULL, L"Драйвер WinDivert не установлен или не запущен.\nПожалуйста, перезапустите программу от имени администратора.", L"WinDivert Error", MB_ICONERROR);
            return;
        }
        WinDivertClose(test);
        running = true;
        worker = std::thread(SnifferThread);
    }

    static void Stop() {
        running = false;
        if (handle != INVALID_HANDLE_VALUE) {
            WinDivertClose(handle);
            handle = INVALID_HANDLE_VALUE;
        }
        if (worker.joinable()) worker.join();
    }

    static bool IsRunning() { return running; }
};

std::atomic<bool> Sniffer::running(false);
std::thread Sniffer::worker;
HANDLE Sniffer::handle = INVALID_HANDLE_VALUE;

// -------------------------------------------------------------------
// ZapretController (исправленный: без глобальных фильтров, с логированием)
// -------------------------------------------------------------------
class ZapretController {
private:
    static PROCESS_INFORMATION pi;
    static bool isRunning;

    // Вспомогательная функция для исправления путей к .bin файлам
    static std::string FixBinPath(const std::string& params, const fs::path& winwsDir) {
        std::string result = params;
        std::regex binPathRegex(R"((\"?[^\s\"]+\.bin\"?))");
        std::smatch match;
        if (std::regex_search(params, match, binPathRegex)) {
            std::string originalPath = match[1].str();
            if (originalPath.front() == '"') originalPath.erase(0, 1);
            if (originalPath.back() == '"') originalPath.pop_back();
            fs::path binFile;
            // Если путь абсолютный (содержит : или начинается с /cygdrive), преобразуем в относительный
            if (originalPath.find(":") != std::string::npos || originalPath.find("/cygdrive/") == 0) {
                std::string winPath = originalPath;
                if (winPath.find("/cygdrive/") == 0) {
                    winPath.erase(0, 10);
                    winPath[0] = toupper(winPath[0]);
                    winPath[1] = ':';
                    std::replace(winPath.begin(), winPath.end(), '/', '\\');
                }
                binFile = winPath;
                // Вычисляем относительный путь от winwsDir
                fs::path relative = fs::relative(binFile, winwsDir);
                std::string relPath = relative.string();
                std::replace(relPath.begin(), relPath.end(), '\\', '/');
                result = std::regex_replace(result, std::regex(originalPath), relPath, std::regex_constants::format_first_only);
            }
        }
        return result;
    }

public:
    static bool GenerateDomainLists() {
        fs::path exeDir = GetExeDirectory();
        fs::path strategiesDir = exeDir / "strategies";
        if (!fs::exists(strategiesDir)) fs::create_directory(strategiesDir);

        for (const auto& entry : fs::directory_iterator(strategiesDir)) {
            std::string name = entry.path().filename().string();
            if (name.rfind("domains_", 0) == 0 || name.rfind("params_", 0) == 0)
                fs::remove(entry.path());
        }

        auto domains = Database::GetAllDomains();
        std::map<std::string, std::vector<std::string>> strategyDomains;
        for (const auto& d : domains) {
            if (!d.active_strategy.empty() && d.active_strategy != u8"чистый") {
                std::string strategy = d.active_strategy;
                if (strategy.rfind("winws ", 0) == 0)
                    strategy = strategy.substr(6);
                strategyDomains[strategy].push_back(d.hostname);
            }
        }

        for (const auto& [strat, hosts] : strategyDomains) {
            size_t hash = std::hash<std::string>{}(strat);
            std::string hashStr = std::to_string(hash);
            fs::path domainsFile = strategiesDir / ("domains_" + hashStr + ".txt");
            fs::path paramsFile = strategiesDir / ("params_" + hashStr + ".txt");

            std::ofstream outDom(domainsFile);
            if (outDom.is_open()) {
                for (const auto& h : hosts) outDom << h << "\n";
                outDom.close();
            }
            std::ofstream outParams(paramsFile);
            if (outParams.is_open()) {
                outParams << strat << "\n";
                outParams.close();
            }
        }
        return true;
    }

    static bool Start() {
        if (isRunning) return true;
        if (!GenerateDomainLists()) return false;

        fs::path exeDir = GetExeDirectory();
        fs::path zapretDir = exeDir / "zapret-win-bundle-master";
        fs::path winwsExe = zapretDir / "zapret-winws" / "winws.exe";
        fs::path strategiesDir = exeDir / "strategies";

        if (!fs::exists(winwsExe)) {
            MessageBoxA(NULL, "winws.exe not found in zapret-win-bundle-master/zapret-winws", "Error", MB_ICONERROR);
            return false;
        }

        // Глобальные фильтры (как в bat-файлах)
        std::string cmdLine = "\"" + winwsExe.string() + "\"";
        cmdLine += " --wf-tcp=80,443,2053,2083,2087,2096,8443 --wf-udp=443,19294-19344,50000-50100";

        // Опциональное логирование (можно закомментировать после отладки)
        //cmdLine += " --debug=@winws.log --debug-level=2 --hostlist-auto-debug=hostlist.log";

        // Сбор всех блоков стратегий (hostlist + параметры)
        std::vector<std::string> blocks;
        for (const auto& entry : fs::directory_iterator(strategiesDir)) {
            std::string name = entry.path().filename().string();
            if (name.rfind("domains_", 0) == 0 && name.size() > 4 && name.substr(name.size() - 4) == ".txt") {
                std::string hashStr = name.substr(8, name.size() - 12);
                fs::path paramsFile = strategiesDir / ("params_" + hashStr + ".txt");
                if (!fs::exists(paramsFile)) continue;

                std::ifstream paramsStream(paramsFile);
                std::string strategyParams;
                std::getline(paramsStream, strategyParams);
                paramsStream.close();

                // 1. Заменяем --wf-tcp=... на --filter-tcp=...
                std::regex wfTcpRegex(R"(\s*--wf-tcp=([0-9,]+)\s*)");
                strategyParams = std::regex_replace(strategyParams, wfTcpRegex, " --filter-tcp=$1 ");
                // 2. Заменяем --wf-udp=... на --filter-udp=...
                std::regex wfUdpRegex(R"(\s*--wf-udp=([0-9,]+)\s*)");
                strategyParams = std::regex_replace(strategyParams, wfUdpRegex, " --filter-udp=$1 ");
                // 3. Удаляем --wf-l3=ipv4
                strategyParams = std::regex_replace(strategyParams, std::regex(R"(\s*--wf-l3=ipv4\s*)"), " ");
                // 4. Убираем лишние пробелы
                strategyParams = std::regex_replace(strategyParams, std::regex("\\s+"), " ");
                if (!strategyParams.empty() && strategyParams.front() == ' ') strategyParams.erase(0, 1);
                if (!strategyParams.empty() && strategyParams.back() == ' ') strategyParams.pop_back();

                // 5. Исправляем пути к .bin файлам (относительно winws.exe)
                strategyParams = FixBinPath(strategyParams, zapretDir / "zapret-winws");

                // Формируем строку блока: hostlist + параметры
                std::string block = " --hostlist=\"" + entry.path().string() + "\"";
                if (!strategyParams.empty()) {
                    block += " " + strategyParams;
                }
                blocks.push_back(block);
            }
        }

        // Добавляем блоки в командную строку
        if (blocks.size() == 1) {
            // Один блок – без --new
            cmdLine += blocks[0];
        }
        else if (blocks.size() > 1) {
            // Первый блок без --new, остальные с --new
            for (size_t i = 0; i < blocks.size(); ++i) {
                if (i == 0) {
                    cmdLine += blocks[i];
                }
                else {
                    cmdLine += " --new" + blocks[i];
                }
            }
        }

        // Сохраняем команду в файл для диагностики
        OutputDebugStringA(("winws command: " + cmdLine + "\n").c_str());
        fs::path logCmdPath = exeDir / "winws_command_last.txt";
        std::ofstream logCmd(logCmdPath);
        logCmd << cmdLine;
        logCmd.close();

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;   // можно SW_SHOW для отладки

        if (!CreateProcessA(NULL, (LPSTR)cmdLine.c_str(), NULL, NULL, FALSE, 0, NULL,
            zapretDir.string().c_str(), &si, &pi)) {
            DWORD err = GetLastError();
            char msg[256];
            sprintf_s(msg, "CreateProcess failed with error %lu", err);
            MessageBoxA(NULL, msg, "winws start error", MB_ICONERROR);
            return false;
        }

        isRunning = true;
        SaveZapretState(true);
        ZapretController::pi = pi;
        return true;
    }

    static void Stop() {
        if (!isRunning) return;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        isRunning = false;
        SaveZapretState(false);
    }

    static void Restart() {
        Stop();
        Start();
    }

    static bool IsRunning() { return isRunning; }
};

PROCESS_INFORMATION ZapretController::pi = {};
bool ZapretController::isRunning = false;

// -------------------------------------------------------------------
// DirectX и глобальные переменные GUI
// -------------------------------------------------------------------
static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();

static std::vector<DomainRecord> domains;
static std::map<int, std::vector<std::string>> domainStrategies;
static std::map<int, int> selectedStrategyIdx;
static std::map<int, int> originalStrategyIdx;
static bool unsavedChanges = false;
static char searchBuffer[128] = "";
static bool showAddDomainPopup = false;
static char newDomainBuffer[4096] = "";

void RefreshDomainList() {
    domains = Database::GetAllDomains();
    domainStrategies.clear();
    selectedStrategyIdx.clear();
    originalStrategyIdx.clear();
    for (auto& d : domains) {
        auto strategies = Database::GetStrategiesForDomain(d.id);
        domainStrategies[d.id] = strategies;
        int idx = 0;
        if (!d.active_strategy.empty()) {
            auto it = std::find(strategies.begin(), strategies.end(), d.active_strategy);
            if (it != strategies.end()) idx = it - strategies.begin();
        }
        selectedStrategyIdx[d.id] = idx;
        originalStrategyIdx[d.id] = idx;
    }
}

void ApplyChanges() {
    for (auto& d : domains) {
        int newIdx = selectedStrategyIdx[d.id];
        if (newIdx != originalStrategyIdx[d.id]) {
            auto& stratList = domainStrategies[d.id];
            if (newIdx >= 0 && newIdx < (int)stratList.size()) {
                Database::UpdateActiveStrategy(d.hostname, stratList[newIdx]);
            }
        }
    }
    for (auto& d : domains) {
        originalStrategyIdx[d.id] = selectedStrategyIdx[d.id];
    }
    unsavedChanges = false;
}

void ApplyAndRegenerate() {
    ApplyChanges();
    ZapretController::GenerateDomainLists();
    if (ZapretController::IsRunning()) ZapretController::Restart();
    RefreshDomainList();
}

void CancelChanges() {
    for (auto& d : domains) {
        selectedStrategyIdx[d.id] = originalStrategyIdx[d.id];
    }
    unsavedChanges = false;
}

bool DomainMatchesFilter(const DomainRecord& d, const char* filter) {
    if (strlen(filter) == 0) return true;
    std::string haystack = d.hostname + " " + d.status;
    std::string needle = filter;
    std::transform(haystack.begin(), haystack.end(), haystack.begin(), ::tolower);
    std::transform(needle.begin(), needle.end(), needle.begin(), ::tolower);
    return haystack.find(needle) != std::string::npos;
}

void ShowAddDomainPopup() {
    if (!showAddDomainPopup) return;
    ImGui::OpenPopup(u8"Домен(ы)");
    if (ImGui::BeginPopupModal(u8"Домен(ы)", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText(u8"Домен(ы)", newDomainBuffer, IM_ARRAYSIZE(newDomainBuffer));
        ImGui::TextWrapped(u8"При добавлении нескольких доменов, разделяйте пробелом");
        if (ImGui::Button(u8"OK")) {
            if (strlen(newDomainBuffer) > 0) {
                std::string domainsStr = newDomainBuffer;
                std::stringstream ss(domainsStr);
                std::string domain;
                while (ss >> domain) {
                    if (!domain.empty()) {
                        std::thread([domain]() { DomainManager::OnNewDomain(domain, true); }).detach();
                    }
                }
                newDomainBuffer[0] = '\0';
                showAddDomainPopup = false;
                ImGui::CloseCurrentPopup();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button(u8"Отмена")) {
            newDomainBuffer[0] = '\0';
            showAddDomainPopup = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void RenderUI() {
    // Обработка отложенных действий (безопасно, вне цикла отрисовки таблицы)
    if (g_PendingAction != PendingAction::None && !g_PendingActionDomain.empty()) {
        switch (g_PendingAction) {
        case PendingAction::Delete: DomainManager::DeleteDomain(g_PendingActionDomain); break;
        case PendingAction::Cancel: DomainManager::CancelScan(g_PendingActionDomain); break;
        case PendingAction::Recheck: DomainManager::ForceRecheckDomain(g_PendingActionDomain); break;
        default: break;
        }
        g_PendingAction = PendingAction::None;
        g_PendingActionDomain = "";
        RefreshDomainList();
    }

    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize, ImGuiCond_Always);
    ImGui::Begin("AdaptiveZapret", nullptr, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

    bool hasActive = false;
    {
        std::lock_guard<std::mutex> lock(DomainManager::domainsMutex);
        hasActive = !scanningDomains.empty();
    }
    if (hasActive) {
        ImGui::SameLine(ImGui::GetWindowWidth() - 250);
        ImGui::TextColored(ImVec4(1, 1, 0, 1), "SCAN ACTIVE");
        if (ImGui::IsItemHovered()) ImGui::SetTooltip(u8"Blockcheck выполняется для одного или нескольких доменов");
    }

    ImGui::SetCursorPosY(0);
    ImGui::InvisibleButton("drag_handle", ImVec2(ImGui::GetWindowWidth(), 30));
    static bool dragging = false;
    static POINT dragStartPos;
    static RECT dragStartWindowRect;
    if (ImGui::IsItemActivated()) {
        GetCursorPos(&dragStartPos);
        GetWindowRect(g_hWnd, &dragStartWindowRect);
        dragging = true;
    }
    if (dragging && ImGui::IsItemActive() && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
        POINT currentPos;
        GetCursorPos(&currentPos);
        int deltaX = currentPos.x - dragStartPos.x;
        int deltaY = currentPos.y - dragStartPos.y;
        SetWindowPos(g_hWnd, NULL,
            dragStartWindowRect.left + deltaX,
            dragStartWindowRect.top + deltaY,
            0, 0, SWP_NOSIZE | SWP_NOZORDER);
    }
    if (ImGui::IsItemDeactivated()) dragging = false;
    if (ImGui::IsItemHovered()) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeAll);
    ImGui::SetCursorPosY(30);

    if (ImGui::BeginTabBar("MainTabs")) {
        if (ImGui::BeginTabItem(u8"Управление")) {
            static bool zapretState = ZapretController::IsRunning();
            static bool snifferState = Sniffer::IsRunning();
            static bool dohState = LoadDoHState();

            if (ImGui::Button(zapretState ? u8"Остановить ZAPRET" : u8"Запустить ZAPRET", ImVec2(220, 0))) {
                if (zapretState) ZapretController::Stop();
                else ZapretController::Start();
                zapretState = ZapretController::IsRunning();
            }
            if (ImGui::Button(u8"Перезапуск ZAPRET", ImVec2(220, 0))) {
                ZapretController::Restart();
                zapretState = ZapretController::IsRunning();
            }
            if (ImGui::Button(snifferState ? u8"Выключить сниффер" : u8"Включить сниффер", ImVec2(220, 0))) {
                if (snifferState) Sniffer::Stop();
                else Sniffer::Start();
                snifferState = Sniffer::IsRunning();
            }
            if (ImGui::Button(u8"Обновить списки", ImVec2(220, 0))) {
                ZapretController::GenerateDomainLists();
                if (zapretState) ZapretController::Restart();
            }
            ImGui::Separator();

            bool newDohState = dohState;
            ImGui::Checkbox(u8"Включить DoH (DNS over HTTPS)", &newDohState);
            if (newDohState != dohState) {
                dohState = newDohState;
                SetSystemDoH(dohState);
                SaveDoHState(dohState);
                ImGui::OpenPopup("DoHChanged");
            }
            if (ImGui::BeginPopupModal("DoHChanged", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                ImGui::Text(u8"Настройка DoH изменена. Для полного применения\nрекомендуется перезапустить браузеры.");
                if (ImGui::Button(u8"OK")) ImGui::CloseCurrentPopup();
                ImGui::EndPopup();
            }
            ImGui::TextWrapped(u8"DoH - способ шифровки DNS-трафика браузеров.\nДля автоматического обнаружения доменов через сниффер необходимо выключить DoH.\nНе забудьте включить DoH обратно после использования сниффера!");
            if (ImGui::Button(u8"Очистить DNS-кэш", ImVec2(220, 0))) {
                FlushDnsCache();
            }
            ImGui::Separator();

            if (ImGui::Button(u8"Откл. встроенный DNS браузеров", ImVec2(270, 0))) {
                DisableBrowserBuiltInDns();
                ImGui::OpenPopup("BrowserDnsDisabled");
            }
            if (ImGui::BeginPopupModal("BrowserDnsDisabled", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                ImGui::Text(u8"Изменения вступят в силу после перезапуска браузеров.");
                if (ImGui::Button(u8"OK")) ImGui::CloseCurrentPopup();
                ImGui::EndPopup();
            }
            ImGui::SameLine();
            if (ImGui::Button(u8"Восстановить DNS браузеров", ImVec2(270, 0))) {
                RestoreBrowserBuiltInDns();
                ImGui::OpenPopup("BrowserDnsRestored");
            }
            if (ImGui::BeginPopupModal("BrowserDnsRestored", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                ImGui::Text(u8"Настройки DNS браузеров восстановлены.\nРекомендуется перезапустить браузеры.");
                if (ImGui::Button(u8"OK")) ImGui::CloseCurrentPopup();
                ImGui::EndPopup();
            }
            ImGui::TextWrapped(u8"Некоторые браузеры дополнительно шифруют трафик через встроенные DNS, в основном браузеры на chromium. Для автоматического получения ссылок из таких браузеров необходимо отключать встроенные DNS. Не забудьте включить DNS обратно после использования сниффера!");

            ImGui::Separator();
            if (ImGui::Button(u8"Свернуть в трей", ImVec2(220, 0))) {
                ShowWindow(GetActiveWindow(), SW_HIDE);
            }
            if (ImGui::Button(u8"Выключить AdaptiveZapret", ImVec2(220, 0))) {
                PostQuitMessage(0);
            }
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem(u8"Список доменов")) {
            bool snifferOn = Sniffer::IsRunning();

            if (snifferOn) {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.5f, 0.0f, 1.0f));
                ImGui::TextWrapped(u8"Сниффер включён, редактирование таблицы невозможно");
                ImGui::PopStyleColor();
                ImGui::Separator();
            }

            ImGui::InputText(u8"Поиск", searchBuffer, IM_ARRAYSIZE(searchBuffer));

            if (!DomainManager::pendingDomains.empty()) {
                ImGui::Separator();
                ImGui::TextColored(ImVec4(1, 1, 0, 1), u8"Очередь проверок:");
                for (size_t i = 0; i < DomainManager::pendingDomains.size(); ++i) {
                    ImGui::PushID(i);
                    ImGui::Text("%s", DomainManager::pendingDomains[i].c_str());
                    ImGui::SameLine();
                    if (ImGui::SmallButton(u8"Удалить")) {
                        std::lock_guard<std::mutex> lock(DomainManager::pendingMutex);
                        std::string dom = DomainManager::pendingDomains[i];
                        DomainManager::pendingDomains.erase(DomainManager::pendingDomains.begin() + i);
                        {
                            std::lock_guard<std::mutex> lock2(DomainManager::domainsMutex);
                            scanningDomains.erase(dom);
                        }
                        RefreshDomainList();
                        ImGui::PopID();
                        break;
                    }
                    ImGui::PopID();
                }
                if (ImGui::Button(u8"Очистить очередь")) {
                    std::lock_guard<std::mutex> lock(DomainManager::pendingMutex);
                    for (const auto& d : DomainManager::pendingDomains) {
                        std::lock_guard<std::mutex> lock2(DomainManager::domainsMutex);
                        scanningDomains.erase(d);
                    }
                    DomainManager::pendingDomains.clear();
                    RefreshDomainList();
                }
                ImGui::Separator();
            }

            auto disabledIfSniffer = [snifferOn]() {
                if (snifferOn) {
                    ImGui::PushItemFlag(ImGuiItemFlags_Disabled, true);
                    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * 0.5f);
                }
            };
            auto enabledIfSniffer = [snifferOn]() {
                if (snifferOn) {
                    ImGui::PopItemFlag();
                    ImGui::PopStyleVar();
                }
            };

            disabledIfSniffer();
            if (ImGui::Button(u8"Добавить домен")) showAddDomainPopup = true;
            enabledIfSniffer();
            ImGui::SameLine();

            disabledIfSniffer();
            if (ImGui::Button(u8"Обновить список (применить и перезапустить)")) ApplyAndRegenerate();
            if (ImGui::Button(u8"Сбросить все застрявшие проверки")) {
                DomainManager::EmergencyReset();
            }
            enabledIfSniffer();
            ImGui::SameLine();

            disabledIfSniffer();
            if (ImGui::Button(u8"Перечитать из БД")) {
                if (!unsavedChanges || !snifferOn) RefreshDomainList();
                else ImGui::OpenPopup(u8"Несохранённые изменения");
            }
            enabledIfSniffer();

            if (ImGui::BeginPopup(u8"Несохранённые изменения")) {
                ImGui::Text(u8"Есть несохранённые изменения. Сначала сохраните или отмените.");
                ImGui::EndPopup();
            }

            if (!snifferOn && unsavedChanges) {
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(1, 1, 0, 1), u8"Есть несохранённые изменения!");
                ImGui::SameLine();
                if (ImGui::Button(u8"Сохранить и применить")) ApplyAndRegenerate();
                ImGui::SameLine();
                if (ImGui::Button(u8"Отмена")) CancelChanges();
            }

            float tableHeight = ImGui::GetContentRegionAvail().y - 400.0f;
            if (tableHeight < 250.0f) tableHeight = 250.0f;
            ImGui::BeginChild("DomainsTable", ImVec2(0, tableHeight), true);
            if (ImGui::BeginTable("table", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn(u8"Домен");
                ImGui::TableSetupColumn(u8"Статус");
                ImGui::TableSetupColumn(u8"Активная стратегия");
                ImGui::TableSetupColumn(u8"Действия", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                ImGui::TableHeadersRow();

                for (auto& d : domains) {
                    if (!DomainMatchesFilter(d, searchBuffer)) continue;

                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextUnformatted(d.hostname.c_str());

                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(d.status.c_str());

                    ImGui::TableSetColumnIndex(2);
                    bool isScanning = false;
                    {
                        std::lock_guard<std::mutex> lock(DomainManager::domainsMutex);
                        isScanning = (scanningDomains.find(d.hostname) != scanningDomains.end());
                    }
                    if (isScanning) {
                        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), u8"Идёт проверка...");
                    }
                    else {
                        auto& strategies = domainStrategies[d.id];
                        if (!strategies.empty()) {
                            std::vector<const char*> items;
                            items.reserve(strategies.size());
                            for (const auto& s : strategies) items.push_back(s.c_str());
                            int current = selectedStrategyIdx[d.id];

                            if (snifferOn) {
                                ImGui::PushItemFlag(ImGuiItemFlags_Disabled, true);
                                ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * 0.5f);
                            }
                            if (ImGui::Combo(("##strat_" + std::to_string(d.id)).c_str(), &current, items.data(), (int)items.size())) {
                                if (!snifferOn) {
                                    selectedStrategyIdx[d.id] = current;
                                    if (current != originalStrategyIdx[d.id]) unsavedChanges = true;
                                }
                            }
                            if (snifferOn) {
                                ImGui::PopItemFlag();
                                ImGui::PopStyleVar();
                            }
                        }
                        else {
                            ImGui::TextDisabled(u8"нет стратегий");
                        }
                    }

                    ImGui::TableSetColumnIndex(3);
                    if (!snifferOn) {
                        bool isPending = false;
                        {
                            std::lock_guard<std::mutex> pLock(DomainManager::pendingMutex);
                            isPending = (std::find(DomainManager::pendingDomains.begin(), DomainManager::pendingDomains.end(), d.hostname) != DomainManager::pendingDomains.end());
                        }

                        if (isScanning || isPending) {
                            if (ImGui::Button((u8"Отм##" + std::to_string(d.id)).c_str())) {
                                g_PendingActionDomain = d.hostname;
                                g_PendingAction = PendingAction::Cancel;
                            }
                            if (ImGui::IsItemHovered()) ImGui::SetTooltip(u8"Отменить проверку домена");
                            ImGui::SameLine();
                            ImGui::TextDisabled(u8"---");
                        }
                        else {
                            if (ImGui::Button((u8"X##" + std::to_string(d.id)).c_str())) {
                                g_PendingActionDomain = d.hostname;
                                g_PendingAction = PendingAction::Delete;
                            }
                            if (ImGui::IsItemHovered()) ImGui::SetTooltip(u8"Удалить домен из базы");
                            ImGui::SameLine();
                            if (ImGui::Button((u8"Прв##" + std::to_string(d.id)).c_str())) {
                                g_PendingActionDomain = d.hostname;
                                g_PendingAction = PendingAction::Recheck;
                            }
                            if (ImGui::IsItemHovered()) ImGui::SetTooltip(u8"Повторная проверка");
                        }
                    }
                    else {
                        ImGui::TextDisabled(u8"---");
                    }
                }
                ImGui::EndTable();
            }
            ImGui::EndChild();

            ImGui::Separator();
            if (ImGui::Button(u8"Вернуть автоскролл")) logAutoScroll = true;
            ImGui::SameLine();
            ImGui::TextUnformatted(u8"Лог последней проверки:");
            ImGui::BeginChild("BlockcheckLog", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
            fs::path logPath = GetExeDirectory() / "scan_result.log";
            if (fs::exists(logPath)) {
                std::ifstream logFile(logPath);
                std::string content;
                std::string line;
                while (std::getline(logFile, line)) content += line + "\n";
                ImGui::TextUnformatted(content.c_str());
            }
            else {
                ImGui::TextDisabled(u8"Нет лога проверки.");
            }
            if (logAutoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 5.0f) {
                ImGui::SetScrollHereY(1.0f);
            }
            if (ImGui::IsWindowHovered() && ImGui::GetIO().MouseWheel != 0.0f) {
                logAutoScroll = false;
            }
            if (ImGui::IsWindowFocused() && !ImGui::IsMouseDragging(ImGuiMouseButton_Left) && ImGui::GetScrollY() < ImGui::GetScrollMaxY() - 5.0f) {
                logAutoScroll = false;
            }
            if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 5.0f) {
                logAutoScroll = true;
            }
            ImGui::EndChild();

            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ShowAddDomainPopup();
    ImGui::End();
}

// -------------------------------------------------------------------
// Оконная процедура (без изменений)
// -------------------------------------------------------------------
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    switch (msg) {
    case WM_USER + 1:
        if (lParam == WM_LBUTTONUP) {
            ShowWindow(hWnd, SW_RESTORE);
            SetForegroundWindow(hWnd);
        }
        else if (lParam == WM_RBUTTONUP) {
            TrayIcon::ShowContextMenu(hWnd);
        }
        break;
    case WM_COMMAND:
        if (LOWORD(wParam) == 101) ZapretController::Restart();
        else if (LOWORD(wParam) == 102) {
            if (Sniffer::IsRunning()) Sniffer::Stop();
            else Sniffer::Start();
        }
        else if (LOWORD(wParam) == 103) PostQuitMessage(0);
        break;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_CLOSE) {
            ShowWindow(hWnd, SW_HIDE);
            return 0;
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

// -------------------------------------------------------------------
// WinMain (без изменений)
// -------------------------------------------------------------------
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    auto IsAdmin = []() -> bool {
        BOOL isAdmin = FALSE;
        PSID adminGroup = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(NULL, adminGroup, &isAdmin);
            FreeSid(adminGroup);
        }
        return isAdmin == TRUE;
    };
    if (!IsAdmin()) {
        MessageBoxW(NULL, L"Программа должна быть запущена от имени администратора.", L"Предупреждение", MB_ICONWARNING);
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        ShellExecuteA(NULL, "runas", path, NULL, NULL, SW_SHOWNORMAL);
        return 0;
    }

    if (!EnsureWinDivertDriver()) {
        MessageBoxW(NULL, L"Не удалось установить/запустить драйвер WinDivert.\nСниффер не будет работать.", L"Ошибка", MB_ICONERROR);
    }

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    Database::InitDB();
    RefreshDomainList();

    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, hInstance, NULL, NULL, NULL, NULL, _T("AdaptiveZapretApp"), NULL };
    RegisterClassEx(&wc);

    HWND hwnd = CreateWindow(wc.lpszClassName, _T("AdaptiveZapret"),
        WS_POPUP,
        CW_USEDEFAULT, CW_USEDEFAULT, 1280, 800,
        NULL, NULL, wc.hInstance, NULL);
    g_hWnd = hwnd;

    RECT rc;
    GetWindowRect(hwnd, &rc);
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int x = (screenWidth - (rc.right - rc.left)) / 2;
    int y = (screenHeight - (rc.bottom - rc.top)) / 2;
    SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        WSACleanup();
        Database::CloseDB();
        return 1;
    }

    ShowWindow(hwnd, SW_HIDE);
    UpdateWindow(hwnd);
    TrayIcon::Init(hwnd);
    TrayIcon::ShowBalloon(hwnd, L"AdaptiveZapret", L"Приложение запущено и готово к работе. Для доступа к интерфейсу нажмите на иконку в трее.", NIIF_INFO);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();

    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->AddFontFromFileTTF("C:/Windows/Fonts/arial.ttf", 16.0f, nullptr, io.Fonts->GetGlyphRangesCyrillic());

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    if (LoadZapretState()) ZapretController::Start();
    bool dohEnabled = LoadDoHState();
    SetSystemDoH(dohEnabled);

    DWORD lastUpdateTime = GetTickCount();
    bool done = false;
    while (!done) {
        MSG msg;
        while (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        DWORD now = GetTickCount();
        if (now - lastUpdateTime > 3000) {
            lastUpdateTime = now;
            if (!unsavedChanges && DomainManager::HasNewData()) RefreshDomainList();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        RenderUI();
        ImGui::Render();

        const float clear_color[4] = { 0.1f, 0.1f, 0.1f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }

    SaveZapretState(ZapretController::IsRunning());
    Sniffer::Stop();
    ZapretController::Stop();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);
    Database::CloseDB();
    WSACleanup();
    return 0;
}

// -------------------------------------------------------------------
// DirectX вспомогательные функции (без изменений)
// -------------------------------------------------------------------
bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0; sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1; sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags,
        featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
        &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
        return false;
    CreateRenderTarget();
    return true;
}

void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = NULL; }
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = NULL; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = NULL; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; }
}