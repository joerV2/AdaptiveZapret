#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <map>
#include "Database.h"

namespace fs = std::filesystem;

class ZapretController {
private:
    static PROCESS_INFORMATION pi;
    static bool isRunning;

public:
    static bool Start() {
        if (isRunning) return true;
        // Генерируем файлы списков перед запуском
        if (!GenerateDomainLists()) return false;

        fs::path winwsDir = fs::current_path() / "zapret-win-bundle" / "zapret-winws";
        fs::path winwsExe = winwsDir / "winws.exe";

        // Формируем командную строку с параметрами для каждой стратегии
        std::string cmdLine = "\"" + winwsExe.string() + "\"";
        // Пример: для каждой стратегии свой параметр --desync-*
        // Сопоставление стратегии -> параметр winws
        std::map<std::string, std::string> strategyToParam = {
            {"fake", "--desync-fake"},
            {"multi", "--desync-fake"},
            {"faked", "--desync-fake"},
            {"hostfake", "--desync-fake"},
            {"oob", "--desync-raw"},
            {"syndata", "--desync-raw"},
            {"seqovl", "--desync-raw"},
            {"desync", "--desync-raw"}
        };
        // Для каждой стратегии, если есть файл с доменами, добавляем параметр
        for (const auto& [strat, param] : strategyToParam) {
            fs::path listFile = winwsDir / ("domains_" + strat + ".txt");
            if (fs::exists(listFile) && fs::file_size(listFile) > 0) {
                cmdLine += " " + param + "=" + listFile.string();
            }
        }
        // Добавим базовые параметры
        cmdLine += " --filter-udp=443 --filter-tcp=80,443";

        STARTUPINFOA si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        if (CreateProcessA(NULL, (LPSTR)cmdLine.c_str(), NULL, NULL, FALSE, 0, NULL,
            winwsDir.string().c_str(), &si, &pi)) {
            isRunning = true;
            return true;
        }
        return false;
    }

    static void Stop() {
        if (!isRunning) return;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        isRunning = false;
    }

    static void Restart() {
        Stop();
        Start();
    }

    static bool IsRunning() { return isRunning; }

    // Обновление txt-файлов на основе текущей БД
    static bool GenerateDomainLists() {
        fs::path winwsDir = fs::current_path() / "zapret-win-bundle" / "zapret-winws";
        // Очищаем старые файлы
        for (const auto& entry : fs::directory_iterator(winwsDir)) {
            std::string name = entry.path().filename().string();
            if (name.rfind("domains_", 0) == 0 && name.substr(name.find_last_of(".")) == ".txt")
                fs::remove(entry.path());
        }

        // Собираем домены с активными стратегиями
        auto domains = Database::GetAllDomains();
        std::map<std::string, std::vector<std::string>> strategyDomains;
        for (const auto& d : domains) {
            if (!d.active_strategy.empty() && d.active_strategy != "чистый") {
                strategyDomains[d.active_strategy].push_back(d.hostname);
            }
        }

        // Записываем в файлы
        for (const auto& [strat, hosts] : strategyDomains) {
            std::ofstream out(winwsDir / ("domains_" + strat + ".txt"));
            if (out.is_open()) {
                for (const auto& h : hosts)
                    out << h << "\n";
                out.close();
            }
        }
        return true;
    }
};

PROCESS_INFORMATION ZapretController::pi = {};
bool ZapretController::isRunning = false;