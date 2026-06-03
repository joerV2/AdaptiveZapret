#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <regex>
#include <windows.h>

namespace fs = std::filesystem;

class Scanner {
public:
    // Запускает blockcheck для домена и возвращает список найденных стратегий
    static std::vector<std::string> RunBlockCheck(const std::string& domain) {
        fs::path exePath = fs::current_path();
        fs::path blockcheckDir = exePath / "zapret-win-bundle" / "blockcheck";
        fs::path cmdPath = blockcheckDir / "blockcheck.cmd";
        fs::path answersPath = blockcheckDir / "temp_answers.txt";
        fs::path logPath = blockcheckDir / "scan_result.log";

        // Удаляем старый лог
        std::error_code ec;
        fs::remove(logPath, ec);

        // Готовим файл ответов (параметры как в примере)
        std::ofstream outFile(answersPath);
        if (!outFile.is_open()) return {};
        outFile << domain << "\n"    // домен
            << "4\n"             // IPv4
            << "Y\n"             // HTTP
            << "Y\n"             // HTTPS TLS 1.2
            << "N\n"             // TLS 1.3
            << "Y\n"             // QUIC
            << "1\n"             // repeats
            << "N\n"             // parallel
            << "1";              // quick mode
        outFile.close();

        // Команда запуска
        std::string command = "cmd.exe /c \"" + cmdPath.string() + "\" < \"" + answersPath.string() + "\" > \"" + logPath.string() + "\" 2>&1";
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        if (CreateProcessA(NULL, (LPSTR)command.c_str(), NULL, NULL, FALSE, 0, NULL,
            blockcheckDir.string().c_str(), &si, &pi)) {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        // Парсим лог: ищем строку "Working: стратегия1, стратегия2, ..."
        std::vector<std::string> strategies;
        std::ifstream logFile(logPath);
        std::string line;
        std::regex working_regex(R"(Working[^:]*:\s*(.+))", std::regex::icase);
        while (std::getline(logFile, line)) {
            std::smatch match;
            if (std::regex_search(line, match, working_regex)) {
                std::string strategies_line = match[1].str();
                std::stringstream ss(strategies_line);
                std::string strat;
                while (std::getline(ss, strat, ',')) {
                    // убираем пробелы
                    strat.erase(0, strat.find_first_not_of(" \t"));
                    strat.erase(strat.find_last_not_of(" \t") + 1);
                    if (!strat.empty()) strategies.push_back(strat);
                }
                break;
            }
        }
        logFile.close();
        // Удаляем временные файлы
        fs::remove(answersPath, ec);
        return strategies;
    }
};