#pragma once
#include <string>
#include <vector>
#include "sqlite3.h"

struct DomainRecord {
    int id;
    std::string hostname;
    std::string status;
    std::string active_strategy;
    bool game_filter;          // добавлено поле GameFilter
};

class Database {
private:
    static sqlite3* db;

public:
    static bool InitDB();
    static void CloseDB();

    // ƒомены
    static bool IsDomainKnown(const std::string& hostname);
    static bool AddDomain(const std::string& hostname, const std::string& status = "в очереди");
    static bool UpdateDomainStatus(const std::string& hostname, const std::string& status);
    static bool UpdateActiveStrategy(const std::string& hostname, const std::string& strategy);
    static std::vector<DomainRecord> GetAllDomains();
    static DomainRecord GetDomainByHostname(const std::string& hostname);
    static bool DeleteDomain(const std::string& hostname);
    static bool UpdateGameFilter(const std::string& hostname, bool enabled);
    static bool GetGameFilter(const std::string& hostname);   // новый метод

    // —тратегии (найденные решени€)
    static bool AddStrategy(int domain_id, const std::string& strategy);
    static std::vector<std::string> GetStrategiesForDomain(int domain_id);
    static bool ClearStrategiesForDomain(int domain_id);
};