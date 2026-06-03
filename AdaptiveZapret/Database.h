#pragma once
#include <string>
#include <vector>
#include "sqlite3.h"

struct DomainRecord {
    int id;
    std::string hostname;
    std::string status;
    std::string active_strategy;
};

class Database {
private:
    static sqlite3* db;

public:
    static bool InitDB();
    static void CloseDB();

    // Домены
    static bool IsDomainKnown(const std::string& hostname);
    static bool AddDomain(const std::string& hostname, const std::string& status = "в очереди");
    static bool UpdateDomainStatus(const std::string& hostname, const std::string& status);
    static bool UpdateActiveStrategy(const std::string& hostname, const std::string& strategy);
    static std::vector<DomainRecord> GetAllDomains();
    static DomainRecord GetDomainByHostname(const std::string& hostname);
    static bool DeleteDomain(const std::string& hostname); // опционально

    // Стратегии (найденные решения)
    static bool AddStrategy(int domain_id, const std::string& strategy);
    static std::vector<std::string> GetStrategiesForDomain(int domain_id);
    static bool ClearStrategiesForDomain(int domain_id);
};