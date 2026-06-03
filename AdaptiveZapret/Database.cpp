#include "Database.h"
#include <iostream>

sqlite3* Database::db = nullptr;

bool Database::InitDB() {
    if (sqlite3_open("zapret_adaptive.db", &db) != SQLITE_OK) {
        std::cerr << "[DB ERROR] Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    // Создаём таблицы (если их нет)
    const char* sql =
        "CREATE TABLE IF NOT EXISTS Domains ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "hostname TEXT UNIQUE NOT NULL, "
        "status TEXT NOT NULL, "
        "active_strategy TEXT);"

        "CREATE TABLE IF NOT EXISTS Strategies ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "domain_id INTEGER, "
        "args TEXT NOT NULL, "
        "FOREIGN KEY(domain_id) REFERENCES Domains(id) ON DELETE CASCADE);";

    char* errMsg = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "[DB ERROR] SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }

    std::cout << "[DB] Database initialized successfully." << std::endl;
    return true;
}

void Database::CloseDB() {
    if (db) {
        sqlite3_close(db);
        db = nullptr;
    }
}

bool Database::IsDomainKnown(const std::string& hostname) {
    const char* sql = "SELECT 1 FROM Domains WHERE hostname = ? LIMIT 1;";
    sqlite3_stmt* stmt;
    bool exists = false;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, hostname.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) exists = true;
        sqlite3_finalize(stmt);
    }
    return exists;
}

bool Database::AddDomain(const std::string& hostname, const std::string& status) {
    if (IsDomainKnown(hostname)) return false;
    const char* sql = "INSERT INTO Domains (hostname, status, active_strategy) VALUES (?, ?, '');";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, hostname.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, status.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return true;
    }
    return false;
}

bool Database::UpdateDomainStatus(const std::string& hostname, const std::string& status) {
    const char* sql = "UPDATE Domains SET status = ? WHERE hostname = ?;";
    sqlite3_stmt* stmt;
    bool success = false;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, hostname.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_DONE) success = true;
        sqlite3_finalize(stmt);
    }
    return success;
}

bool Database::UpdateActiveStrategy(const std::string& hostname, const std::string& strategy) {
    const char* sql = "UPDATE Domains SET active_strategy = ? WHERE hostname = ?;";
    sqlite3_stmt* stmt;
    bool success = false;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, strategy.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, hostname.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_DONE) success = true;
        sqlite3_finalize(stmt);
    }
    return success;
}

std::vector<DomainRecord> Database::GetAllDomains() {
    std::vector<DomainRecord> records;
    const char* sql = "SELECT id, hostname, status, active_strategy FROM Domains;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            DomainRecord rec;
            rec.id = sqlite3_column_int(stmt, 0);
            rec.hostname = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            rec.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            rec.active_strategy = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            records.push_back(rec);
        }
        sqlite3_finalize(stmt);
    }
    return records;
}

DomainRecord Database::GetDomainByHostname(const std::string& hostname) {
    DomainRecord rec{ -1, "", "", "" };
    const char* sql = "SELECT id, hostname, status, active_strategy FROM Domains WHERE hostname = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, hostname.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            rec.id = sqlite3_column_int(stmt, 0);
            rec.hostname = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            rec.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            rec.active_strategy = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        }
        sqlite3_finalize(stmt);
    }
    return rec;
}

bool Database::DeleteDomain(const std::string& hostname) {
    const char* sql = "DELETE FROM Domains WHERE hostname = ?;";
    sqlite3_stmt* stmt;
    bool success = false;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, hostname.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_DONE) success = true;
        sqlite3_finalize(stmt);
    }
    return success;
}

// ---------- Стратегии ----------
bool Database::AddStrategy(int domain_id, const std::string& strategy) {
    const char* sql = "INSERT INTO Strategies (domain_id, args) VALUES (?, ?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, domain_id);
        sqlite3_bind_text(stmt, 2, strategy.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return true;
    }
    return false;
}

std::vector<std::string> Database::GetStrategiesForDomain(int domain_id) {
    std::vector<std::string> strategies;
    const char* sql = "SELECT args FROM Strategies WHERE domain_id = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, domain_id);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            strategies.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
        }
        sqlite3_finalize(stmt);
    }
    return strategies;
}

bool Database::ClearStrategiesForDomain(int domain_id) {
    const char* sql = "DELETE FROM Strategies WHERE domain_id = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, domain_id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return true;
    }
    return false;
}