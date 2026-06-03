#pragma once
#include <string>
#include <thread>
#include <vector>
#include "Database.h"
#include "Scanner.h"

class DomainManager {
public:
    static void OnNewDomain(const std::string& domain) {
        if (Database::IsDomainKnown(domain)) return;

        // Проверяем доступность (HTTP/HTTPS)
        bool reachable = IsReachable(domain);
        if (reachable) {
            Database::AddDomain(domain, "чистый");
            return;
        }

        // Заблокирован – запускаем blockcheck в отдельном потоке
        Database::AddDomain(domain, "заблокирован (проверка)");
        std::thread([domain]() {
            auto strategies = Scanner::RunBlockCheck(domain);
            auto dom = Database::GetDomainByHostname(domain);
            if (dom.id == -1) return;

            Database::ClearStrategiesForDomain(dom.id);
            for (const auto& s : strategies) {
                Database::AddStrategy(dom.id, s);
            }
            if (!strategies.empty()) {
                Database::UpdateActiveStrategy(domain, strategies[0]);
                Database::UpdateDomainStatus(domain, "решения найдены");
            }
            else {
                Database::UpdateDomainStatus(domain, "решений не найдено");
            }
            }).detach();
    }

private:
    static bool IsReachable(const std::string& hostname) {
        // Пытаемся открыть TCP-сокет на порт 80 и 443
        // Если любой успешен – считаем "чистым"
        // Реальная проверка на блокировку DPI сложнее, но для начала так.
        return (TcpConnect(hostname, 80) || TcpConnect(hostname, 443));
    }

    static bool TcpConnect(const std::string& hostname, int port) {
        // Преобразуем hostname в IP
        addrinfo hints = {}, * res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(hostname.c_str(), std::to_string(port).c_str(), &hints, &res) != 0)
            return false;
        SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock == INVALID_SOCKET) {
            freeaddrinfo(res);
            return false;
        }
        // Устанавливаем неблокирующий режим для таймаута
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
        connect(sock, res->ai_addr, (int)res->ai_addrlen);
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        timeval tv;
        tv.tv_sec = 3;  // 3 секунды таймаут
        tv.tv_usec = 0;
        int ret = select(0, nullptr, &fdset, nullptr, &tv);
        closesocket(sock);
        freeaddrinfo(res);
        return ret > 0;
    }
};