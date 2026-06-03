#pragma once
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include "WinDivert.h"
#include "DomainManager.h"   // будет ниже

class Sniffer {
private:
    static std::atomic<bool> running;
    static std::thread worker;
    static HANDLE handle;

    static void SnifferThread() {
        // Фильтр: все UDP пакеты на порт 53 (запросы)
        handle = WinDivertOpen("udp.DstPort == 53 and udp.PayloadLength > 0",
            WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF);
        if (handle == INVALID_HANDLE_VALUE) return;

        char packet[4096];
        WINDIVERT_ADDRESS addr;
        UINT packetLen;

        while (running) {
            if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packetLen)) break;
            // Извлекаем DNS имя
            std::string domain = ExtractDomainFromDNS(packet, packetLen);
            if (!domain.empty()) {
                DomainManager::OnNewDomain(domain);
            }
        }
        WinDivertClose(handle);
    }

    // Простейший парсер DNS-имени (первое имя в вопросе)
    static std::string ExtractDomainFromDNS(const char* packet, UINT len) {
        // Пропускаем Ethernet/IP/UDP заголовки. Для упрощения считаем, 
        // что пакет начинается с IP-заголовка (без Ethernet). 
        // В реальном коде нужно определить смещение до UDP payload.
        // Для демонстрации используем упрощённый поиск метки 0x0C (label)
        // и собираем домен. 
        // Здесь приведён только набросок – полная реализация требует анализа DNS-формата.
        // Для рабочего кода возьмите готовый DNS-парсер.
        return ""; // заглушка – нужна реальная реализация
    }

public:
    static void Start() {
        if (running) return;
        running = true;
        worker = std::thread(SnifferThread);
    }

    static void Stop() {
        running = false;
        if (worker.joinable()) worker.join();
    }

    static bool IsRunning() { return running; }
};

std::atomic<bool> Sniffer::running(false);
std::thread Sniffer::worker;
HANDLE Sniffer::handle = INVALID_HANDLE_VALUE;