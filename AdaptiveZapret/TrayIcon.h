#pragma once
#include <windows.h>
#include <shellapi.h>

class TrayIcon {
public:
    static void Init(HWND hWnd) {
        NOTIFYICONDATA nid = {};
        nid.cbSize = sizeof(nid);
        nid.hWnd = hWnd;
        nid.uID = 1;
        nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        nid.uCallbackMessage = WM_USER + 1;
        nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
        // Исправлено: добавлены L и размер буфера
        wcscpy_s(nid.szTip, L"AdaptiveZapret");
        Shell_NotifyIcon(NIM_ADD, &nid);
    }

    static void ShowBalloon(HWND hWnd, const wchar_t* title, const wchar_t* msg, DWORD iconType) {
        NOTIFYICONDATA nid = {};
        nid.cbSize = sizeof(NOTIFYICONDATA);
        nid.hWnd = hWnd;
        nid.uID = 1;
        nid.uFlags = NIF_INFO;
        wcscpy_s(nid.szInfoTitle, title);
        wcscpy_s(nid.szInfo, msg);
        nid.dwInfoFlags = iconType; // NIIF_INFO, NIIF_WARNING, NIIF_ERROR
        Shell_NotifyIcon(NIM_MODIFY, &nid);
    }

    static void ShowContextMenu(HWND hWnd) {
        POINT pt;
        GetCursorPos(&pt);
        HMENU hMenu = CreatePopupMenu();
        // Исправлено: добавлены L перед строками для LPCWSTR
        AppendMenu(hMenu, MF_STRING, 101, L"Перезапуск winws");
        AppendMenu(hMenu, MF_STRING, 102, L"Включить/Выключить сниффер");
        AppendMenu(hMenu, MF_STRING, 103, L"Выключить AdaptiveZapret");

        SetForegroundWindow(hWnd);
        TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hWnd, NULL);
        DestroyMenu(hMenu);
    }
};