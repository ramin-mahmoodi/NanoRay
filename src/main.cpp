#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <objidl.h>
#include <gdiplus.h>
#include "config.h"
#include "tunnel.h"
#include "ui_flyout.h"

using namespace Gdiplus;

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int) {
    if (strstr(GetCommandLineA(), "--preview")) {
        WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
        GdiplusStartupInput gsi; ULONG_PTR gToken = 0; GdiplusStartup(&gToken, &gsi, nullptr);
        load_config_ini();
        init_tray_flyout(hInst);
        export_flyout_preview(L"preview_dark.png", true);
        export_flyout_preview(L"preview_light.png", false);
        cleanup_tray_flyout();
        GdiplusShutdown(gToken);
        WSACleanup();
        return 0;
    }

    HANDLE hMutex = CreateMutexW(nullptr, TRUE, L"Global\\NanoRayMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(nullptr, L"NanoRay is already running in the System Tray.", L"NanoRay", MB_ICONINFORMATION);
        return 0;
    }
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    GdiplusStartupInput gsi; ULONG_PTR gToken = 0; GdiplusStartup(&gToken, &gsi, nullptr);
    load_config_ini();
    if (!init_tray_flyout(hInst)) { GdiplusShutdown(gToken); WSACleanup(); CloseHandle(hMutex); return 1; }
    show_tray_flyout();
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    cleanup_tray_flyout(); GdiplusShutdown(gToken); WSACleanup(); CloseHandle(hMutex);
    return 0;
}