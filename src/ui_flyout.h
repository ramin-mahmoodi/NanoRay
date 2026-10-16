#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>

#define WM_TRAYICON       (WM_USER + 100)
#define WM_REPAINT_FLYOUT (WM_USER + 101)

extern HWND g_Hwnd;

bool init_tray_flyout(HINSTANCE hInst);
void cleanup_tray_flyout();
void update_tray_icon();
void show_tray_flyout();
void request_flyout_repaint();
void export_flyout_preview(const wchar_t* filename, bool is_dark);