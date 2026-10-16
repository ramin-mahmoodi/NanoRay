#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include "ui_flyout.h"
#include "config.h"
#include "tunnel.h"
#include <windowsx.h>
#include <shellapi.h>
#include <psapi.h>
#include <objidl.h>
#include <gdiplus.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <cmath>
#include <algorithm>

using namespace Gdiplus;

static float get_dpi_scale() {
    if (!g_Hwnd) {
        HDC hdc = GetDC(nullptr);
        int dpi = GetDeviceCaps(hdc, LOGPIXELSX);
        ReleaseDC(nullptr, hdc);
        return (dpi > 0) ? (static_cast<float>(dpi) / 96.0f) : 1.0f;
    }
    UINT dpi = GetDpiForWindow(g_Hwnd);
    if (dpi == 0) {
        HDC hdc = GetDC(g_Hwnd);
        dpi = GetDeviceCaps(hdc, LOGPIXELSX);
        ReleaseDC(g_Hwnd, hdc);
    }
    return (dpi > 0) ? (static_cast<float>(dpi) / 96.0f) : 1.0f;
}

static const int PANEL_W    = 400;
static const int PANEL_H    = 552;
static const int WIN_W      = PANEL_W;
static const int WIN_H      = PANEL_H;

enum ActiveInputField { FIELD_NONE = 0, FIELD_VLESS_URI = 1, FIELD_CHAIN_ADDR = 2, FIELD_CHAIN_AUTH = 3 };

HWND                    g_Hwnd       = nullptr;
static HINSTANCE        g_HInst      = nullptr;
static ActiveInputField g_FocusField = FIELD_NONE;
static int              g_HoverBtn   = 0;
static NOTIFYICONDATAW  g_Nid{};
static Bitmap*          g_LogoBmp    = nullptr;
static HICON            g_IconIdle   = nullptr;
static HICON            g_IconPending = nullptr;
static HICON            g_IconConn   = nullptr;
static uint64_t         g_LastRx     = 0, g_LastTx = 0;
static double           g_SpeedRxKB  = 0.0, g_SpeedTxKB = 0.0;

static const UINT_PTR   IDT_ANIM     = 101;
static const UINT_PTR   IDT_STATS    = 102;
static const UINT_PTR   IDT_SAVE     = 103;
static int              g_PressedBtn = 0;
static float            g_SegPillX   = 25.0f;
static float            g_SegTargetX = 25.0f;
static ULONGLONG        g_FlushFeedbackTicks = 0;

static const int SPARK_COUNT = 30;
static float            g_SparkRx[SPARK_COUNT] = { 0 };
static float            g_SparkTx[SPARK_COUNT] = { 0 };

static int              g_CaretPos     = 0;
static int              g_SelStart     = 0;
static int              g_SelEnd       = 0;
static int              g_ScrollOffset = 0;
static bool             g_IsDragging   = false;
static float            g_CharW        = 0.0f;

// Layout Rectangles (400x552 with 12px outer padding, 11.5px flex-spaced gaps matching HTML exactly)
static const RectF R_BTN_THEME     (254.0f, 14.0f,  32.0f,  32.0f);
static const RectF R_BTN_PING      (292.0f, 14.0f,  96.0f,  32.0f);
static const RectF R_BTN_CONNECT   (12.0f,  60.0f,  376.0f, 44.0f);
static const RectF R_CARD_DL       (12.0f,  116.0f, 184.0f, 118.0f);
static const RectF R_CARD_UL       (204.0f, 116.0f, 184.0f, 118.0f);
static const RectF R_CARD_VLESS    (12.0f,  245.0f, 376.0f, 113.0f);
static const RectF R_BTN_CLEAR_URI (223.0f, 255.0f, 52.0f,  26.0f);
static const RectF R_BTN_PASTE_URI (281.0f, 255.0f, 95.0f,  26.0f);
static const RectF R_INP_VLESS_URI (24.0f,  287.0f, 352.0f, 34.0f);
static const RectF R_EMPTY_URI     (24.0f,  287.0f, 352.0f, 60.0f);
static const RectF R_CARD_PROXY    (12.0f,  370.0f, 376.0f, 120.0f);
static const RectF R_BTN_CH_NONE   (27.0f,  406.0f, 112.0f, 28.0f);
static const RectF R_BTN_CH_SOCKS5 (143.0f, 406.0f, 112.0f, 28.0f);
static const RectF R_BTN_CH_HTTP   (259.0f, 406.0f, 112.0f, 28.0f);
static const RectF R_INP_CH_ADDR   (24.0f,  443.0f, 168.0f, 34.0f);
static const RectF R_INP_CH_AUTH   (198.0f, 443.0f, 140.0f, 34.0f);
static const RectF R_BTN_PASTE_CH  (344.0f, 443.0f, 32.0f,  34.0f);
static const RectF R_BTN_FLUSHDNS  (12.0f,  501.0f, 184.0f, 38.0f);
static const RectF R_BTN_EXIT      (204.0f, 501.0f, 184.0f, 38.0f);


struct UiTheme {
    Color bg;
    Color card;
    Color border;
    Color field;
    Color text;
    Color muted;
    Color chip;
    Color chip_text;
    Color green;
    Color green_area;
    Color sky;
    Color sky_bg;
    Color sky_border;
    Color uri;
    Color proto;
    Color ghost;
    Color danger_bg;
    Color danger_border;
    Color danger_text;
    Color dashed;
    Color ph;
    Color focus;
};

static UiTheme get_theme(bool is_dark) {
    UiTheme t;
    if (is_dark) {
        t.bg            = Color(255, 14, 17, 23);       // #0e1117
        t.card          = Color(255, 21, 25, 34);       // #151922
        t.border        = Color(255, 35, 41, 56);       // #232938
        t.field         = Color(255, 14, 17, 23);       // #0e1117
        t.text          = Color(255, 232, 236, 244);    // #e8ecf4
        t.muted         = Color(255, 139, 149, 170);    // #8b95aa
        t.chip          = Color(255, 28, 34, 48);       // #1c2230
        t.chip_text     = Color(255, 195, 203, 219);    // #c3cbdb
        t.green         = Color(255, 52, 211, 153);     // #34d399
        t.green_area    = Color(36,  52, 211, 153);     // rgba(52,211,153,.14)
        t.sky           = Color(255, 56, 189, 248);     // #38bdf8
        t.sky_bg        = Color(25,  14, 165, 233);     // rgba(14,165,233,.1)
        t.sky_border    = Color(255, 14, 165, 233);     // #0ea5e9
        t.uri           = Color(255, 56, 189, 248);     // #38bdf8
        t.proto         = Color(255, 125, 211, 252);    // #7dd3fc
        t.ghost         = Color(255, 152, 162, 184);    // #98a2b8
        t.danger_bg     = Color(25,  248, 113, 113);    // rgba(248,113,113,.1)
        t.danger_border = Color(102, 248, 113, 113);    // rgba(248,113,113,.4)
        t.danger_text   = Color(255, 252, 165, 165);    // #fca5a5
        t.dashed        = Color(255, 47, 55, 74);       // #2f374a
        t.ph            = Color(255, 103, 113, 136);    // #677188
        t.focus         = Color(255, 56, 189, 248);     // #38bdf8
    } else {
        t.bg            = Color(255, 243, 245, 249);    // #f3f5f9
        t.card          = Color(255, 255, 255, 255);    // #ffffff
        t.border        = Color(255, 221, 226, 236);    // #dde2ec
        t.field         = Color(255, 241, 244, 249);    // #f1f4f9
        t.text          = Color(255, 19, 23, 34);       // #131722
        t.muted         = Color(255, 93, 103, 121);     // #5d6779
        t.chip          = Color(255, 238, 241, 246);    // #eef1f6
        t.chip_text     = Color(255, 59, 69, 88);       // #3b4558
        t.green         = Color(255, 4, 120, 87);       // #047857
        t.green_area    = Color(36,  5, 150, 105);      // rgba(5,150,105,.14)
        t.sky           = Color(255, 3, 105, 161);      // #0369a1
        t.sky_bg        = Color(23,  2, 132, 199);      // rgba(2,132,199,.09)
        t.sky_border    = Color(255, 2, 132, 199);      // #0284c7
        t.uri           = Color(255, 3, 105, 161);      // #0369a1
        t.proto         = Color(255, 3, 105, 161);      // #0369a1
        t.ghost         = Color(255, 74, 85, 104);      // #4a5568
        t.danger_bg     = Color(20,  220, 38, 38);      // rgba(220,38,38,.08)
        t.danger_border = Color(89,  220, 38, 38);      // rgba(220,38,38,.35)
        t.danger_text   = Color(255, 185, 28, 28);      // #b91c1c
        t.dashed        = Color(255, 195, 203, 219);    // #c3cbdb
        t.ph            = Color(255, 107, 117, 137);    // #6b7589
        t.focus         = Color(255, 2, 132, 199);      // #0284c7
    }
    return t;
}

static bool pt_in_rect(int x, int y, const RectF& r) {
    return x >= r.X && x <= (r.X + r.Width) && y >= r.Y && y <= (r.Y + r.Height);
}

static void add_rounded_rect(GraphicsPath& path, RectF r, float radius) {
    float d = radius * 2.0f;
    path.AddArc(r.X, r.Y, d, d, 180.0f, 90.0f);
    path.AddArc(r.X + r.Width - d, r.Y, d, d, 270.0f, 90.0f);
    path.AddArc(r.X + r.Width - d, r.Y + r.Height - d, d, d, 0.0f, 90.0f);
    path.AddArc(r.X, r.Y + r.Height - d, d, d, 90.0f, 90.0f);
    path.CloseFigure();
}

static Bitmap* load_logo_bitmap(HINSTANCE hInst) {
    HRSRC hRes = FindResourceA(hInst, MAKEINTRESOURCEA(200), RT_RCDATA);
    if (hRes) {
        HGLOBAL hMem = LoadResource(hInst, hRes);
        if (hMem) {
            DWORD size = SizeofResource(hInst, hRes);
            const void* pData = LockResource(hMem);
            if (pData && size > 0) {
                HGLOBAL hCopy = GlobalAlloc(GMEM_MOVEABLE, size);
                if (hCopy) {
                    void* pCopy = GlobalLock(hCopy);
                    if (pCopy) {
                        memcpy(pCopy, pData, size);
                        GlobalUnlock(hCopy);
                        IStream* pStream = nullptr;
                        if (CreateStreamOnHGlobal(hCopy, TRUE, &pStream) == S_OK) {
                            Bitmap* tmp = Bitmap::FromStream(pStream);
                            if (tmp && tmp->GetLastStatus() == Ok) {
                                Bitmap* finalBmp = new Bitmap(tmp->GetWidth(), tmp->GetHeight(), PixelFormat32bppARGB);
                                Graphics g(finalBmp);
                                g.DrawImage(tmp, 0, 0);
                                delete tmp;
                                pStream->Release();
                                return finalBmp;
                            }
                            delete tmp;
                            pStream->Release();
                        }
                    } else {
                        GlobalFree(hCopy);
                    }
                }
            }
        }
    }
    HICON hIco = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(1), IMAGE_ICON, 256, 256, LR_DEFAULTCOLOR);
    if (!hIco) {
        hIco = (HICON)LoadImageW(nullptr, L"resources\\app.ico", IMAGE_ICON, 256, 256, LR_LOADFROMFILE);
    }
    if (hIco) {
        Bitmap* tmp = Bitmap::FromHICON(hIco);
        DestroyIcon(hIco);
        return tmp;
    }
    return nullptr;
}

static void load_status_icons(HINSTANCE hInst) {
    if (g_IconIdle)    { DestroyIcon(g_IconIdle);    g_IconIdle = nullptr; }
    if (g_IconPending) { DestroyIcon(g_IconPending); g_IconPending = nullptr; }
    if (g_IconConn)    { DestroyIcon(g_IconConn);    g_IconConn = nullptr; }

    int cx = GetSystemMetrics(SM_CXSMICON);
    int cy = GetSystemMetrics(SM_CYSMICON);
    if (cx <= 0) cx = 16;
    if (cy <= 0) cy = 16;

    if (hInst) {
        g_IconIdle    = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(101), IMAGE_ICON, cx, cy, LR_DEFAULTCOLOR);
        g_IconPending = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(102), IMAGE_ICON, cx, cy, LR_DEFAULTCOLOR);
        g_IconConn    = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(103), IMAGE_ICON, cx, cy, LR_DEFAULTCOLOR);
    }
    if (!g_IconIdle)    g_IconIdle    = (HICON)LoadImageW(nullptr, L"resources\\icon_idle.ico", IMAGE_ICON, cx, cy, LR_LOADFROMFILE);
    if (!g_IconPending) g_IconPending = (HICON)LoadImageW(nullptr, L"resources\\icon_pending.ico", IMAGE_ICON, cx, cy, LR_LOADFROMFILE);
    if (!g_IconConn)    g_IconConn    = (HICON)LoadImageW(nullptr, L"resources\\icon_conn.ico", IMAGE_ICON, cx, cy, LR_LOADFROMFILE);
}

void update_tray_icon() {
    if (!g_Hwnd) return;
    TunnelState st = g_State.load();
    if (st == STATE_CONNECTED) {
        g_Nid.hIcon = g_IconConn;
        wcscpy_s(g_Nid.szTip, L"NanoRay - Connected");
    } else if (st == STATE_CONNECTING) {
        g_Nid.hIcon = g_IconPending ? g_IconPending : g_IconIdle;
        wcscpy_s(g_Nid.szTip, L"NanoRay - Connecting...");
    } else {
        g_Nid.hIcon = g_IconIdle;
        wcscpy_s(g_Nid.szTip, L"NanoRay - Disconnected");
    }
    Shell_NotifyIconW(NIM_MODIFY, &g_Nid);
}

static void fill_round_card(Graphics& g, RectF r, float rad, Color fill, Color border, float bw = 1.0f) {
    GraphicsPath path; add_rounded_rect(path, r, rad);
    SolidBrush br(fill); g.FillPath(&br, &path);
    if (border.GetAlpha() > 0) { Pen pen(border, bw); g.DrawPath(&pen, &path); }
}

static std::wstring to_wstr(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n > 0 ? n - 1 : 0, 0);
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

static std::string to_utf8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(n > 0 ? n - 1 : 0, 0);
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], n, nullptr, nullptr);
    return s;
}

static std::wstring read_clipboard_wtext(HWND hwnd) {
    std::wstring res;
    if (OpenClipboard(hwnd)) {
        HANDLE hData = GetClipboardData(CF_UNICODETEXT);
        if (hData) {
            const wchar_t* txt = static_cast<const wchar_t*>(GlobalLock(hData));
            if (txt) { res = txt; GlobalUnlock(hData); }
        }
        CloseClipboard();
    }
    while (!res.empty() && (res.back() == L'\r' || res.back() == L'\n' || res.back() == L' ')) res.pop_back();
    return res;
}

static std::string read_clipboard_text(HWND hwnd) {
    return to_utf8(read_clipboard_wtext(hwnd));
}

static std::string* get_field_string(ActiveInputField field) {
    switch (field) {
    case FIELD_VLESS_URI:  return &g_cfg.raw_vless_uri;
    case FIELD_CHAIN_ADDR: return &g_cfg.chain_addr_str;
    case FIELD_CHAIN_AUTH: return &g_cfg.chain_auth_str;
    default: return nullptr;
    }
}

static const RectF* get_field_rect(ActiveInputField field) {
    switch (field) {
    case FIELD_VLESS_URI:  return &R_INP_VLESS_URI;
    case FIELD_CHAIN_ADDR: return &R_INP_CH_ADDR;
    case FIELD_CHAIN_AUTH: return &R_INP_CH_AUTH;
    default: return nullptr;
    }
}

static int get_field_len(ActiveInputField field) {
    std::string* s = get_field_string(field);
    if (!s) return 0;
    return static_cast<int>(to_wstr(*s).size());
}

static bool delete_selection(std::string* s) {
    if (!s) return false;
    if (g_SelStart != g_SelEnd) {
        std::wstring w = to_wstr(*s);
        int s_min = std::max(0, std::min(g_SelStart, g_SelEnd));
        int s_max = std::min(static_cast<int>(w.size()), std::max(g_SelStart, g_SelEnd));
        if (s_min < s_max) {
            w.erase(s_min, s_max - s_min);
            *s = to_utf8(w);
        }
        g_CaretPos = s_min;
        g_SelStart = g_CaretPos;
        g_SelEnd   = g_CaretPos;
        return true;
    }
    return false;
}

// Vector SVG Drawing Helpers (viewBox 0 0 24 24)
struct SvgScope {
    Graphics& g;
    GraphicsState state;
    SvgScope(Graphics& gr, float x, float y, float size) : g(gr) {
        state = g.Save();
        g.SetSmoothingMode(SmoothingModeAntiAlias);
        g.TranslateTransform(x, y);
        g.ScaleTransform(size / 24.0f, size / 24.0f);
    }
    ~SvgScope() {
        g.Restore(state);
    }
};

static void draw_svg_sun(Graphics& g, float x, float y, float size, Color col) {
    SvgScope scope(g, x, y, size);
    Pen pen(col, 2.2f);
    pen.SetStartCap(LineCapRound);
    pen.SetEndCap(LineCapRound);
    pen.SetLineJoin(LineJoinRound);
    g.DrawEllipse(&pen, 8.0f, 8.0f, 8.0f, 8.0f);
    g.DrawLine(&pen, 12.0f, 2.0f, 12.0f, 4.0f);
    g.DrawLine(&pen, 12.0f, 20.0f, 12.0f, 22.0f);
    g.DrawLine(&pen, 4.93f, 4.93f, 6.34f, 6.34f);
    g.DrawLine(&pen, 17.66f, 17.66f, 19.07f, 19.07f);
    g.DrawLine(&pen, 2.0f, 12.0f, 4.0f, 12.0f);
    g.DrawLine(&pen, 20.0f, 12.0f, 22.0f, 12.0f);
    g.DrawLine(&pen, 6.34f, 17.66f, 4.93f, 19.07f);
    g.DrawLine(&pen, 19.07f, 4.93f, 17.66f, 6.34f);
}

static void draw_svg_moon(Graphics& g, float x, float y, float size, Color col) {
    SvgScope scope(g, x, y, size);
    Pen pen(col, 2.2f);
    pen.SetStartCap(LineCapRound);
    pen.SetEndCap(LineCapRound);
    pen.SetLineJoin(LineJoinRound);
    GraphicsPath path;
    path.AddArc(3.0f, 3.0f, 18.0f, 18.0f, 5.0f, 260.0f);
    path.AddBezier(11.21f, 3.0f, 11.5f, 9.5f, 16.0f, 13.5f, 21.0f, 12.79f);
    g.DrawPath(&pen, &path);
}

static void draw_svg_ecg(Graphics& g, float x, float y, float size, Color col) {
    SvgScope scope(g, x, y, size);
    Pen pen(col, 2.2f);
    pen.SetStartCap(LineCapRound);
    pen.SetEndCap(LineCapRound);
    pen.SetLineJoin(LineJoinRound);
    PointF pts[6] = {
        PointF(2.0f, 12.0f),
        PointF(6.0f, 12.0f),
        PointF(9.0f, 3.0f),
        PointF(15.0f, 21.0f),
        PointF(18.0f, 12.0f),
        PointF(22.0f, 12.0f)
    };
    g.DrawLines(&pen, pts, 6);
}

static RectF get_btn_rect(const RectF& r, int btn_id) {
    if (g_PressedBtn == btn_id) {
        return RectF(r.X + 1.0f, r.Y + 1.0f, r.Width - 2.0f, r.Height - 2.0f);
    }
    return r;
}

static void draw_svg_power(Graphics& g, float x, float y, float size, Color col) {
    SvgScope scope(g, x, y, size);
    Pen pen(col, 2.4f);
    pen.SetStartCap(LineCapRound);
    pen.SetEndCap(LineCapRound);
    pen.SetLineJoin(LineJoinRound);
    g.DrawLine(&pen, 12.0f, 2.0f, 12.0f, 12.0f);
    g.DrawArc(&pen, 3.0f, 3.0f, 18.0f, 18.0f, -45.0f, 270.0f);
}

static void draw_svg_spinner(Graphics& g, float x, float y, float size, Color col, float angle) {
    SvgScope scope(g, x, y, size);
    Pen pen(col, 2.6f);
    pen.SetStartCap(LineCapRound);
    pen.SetEndCap(LineCapRound);
    pen.SetLineJoin(LineJoinRound);
    g.DrawArc(&pen, 3.0f, 3.0f, 18.0f, 18.0f, angle, 270.0f);
}

static void draw_svg_check(Graphics& g, float x, float y, float size, Color col) {
    SvgScope scope(g, x, y, size);
    Pen pen(col, 2.4f);
    pen.SetStartCap(LineCapRound);
    pen.SetEndCap(LineCapRound);
    pen.SetLineJoin(LineJoinRound);
    PointF pts[3] = { PointF(4.0f, 12.0f), PointF(9.0f, 17.0f), PointF(20.0f, 6.0f) };
    g.DrawLines(&pen, pts, 3);
}

static void draw_svg_download(Graphics& g, float x, float y, float size, Color col) {
    SvgScope scope(g, x, y, size);
    Pen pen(col, 2.6f);
    pen.SetStartCap(LineCapRound);
    pen.SetEndCap(LineCapRound);
    pen.SetLineJoin(LineJoinRound);
    g.DrawLine(&pen, 12.0f, 5.0f, 12.0f, 19.0f);
    PointF pts[3] = { PointF(5.0f, 12.0f), PointF(12.0f, 19.0f), PointF(19.0f, 12.0f) };
    g.DrawLines(&pen, pts, 3);
}

static void draw_svg_upload(Graphics& g, float x, float y, float size, Color col) {
    SvgScope scope(g, x, y, size);
    Pen pen(col, 2.6f);
    pen.SetStartCap(LineCapRound);
    pen.SetEndCap(LineCapRound);
    pen.SetLineJoin(LineJoinRound);
    g.DrawLine(&pen, 12.0f, 19.0f, 12.0f, 5.0f);
    PointF pts[3] = { PointF(5.0f, 12.0f), PointF(12.0f, 5.0f), PointF(19.0f, 12.0f) };
    g.DrawLines(&pen, pts, 3);
}

static void draw_svg_clipboard(Graphics& g, float x, float y, float size, Color col, float stroke_w = 2.4f) {
    SvgScope scope(g, x, y, size);
    Pen pen(col, stroke_w);
    pen.SetStartCap(LineCapRound);
    pen.SetEndCap(LineCapRound);
    pen.SetLineJoin(LineJoinRound);
    GraphicsPath clip_path;
    clip_path.AddRectangle(RectF(8.0f, 2.0f, 8.0f, 4.0f));
    g.DrawPath(&pen, &clip_path);
    PointF pts[8] = {
        PointF(8.0f, 4.0f),
        PointF(5.0f, 4.0f),
        PointF(4.0f, 5.0f),
        PointF(4.0f, 21.0f),
        PointF(20.0f, 21.0f),
        PointF(20.0f, 5.0f),
        PointF(19.0f, 4.0f),
        PointF(16.0f, 4.0f)
    };
    g.DrawLines(&pen, pts, 8);
}

static void draw_svg_refresh(Graphics& g, float x, float y, float size, Color col, float stroke_w = 2.3f) {
    SvgScope scope(g, x, y, size);
    Pen pen(col, stroke_w);
    pen.SetStartCap(LineCapRound);
    pen.SetEndCap(LineCapRound);
    pen.SetLineJoin(LineJoinRound);

    GraphicsPath path;
    // M21 12 a9 9 0 1 1 -3 -6.7 L21 8
    path.AddArc(3.0f, 3.0f, 18.0f, 18.0f, 0.0f, 312.0f);
    path.AddLine(18.0f, 5.3f, 21.0f, 8.0f);
    g.DrawPath(&pen, &path);

    // M21 3 v5 h-5
    PointF arrow[3] = { PointF(21.0f, 3.0f), PointF(21.0f, 8.0f), PointF(16.0f, 8.0f) };
    g.DrawLines(&pen, arrow, 3);
}

static void draw_svg_exit(Graphics& g, float x, float y, float size, Color col) {
    SvgScope scope(g, x, y, size);
    Pen pen(col, 2.3f);
    pen.SetStartCap(LineCapRound);
    pen.SetEndCap(LineCapRound);
    pen.SetLineJoin(LineJoinRound);
    PointF door[4] = { PointF(9.0f, 3.0f), PointF(4.0f, 3.0f), PointF(4.0f, 21.0f), PointF(9.0f, 21.0f) };
    g.DrawLines(&pen, door, 4);
    PointF arrow[3] = { PointF(16.0f, 7.0f), PointF(21.0f, 12.0f), PointF(16.0f, 17.0f) };
    g.DrawLines(&pen, arrow, 3);
    g.DrawLine(&pen, 9.0f, 12.0f, 21.0f, 12.0f);
}

static void draw_sparkline(Graphics& g, RectF r, const float* arr, int count, float floor_val, Color stroke_col, Color grad_col) {
    if (count < 2) return;
    float peak = floor_val;
    for (int i = 0; i < count; ++i) if (arr[i] > peak) peak = arr[i];
    if (peak <= 0.0f) peak = 1.0f;

    std::vector<PointF> line_pts(count);
    float step_x = r.Width / static_cast<float>(count - 1);
    for (int i = 0; i < count; ++i) {
        float norm = arr[i] / peak;
        if (norm > 1.0f) norm = 1.0f;
        float y = r.Y + 22.0f - (norm * 19.0f);
        line_pts[i] = PointF(r.X + i * step_x, y);
    }

    std::vector<PointF> poly_pts;
    poly_pts.reserve(count + 2);
    poly_pts.push_back(PointF(r.X, r.Y + r.Height));
    for (const auto& p : line_pts) poly_pts.push_back(p);
    poly_pts.push_back(PointF(r.X + r.Width, r.Y + r.Height));

    LinearGradientBrush grad(PointF(r.X, r.Y), PointF(r.X, r.Y + r.Height),
        Color(82, grad_col.GetR(), grad_col.GetG(), grad_col.GetB()),
        Color(0,  grad_col.GetR(), grad_col.GetG(), grad_col.GetB()));
    g.FillPolygon(&grad, poly_pts.data(), static_cast<INT>(poly_pts.size()));

    Pen pen(stroke_col, 1.5f);
    pen.SetLineJoin(LineJoinRound);
    g.DrawLines(&pen, line_pts.data(), static_cast<INT>(line_pts.size()));
}

static void draw_input_box(Graphics& g, const RectF& box_r, ActiveInputField field_id,
                           const std::string& text, const wchar_t* placeholder,
                           const Font* font, Color textColor, float char_w, const UiTheme& theme)
{
    bool is_focused = (g_FocusField == field_id);
    Color border_col = is_focused ? theme.focus : theme.border;
    float bw = is_focused ? 1.5f : 1.0f;
    fill_round_card(g, box_r, 6.0f, theme.field, border_col, bw);

    float pad_x = 10.0f;
    float text_x = box_r.X + pad_x;
    float text_w = box_r.Width - pad_x * 2.0f;
    int visible_chars = static_cast<int>(text_w / (char_w > 0.0f ? char_w : 6.0f));
    if (visible_chars < 1) visible_chars = 1;

    StringFormat sf_typ(StringFormat::GenericTypographic());
    sf_typ.SetLineAlignment(StringAlignmentCenter);
    sf_typ.SetFormatFlags(StringFormatFlagsNoWrap);

    if (text.empty()) {
        SolidBrush br_ph(is_focused ? Color(120, theme.ph.GetR(), theme.ph.GetG(), theme.ph.GetB()) : theme.ph);
        RectF r_txt(text_x, box_r.Y, text_w, box_r.Height);
        g.DrawString(placeholder, -1, font, r_txt, &sf_typ, &br_ph);
        if (is_focused) {
            Pen caret_pen(theme.focus, 1.5f);
            g.DrawLine(&caret_pen, text_x, box_r.Y + 7.0f, text_x, box_r.Y + box_r.Height - 7.0f);
        }
        return;
    }

    std::wstring wstr = to_wstr(text);

    int vis_start = 0;
    if (is_focused) {
        if (g_CaretPos < g_ScrollOffset) g_ScrollOffset = g_CaretPos;
        if (g_CaretPos >= g_ScrollOffset + visible_chars) g_ScrollOffset = g_CaretPos - visible_chars + 1;
        if (g_ScrollOffset < 0) g_ScrollOffset = 0;
        if (static_cast<int>(wstr.size()) <= visible_chars) g_ScrollOffset = 0;
        vis_start = g_ScrollOffset;
    }

    int vis_count = std::min(visible_chars, static_cast<int>(wstr.size()) - vis_start);
    if (vis_count < 0) vis_count = 0;
    std::wstring vis_str = (vis_start < static_cast<int>(wstr.size())) ? wstr.substr(vis_start, vis_count) : L"";

    int s_min = is_focused ? std::min(g_SelStart, g_SelEnd) : 0;
    int s_max = is_focused ? std::max(g_SelStart, g_SelEnd) : 0;
    bool has_sel = is_focused && (s_min != s_max);

    int sel_v_start = std::max(s_min, vis_start);
    int sel_v_end   = std::min(s_max, vis_start + vis_count);

    if (has_sel && sel_v_start < sel_v_end) {
        float sel_x = text_x + (sel_v_start - vis_start) * char_w;
        float sel_w = (sel_v_end - sel_v_start) * char_w;
        float sel_y = box_r.Y + 5.0f;
        float sel_h = box_r.Height - 10.0f;
        SolidBrush br_sel(Color(255, 37, 99, 235));
        g.FillRectangle(&br_sel, sel_x, sel_y, sel_w, sel_h);

        int p1_len = sel_v_start - vis_start;
        if (p1_len > 0) {
            std::wstring p1 = vis_str.substr(0, p1_len);
            SolidBrush br_txt(textColor);
            RectF r_p1(text_x, box_r.Y, p1_len * char_w + 2.0f, box_r.Height);
            g.DrawString(p1.c_str(), -1, font, r_p1, &sf_typ, &br_txt);
        }

        int p2_len = sel_v_end - sel_v_start;
        if (p2_len > 0) {
            std::wstring p2 = vis_str.substr(p1_len, p2_len);
            SolidBrush br_white(Color(255, 255, 255));
            RectF r_p2(sel_x, box_r.Y, sel_w + 2.0f, box_r.Height);
            g.DrawString(p2.c_str(), -1, font, r_p2, &sf_typ, &br_white);
        }

        int p3_len = vis_count - (sel_v_end - vis_start);
        if (p3_len > 0) {
            std::wstring p3 = vis_str.substr(p1_len + p2_len, p3_len);
            SolidBrush br_txt(textColor);
            RectF r_p3(sel_x + sel_w, box_r.Y, p3_len * char_w + 2.0f, box_r.Height);
            g.DrawString(p3.c_str(), -1, font, r_p3, &sf_typ, &br_txt);
        }
    } else {
        SolidBrush br_txt(textColor);
        RectF r_txt(text_x, box_r.Y, text_w, box_r.Height);
        g.DrawString(vis_str.c_str(), -1, font, r_txt, &sf_typ, &br_txt);
    }

    if (is_focused) {
        int rel_caret = g_CaretPos - vis_start;
        if (rel_caret >= 0 && rel_caret <= vis_count) {
            float cx = text_x + rel_caret * char_w;
            Pen caret_pen(theme.focus, 1.5f);
            g.DrawLine(&caret_pen, cx, box_r.Y + 7.0f, cx, box_r.Y + box_r.Height - 7.0f);
        }
    }
}

static void format_rate(double bytes_per_sec, std::wstring& out_val, std::wstring& out_unit) {
    wchar_t buf[32];
    if (bytes_per_sec >= 1048576.0) {
        swprintf_s(buf, L"%.1f", bytes_per_sec / 1048576.0);
        out_val = buf;
        out_unit = L"MB/s";
    } else {
        swprintf_s(buf, L"%.1f", bytes_per_sec / 1024.0);
        out_val = buf;
        out_unit = L"KB/s";
    }
}

static std::wstring format_total_bytes(uint64_t b) {
    const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB" };
    int i = 0;
    double v = static_cast<double>(b);
    while (v >= 1024.0 && i < 3) {
        v /= 1024.0;
        i++;
    }
    wchar_t buf[64];
    if (i == 0) swprintf_s(buf, L"Total %.0f %ls", v, units[i]);
    else swprintf_s(buf, L"Total %.1f %ls", v, units[i]);
    return buf;
}

static std::string format_uptime() {
    if (g_State.load() != STATE_CONNECTED || g_ConnectTick == 0) return "00:00:00";
    ULONGLONG sec = (GetTickCount64() - g_ConnectTick) / 1000ULL;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%02u:%02u:%02u",
        static_cast<unsigned>(sec / 3600), static_cast<unsigned>((sec % 3600) / 60), static_cast<unsigned>(sec % 60));
    return buf;
}

static PrivateFontCollection* g_Pfc = nullptr;
static FontFamily* g_FfManropeExtraBold = nullptr;
static FontFamily* g_FfManropeBold = nullptr;
static FontFamily* g_FfManropeSemiBold = nullptr;
static FontFamily* g_FfManropeMedium = nullptr;
static FontFamily* g_FfJbMono = nullptr;
static FontFamily* g_FfJbMonoMed = nullptr;
static FontFamily* g_FfSegoe = nullptr;
static FontFamily* g_FfConsolas = nullptr;

static void load_font_res(HINSTANCE hInst, int res_id, PrivateFontCollection* pfc) {
    HRSRC hRes = FindResourceW(hInst, MAKEINTRESOURCEW(res_id), (LPCWSTR)RT_RCDATA);
    if (!hRes) return;
    HGLOBAL hData = LoadResource(hInst, hRes);
    if (!hData) return;
    void* p = LockResource(hData);
    DWORD sz = SizeofResource(hInst, hRes);
    if (p && sz > 0) {
        pfc->AddMemoryFont(p, static_cast<int>(sz));
    }
}

static void init_custom_fonts(HINSTANCE hInst) {
    if (g_Pfc) return;
    g_Pfc = new PrivateFontCollection();
    for (int id = 301; id <= 307; ++id) {
        load_font_res(hInst, id, g_Pfc);
    }
    if (g_Pfc->GetFamilyCount() == 0) {
        g_Pfc->AddFontFile(L"resources/fonts/Manrope-ExtraBold.ttf");
        g_Pfc->AddFontFile(L"resources/fonts/Manrope-Bold.ttf");
        g_Pfc->AddFontFile(L"resources/fonts/Manrope-SemiBold.ttf");
        g_Pfc->AddFontFile(L"resources/fonts/Manrope-Medium.ttf");
        g_Pfc->AddFontFile(L"resources/fonts/JetBrainsMono-Regular.ttf");
        g_Pfc->AddFontFile(L"resources/fonts/JetBrainsMono-Medium.ttf");
        g_Pfc->AddFontFile(L"resources/fonts/JetBrainsMono-Bold.ttf");
    }

    int count = g_Pfc->GetFamilyCount();
    if (count > 0) {
        std::vector<FontFamily> fams(count);
        int num = 0;
        g_Pfc->GetFamilies(count, fams.data(), &num);
        for (int i = 0; i < num; ++i) {
            WCHAR name[LF_FACESIZE]{};
            fams[i].GetFamilyName(name);
            if (wcscmp(name, L"Manrope ExtraBold") == 0) g_FfManropeExtraBold = new FontFamily(name, g_Pfc);
            else if (wcscmp(name, L"Manrope") == 0) g_FfManropeBold = new FontFamily(name, g_Pfc);
            else if (wcscmp(name, L"Manrope SemiBold") == 0) g_FfManropeSemiBold = new FontFamily(name, g_Pfc);
            else if (wcscmp(name, L"Manrope Medium") == 0) g_FfManropeMedium = new FontFamily(name, g_Pfc);
            else if (wcscmp(name, L"JetBrains Mono") == 0) g_FfJbMono = new FontFamily(name, g_Pfc);
            else if (wcscmp(name, L"JetBrains Mono Medium") == 0) g_FfJbMonoMed = new FontFamily(name, g_Pfc);
        }
    }

    g_FfSegoe = new FontFamily(L"Segoe UI");
    g_FfConsolas = new FontFamily(L"Consolas");
}

static const FontFamily* get_ff_title() { return g_FfManropeExtraBold ? g_FfManropeExtraBold : (g_FfManropeBold ? g_FfManropeBold : g_FfSegoe); }
static const FontFamily* get_ff_bold() { return g_FfManropeBold ? g_FfManropeBold : (g_FfManropeExtraBold ? g_FfManropeExtraBold : g_FfSegoe); }
static const FontFamily* get_ff_semibold() { return g_FfManropeSemiBold ? g_FfManropeSemiBold : (g_FfManropeBold ? g_FfManropeBold : g_FfSegoe); }
static const FontFamily* get_ff_medium() { return g_FfManropeMedium ? g_FfManropeMedium : (g_FfManropeSemiBold ? g_FfManropeSemiBold : g_FfSegoe); }
static const FontFamily* get_ff_mono() { return g_FfJbMono ? g_FfJbMono : g_FfConsolas; }
static const FontFamily* get_ff_mono_med() { return g_FfJbMonoMed ? g_FfJbMonoMed : (g_FfJbMono ? g_FfJbMono : g_FfConsolas); }

static void cleanup_custom_fonts() {
    delete g_FfManropeExtraBold; g_FfManropeExtraBold = nullptr;
    delete g_FfManropeBold; g_FfManropeBold = nullptr;
    delete g_FfManropeSemiBold; g_FfManropeSemiBold = nullptr;
    delete g_FfManropeMedium; g_FfManropeMedium = nullptr;
    delete g_FfJbMono; g_FfJbMono = nullptr;
    delete g_FfJbMonoMed; g_FfJbMonoMed = nullptr;
    delete g_FfSegoe; g_FfSegoe = nullptr;
    delete g_FfConsolas; g_FfConsolas = nullptr;
    delete g_Pfc; g_Pfc = nullptr;
}

static void render_flyout_graphics(Graphics& g, float scale, bool is_dark) {
    g.SetSmoothingMode(SmoothingModeAntiAlias);
    g.SetInterpolationMode(InterpolationModeHighQualityBicubic);
    g.SetPixelOffsetMode(PixelOffsetModeHalf);
    g.SetTextRenderingHint(TextRenderingHintAntiAliasGridFit);
    g.Clear(Color(0, 0, 0, 0));
    g.ScaleTransform(scale, scale);

    UiTheme theme = get_theme(is_dark);

    // Window rounded background (10px radius)
    GraphicsPath win_path;
    add_rounded_rect(win_path, RectF(0.5f, 0.5f, static_cast<float>(PANEL_W) - 1.0f, static_cast<float>(PANEL_H) - 1.0f), 10.0f);
    std::lock_guard<std::recursive_mutex> lk_cfg(g_cfg_mtx);
    SolidBrush bg_br(theme.bg);
    g.FillPath(&bg_br, &win_path);
    Pen win_border(theme.border, 1.0f);
    g.DrawPath(&win_border, &win_path);

    // Fonts matching Main.dc.html exactly:
    Font f_title(get_ff_title(), 15.0f, FontStyleBold, UnitPixel);          // Title: 15px 800
    Font f_status(get_ff_semibold(), 11.5f, FontStyleRegular, UnitPixel);   // Subtitle: 11.5px 600
    Font f_ping(get_ff_bold(), 12.5f, FontStyleBold, UnitPixel);            // Ping: 12.5px 700
    Font f_hero(get_ff_title(), 13.0f, FontStyleBold, UnitPixel);           // Connect: 13px 800
    Font f_badge_lbl(get_ff_bold(), 10.5f, FontStyleBold, UnitPixel);       // Download/Upload badge: 10.5px 700
    Font f_speed_num(get_ff_title(), 21.0f, FontStyleBold, UnitPixel);      // Speed number: 21px 800
    Font f_speed_unit(get_ff_semibold(), 11.0f, FontStyleBold, UnitPixel);  // Speed unit: 11px 600
    Font f_small(get_ff_medium(), 11.0f, FontStyleRegular, UnitPixel);      // Total: 11px 500
    Font f_sec_hdr(get_ff_bold(), 11.0f, FontStyleBold, UnitPixel);         // Section headers: 11px 700
    Font f_btn(get_ff_bold(), 12.0f, FontStyleBold, UnitPixel);             // Clear/Paste/Segment tabs: 12px 700
    Font f_btn_footer(get_ff_bold(), 12.5f, FontStyleBold, UnitPixel);      // Footer buttons: 12.5px 700
    Font f_mono(get_ff_mono(), 11.5f, FontStyleRegular, UnitPixel);         // URI text: 11.5px 400
    Font f_mono_field(get_ff_mono(), 12.0f, FontStyleRegular, UnitPixel);   // Proxy input text: 12px 400
    Font f_chip_proto(get_ff_semibold(), 11.5f, FontStyleBold, UnitPixel);  // VLESS chip: 11.5px 600
    Font f_chip_ip(get_ff_mono_med(), 11.5f, FontStyleRegular, UnitPixel);  // IP:Port chip: 11.5px 500
    Font f_chip_rem(get_ff_semibold(), 11.5f, FontStyleBold, UnitPixel);    // Remark chip: 11.5px 600
    Font f_empty_msg(get_ff_medium(), 12.5f, FontStyleRegular, UnitPixel);  // Empty URI msg: 12.5px 500
    Font f_direct_msg(get_ff_medium(), 12.0f, FontStyleRegular, UnitPixel); // Direct subtitle: 12px 500

    RectF bounds;
    const wchar_t* sample = L"12345678901234567890";
    g.MeasureString(sample, 20, &f_mono, PointF(0, 0), StringFormat::GenericTypographic(), &bounds);
    g_CharW = bounds.Width / 20.0f;
    if (g_CharW <= 0.0f) g_CharW = 6.9f;


        SolidBrush text_br(theme.text);
        SolidBrush muted_br(theme.muted);
        SolidBrush sky_br(theme.sky);
        SolidBrush ghost_br(theme.ghost);

        StringFormat sf_center; sf_center.SetAlignment(StringAlignmentCenter); sf_center.SetLineAlignment(StringAlignmentCenter);
        sf_center.SetFormatFlags(StringFormatFlagsNoWrap);
        StringFormat sf_left; sf_left.SetAlignment(StringAlignmentNear); sf_left.SetLineAlignment(StringAlignmentCenter);
        sf_left.SetFormatFlags(StringFormatFlagsNoWrap); sf_left.SetTrimming(StringTrimmingEllipsisCharacter);

        // ----------------------------------------------------
        // SECTION 1: HEADER
        // ----------------------------------------------------
        // Circular Logo (36x36 at 12, 12)
        if (g_LogoBmp) {
            GraphicsPath logo_clip;
            logo_clip.AddEllipse(12.0f, 12.0f, 36.0f, 36.0f);
            Region old_clip;
            g.GetClip(&old_clip);
            g.SetClip(&logo_clip, CombineModeIntersect);
            g.DrawImage(g_LogoBmp, RectF(12.0f, 12.0f, 36.0f, 36.0f));
            g.SetClip(&old_clip);
        } else {
            SolidBrush fallback_bg(theme.card);
            g.FillEllipse(&fallback_bg, 12.0f, 12.0f, 36.0f, 36.0f);
        }

        // Status Dot with background cutout ring (38, 38)
        TunnelState st = g_State.load();
        Color dot_col;
        std::wstring status_line;
        Color status_col;

        ULONGLONG now = GetTickCount64();
        float dot_cx = 43.0f, dot_cy = 43.0f, dot_r = 5.0f;

        bool can_connect = g_cfg.vless_valid || (g_cfg.chain_type != CHAIN_NONE && !g_cfg.chain_addr_str.empty());

        if (st == STATE_CONNECTED) {
            status_line = L"Connected  " + to_wstr(format_uptime());
            status_col = theme.green;
            dot_col = Color(255, 16, 185, 129); // #10b981
            // nrPulse: 1.6s ease-out infinite (expanding ripple)
            float cycle = 1600.0f;
            float t = std::fmod(static_cast<float>(now), cycle) / cycle;
            float ring_r = dot_r + t * 7.0f;
            int alpha = static_cast<int>((1.0f - t) * 140.0f);
            if (alpha > 0) {
                Pen pulse_pen(Color(alpha, 52, 211, 153), 1.8f);
                g.DrawEllipse(&pulse_pen, dot_cx - ring_r, dot_cy - ring_r, ring_r * 2.0f, ring_r * 2.0f);
            }
        } else if (st == STATE_CONNECTING) {
            status_line = L"Connecting...";
            status_col = is_dark ? Color(255, 251, 191, 36) : Color(255, 180, 83, 9); // #fbbf24 / #b45309
            dot_col = Color(255, 245, 158, 11); // #f59e0b
            // nrPulseWarn: 1.0s ease-out infinite (expanding ripple)
            float cycle = 1000.0f;
            float t = std::fmod(static_cast<float>(now), cycle) / cycle;
            float ring_r = dot_r + t * 7.0f;
            int alpha = static_cast<int>((1.0f - t) * 165.0f);
            if (alpha > 0) {
                Pen pulse_pen(Color(alpha, 245, 158, 11), 1.8f);
                g.DrawEllipse(&pulse_pen, dot_cx - ring_r, dot_cy - ring_r, ring_r * 2.0f, ring_r * 2.0f);
            }
        } else if (st == STATE_FAILED && can_connect) {
            std::string smsg = get_status_msg();
            status_line = smsg.empty() ? L"Connection failed" : to_wstr(smsg);
            status_col = theme.danger_text;
            dot_col = Color(255, 239, 68, 68); // #ef4444
        } else {
            status_line = L"Disconnected  " + to_wstr(format_uptime());
            status_col = theme.muted;
            dot_col = Color(255, 239, 68, 68); // #ef4444
        }

        // Cutout ring & solid dot
        SolidBrush cutout_br(theme.bg);
        g.FillEllipse(&cutout_br, 36.0f, 36.0f, 14.0f, 14.0f);
        SolidBrush dot_br(dot_col);
        g.FillEllipse(&dot_br, 38.0f, 38.0f, 10.0f, 10.0f);

        // Title "NanoRay"
        g.DrawString(L"NanoRay", -1, &f_title, PointF(56.0f, 12.0f), &text_br);

        // Subtitle Status Line
        SolidBrush stat_br(status_col);
        g.DrawString(status_line.c_str(), -1, &f_status, PointF(56.0f, 31.0f), &stat_br);

        // Theme Toggle button at (254, 14, 32, 32)
        RectF r_theme = get_btn_rect(R_BTN_THEME, 9);
        Color theme_btn_bg = (g_HoverBtn == 9) ? (is_dark ? Color(255, 28, 34, 48) : Color(255, 238, 241, 246)) : theme.card;
        fill_round_card(g, r_theme, 7.0f, theme_btn_bg, theme.border, 1.0f);
        if (is_dark) {
            draw_svg_sun(g, r_theme.X + (r_theme.Width - 15.0f) * 0.5f, r_theme.Y + (r_theme.Height - 15.0f) * 0.5f, 15.0f, theme.muted);
        } else {
            draw_svg_moon(g, r_theme.X + (r_theme.Width - 15.0f) * 0.5f, r_theme.Y + (r_theme.Height - 15.0f) * 0.5f, 15.0f, theme.muted);
        }

        // Ping button at (292, 14, 96, 32)
        RectF r_ping = get_btn_rect(R_BTN_PING, 1);
        Color ping_btn_bg = (g_HoverBtn == 1) ? (is_dark ? Color(255, 28, 34, 48) : Color(255, 238, 241, 246)) : theme.card;
        fill_round_card(g, r_ping, 7.0f, ping_btn_bg, theme.border, 1.0f);
        int p_ms = g_LastPingMs.load();
        wchar_t ping_txt[32];
        if (p_ms == PING_TESTING) swprintf_s(ping_txt, L"Testing...");
        else if (p_ms == PING_TIMEOUT) swprintf_s(ping_txt, L"Timeout");
        else if (p_ms >= 0) swprintf_s(ping_txt, L"%d ms", p_ms);
        else swprintf_s(ping_txt, L"Ping Test");

        Color ping_col = can_connect ? theme.sky : theme.muted;
        SolidBrush ping_txt_br(ping_col);

        RectF ping_bounds;
        g.MeasureString(ping_txt, -1, &f_ping, PointF(0, 0), StringFormat::GenericTypographic(), &ping_bounds);
        float ping_content_w = 14.0f + 7.0f + ping_bounds.Width;
        float ping_start_x = r_ping.X + (r_ping.Width - ping_content_w) / 2.0f;
        draw_svg_ecg(g, ping_start_x, r_ping.Y + (r_ping.Height - 14.0f) * 0.5f, 14.0f, ping_col);
        PointF ping_txt_pt(ping_start_x + 21.0f, r_ping.Y + (r_ping.Height - ping_bounds.Height) / 2.0f);
        g.DrawString(ping_txt, -1, &f_ping, ping_txt_pt, &ping_txt_br);

        // ----------------------------------------------------
        // SECTION 2: MAIN CONNECT BUTTON (Y=62, H=44)
        // ----------------------------------------------------
        RectF r_conn = get_btn_rect(R_BTN_CONNECT, 2);
        Color btn_c1, btn_c2, btn_border;
        const wchar_t* btn_text = L"CONNECT SYSTEM TUNNEL";
        bool show_power = true;
        bool show_spinner = false;
        bool show_retry = false;

        if (st == STATE_CONNECTED) {
            btn_c1 = Color(255, 4, 120, 87);
            btn_c2 = Color(255, 13, 148, 136);
            btn_border = Color(160, 52, 211, 153);
            btn_text = L"DISCONNECT";
        } else if (st == STATE_CONNECTING) {
            btn_c1 = Color(255, 180, 83, 9);
            btn_c2 = Color(255, 217, 119, 6);
            btn_border = Color(160, 245, 158, 11);
            btn_text = L"CONNECTING...";
            show_power = false;
            show_spinner = true;
        } else if (st == STATE_FAILED && can_connect) {
            btn_c1 = Color(255, 185, 28, 28);
            btn_c2 = Color(255, 220, 38, 38);
            btn_border = Color(160, 248, 113, 113);
            btn_text = L"RETRY";
            show_power = false;
            show_retry = true;
        } else if (!can_connect) {
            btn_c1 = is_dark ? Color(255, 30, 41, 59) : Color(255, 241, 245, 249);
            btn_c2 = is_dark ? Color(255, 30, 41, 59) : Color(255, 241, 245, 249);
            btn_border = is_dark ? Color(255, 51, 65, 85) : Color(255, 226, 232, 240);
            btn_text = L"CONNECT SYSTEM TUNNEL";
            show_power = true;
        } else {
            btn_c1 = (g_HoverBtn == 2) ? Color(255, 37, 99, 235) : Color(255, 29, 78, 216);
            btn_c2 = (g_HoverBtn == 2) ? Color(255, 14, 165, 233) : Color(255, 2, 132, 199);
            btn_border = Color(160, 56, 189, 248);
        }

        GraphicsPath btn_path;
        add_rounded_rect(btn_path, r_conn, 8.0f);
        LinearGradientBrush btn_grad(PointF(r_conn.X, r_conn.Y),
            PointF(r_conn.X + r_conn.Width, r_conn.Y + r_conn.Height), btn_c1, btn_c2);
        g.FillPath(&btn_grad, &btn_path);
        Pen btn_pen(btn_border, 1.0f);
        g.DrawPath(&btn_pen, &btn_path);

        RectF text_bounds;
        g.MeasureString(btn_text, -1, &f_hero, PointF(0, 0), StringFormat::GenericTypographic(), &text_bounds);
        float icon_w = (show_power || show_spinner || show_retry) ? 26.0f : 0.0f;
        float content_w = text_bounds.Width + icon_w;
        float start_x = r_conn.X + (r_conn.Width - content_w) / 2.0f;
        float mid_y = r_conn.Y + r_conn.Height / 2.0f;

        Color btn_txt_color = can_connect ? Color(255, 255, 255, 255) : theme.muted;
        SolidBrush text_br_conn(btn_txt_color);

        if (show_power) {
            draw_svg_power(g, start_x, mid_y - 8.5f, 17.0f, btn_txt_color);
        } else if (show_spinner) {
            float spin_angle = std::fmod(static_cast<float>(now), 900.0f) / 900.0f * 360.0f;
            draw_svg_spinner(g, start_x, mid_y - 8.5f, 17.0f, Color(255, 255, 255), spin_angle);
        } else if (show_retry) {
            draw_svg_refresh(g, start_x, mid_y - 8.5f, 17.0f, Color(255, 255, 255), 2.4f);
        }
        g.DrawString(btn_text, -1, &f_hero, PointF(start_x + icon_w, mid_y - text_bounds.Height / 2.0f), &text_br_conn);

        // ----------------------------------------------------
        // SECTION 3: METRICS (DOWNLOAD & UPLOAD CARDS Y=116, H=118)
        // ----------------------------------------------------
        StringFormat sf_typo(StringFormat::GenericTypographic());
        sf_typo.SetFormatFlags(StringFormatFlagsNoFitBlackBox | StringFormatFlagsMeasureTrailingSpaces);

        // Download Card (12, 116, 184, 118)
        fill_round_card(g, R_CARD_DL, 8.0f, theme.card, theme.border, 1.0f);
        fill_round_card(g, RectF(22.0f, 126.0f, 20.0f, 20.0f), 5.0f, theme.green_area, Color(0,0,0,0));
        draw_svg_download(g, 26.0f, 130.0f, 12.0f, theme.green);
        g.DrawString(L"DOWNLOAD", -1, &f_badge_lbl, PointF(49.0f, 128.0f), &muted_br);

        std::wstring dl_val, dl_unit;
        format_rate(g_SpeedRxKB * 1024.0, dl_val, dl_unit);
        RectF dl_val_rect;
        g.MeasureString(dl_val.c_str(), -1, &f_speed_num, PointF(0, 0), &sf_typo, &dl_val_rect);
        g.DrawString(dl_val.c_str(), -1, &f_speed_num, PointF(22.0f, 149.0f), &sf_typo, &text_br);
        g.DrawString(dl_unit.c_str(), -1, &f_speed_unit, PointF(22.0f + dl_val_rect.Width + 4.0f, 158.0f), &sf_typo, &muted_br);

        RectF r_graph_dl(22.0f, 180.0f, 164.0f, 24.0f);
        draw_sparkline(g, r_graph_dl, g_SparkRx, SPARK_COUNT, 262144.0f, theme.green, theme.green);
        std::wstring dl_total_str = format_total_bytes(g_TotalRx.load());
        g.DrawString(dl_total_str.c_str(), -1, &f_small, PointF(22.0f, 209.0f), &sf_typo, &muted_br);

        // Upload Card (204, 116, 184, 118)
        fill_round_card(g, R_CARD_UL, 8.0f, theme.card, theme.border, 1.0f);
        fill_round_card(g, RectF(214.0f, 126.0f, 20.0f, 20.0f), 5.0f, theme.sky_bg, Color(0,0,0,0));
        draw_svg_upload(g, 218.0f, 130.0f, 12.0f, theme.sky);
        g.DrawString(L"UPLOAD", -1, &f_badge_lbl, PointF(241.0f, 128.0f), &muted_br);

        std::wstring ul_val, ul_unit;
        format_rate(g_SpeedTxKB * 1024.0, ul_val, ul_unit);
        RectF ul_val_rect;
        g.MeasureString(ul_val.c_str(), -1, &f_speed_num, PointF(0, 0), &sf_typo, &ul_val_rect);
        g.DrawString(ul_val.c_str(), -1, &f_speed_num, PointF(214.0f, 149.0f), &sf_typo, &text_br);
        g.DrawString(ul_unit.c_str(), -1, &f_speed_unit, PointF(214.0f + ul_val_rect.Width + 4.0f, 158.0f), &sf_typo, &muted_br);

        RectF r_graph_ul(214.0f, 180.0f, 164.0f, 24.0f);
        draw_sparkline(g, r_graph_ul, g_SparkTx, SPARK_COUNT, 65536.0f, theme.sky, theme.sky);
        std::wstring ul_total_str = format_total_bytes(g_TotalTx.load());
        g.DrawString(ul_total_str.c_str(), -1, &f_small, PointF(214.0f, 209.0f), &sf_typo, &muted_br);

        // ----------------------------------------------------
        // SECTION 4: SERVER CARD (Y=245.5, H=113)
        // ----------------------------------------------------
        fill_round_card(g, R_CARD_VLESS, 8.0f, theme.card, theme.border, 1.0f);
        const wchar_t* sec_title = (g_cfg.vless_valid && g_cfg.outbound_proto == PROTO_TROJAN) ? L"TROJAN SERVER" : L"VLESS SERVER";
        g.DrawString(sec_title, -1, &f_sec_hdr, PointF(24.0f, 258.0f), &muted_br);

        // Clear Button
        RectF r_clr = get_btn_rect(R_BTN_CLEAR_URI, 7);
        Color clr_bg = (g_HoverBtn == 7) ? (is_dark ? Color(255, 28, 34, 48) : Color(255, 238, 241, 246)) : Color(0,0,0,0);
        fill_round_card(g, r_clr, 5.0f, clr_bg, theme.border, 1.0f);
        g.DrawString(L"Clear", -1, &f_btn, r_clr, &sf_center, &ghost_br);

        // Paste URI Button
        RectF r_p_uri = get_btn_rect(R_BTN_PASTE_URI, 3);
        Color paste_bg = (g_HoverBtn == 3) ? (is_dark ? Color(50, 14, 165, 233) : Color(45, 2, 132, 199)) : theme.sky_bg;
        fill_round_card(g, r_p_uri, 5.0f, paste_bg, theme.sky_border, 1.0f);
        draw_svg_clipboard(g, r_p_uri.X + 10.0f, r_p_uri.Y + (r_p_uri.Height - 12.0f) * 0.5f, 12.0f, theme.sky, 2.4f);
        RectF r_paste_txt(r_p_uri.X + 24.0f, r_p_uri.Y, r_p_uri.Width - 28.0f, r_p_uri.Height);
        g.DrawString(L"Paste URI", -1, &f_btn, r_paste_txt, &sf_center, &sky_br);

        // Always draw input box so user can click, focus, and type manually even before a URI is valid
        draw_input_box(g, R_INP_VLESS_URI, FIELD_VLESS_URI, g_cfg.raw_vless_uri,
                       L"vless:// or trojan:// URI", &f_mono, theme.uri, g_CharW, theme);

        if (g_cfg.vless_valid) {
            float curr_chip_x = 24.0f;
            // Chip 1: Protocol & Transport Badge
            std::wstring base_proto = (g_cfg.outbound_proto == PROTO_TROJAN) ? L"TROJAN" : L"VLESS";
            std::wstring proto_name = base_proto;
            std::string t = g_cfg.vless_type.empty() ? "tcp" : g_cfg.vless_type;
            std::string s = g_cfg.vless_security.empty() ? "none" : g_cfg.vless_security;
            bool is_vision = (g_cfg.vless_flow == "xtls-rprx-vision");

            if (t == "ws") {
                if (s == "reality") proto_name = is_vision ? base_proto + L" · WS+REALITY+VISION (basic)" : base_proto + L" · WS+REALITY";
                else if (s == "tls") proto_name = base_proto + L" · WS+TLS";
                else proto_name = base_proto + L" · WS";
            } else if (t == "xhttp") {
                if (s == "reality") proto_name = is_vision ? base_proto + L" · XHTTP+REALITY+VISION (basic)" : base_proto + L" · XHTTP+REALITY";
                else if (s == "tls") proto_name = base_proto + L" · XHTTP+TLS";
                else proto_name = base_proto + L" · XHTTP";
            } else if (t == "httpupgrade") {
                if (s == "reality") proto_name = is_vision ? base_proto + L" · HTTPUPGRADE+REALITY+VISION (basic)" : base_proto + L" · HTTPUPGRADE+REALITY";
                else if (s == "tls") proto_name = base_proto + L" · HTTPUPGRADE+TLS";
                else proto_name = base_proto + L" · HTTPUPGRADE";
            } else if (t == "grpc") {
                if (s == "reality") proto_name = is_vision ? base_proto + L" · GRPC+REALITY+VISION (basic)" : base_proto + L" · GRPC+REALITY";
                else if (s == "tls") proto_name = base_proto + L" · GRPC+TLS";
                else proto_name = base_proto + L" · GRPC";
            } else {
                if (s == "reality") proto_name = is_vision ? base_proto + L" · TCP+REALITY+VISION (basic)" : base_proto + L" · TCP+REALITY";
                else if (s == "tls") proto_name = is_vision ? base_proto + L" · TCP+TLS+VISION (basic)" : base_proto + L" · TCP+TLS";
                else proto_name = base_proto + L" · TCP";
            }

            RectF proto_rc;
            g.MeasureString(proto_name.c_str(), -1, &f_chip_proto, PointF(0, 0), StringFormat::GenericTypographic(), &proto_rc);
            float w1 = proto_rc.Width + 14.0f;
            fill_round_card(g, RectF(curr_chip_x, 327.5f, w1, 20.0f), 5.0f, theme.sky_bg, Color(0,0,0,0));
            SolidBrush proto_br(theme.proto);
            g.DrawString(proto_name.c_str(), -1, &f_chip_proto, RectF(curr_chip_x, 327.5f, w1, 20.0f), &sf_center, &proto_br);
            curr_chip_x += w1 + 6.0f;

            // Chip 2: Node IP:Port
            std::wstring node_str = to_wstr(g_cfg.vless_ip + ":" + std::to_string(g_cfg.vless_port));
            RectF node_rc;
            g.MeasureString(node_str.c_str(), -1, &f_chip_ip, PointF(0, 0), StringFormat::GenericTypographic(), &node_rc);
            float w2 = node_rc.Width + 14.0f;
            fill_round_card(g, RectF(curr_chip_x, 327.5f, w2, 20.0f), 5.0f, theme.chip, Color(0,0,0,0));
            SolidBrush chip_txt_br(theme.chip_text);
            g.DrawString(node_str.c_str(), -1, &f_chip_ip, RectF(curr_chip_x, 327.5f, w2, 20.0f), &sf_center, &chip_txt_br);
            curr_chip_x += w2 + 6.0f;

            // Chip 3: Fingerprint (if specified)
            if (!g_cfg.vless_fp.empty()) {
                std::wstring fp_str = L"fp: " + to_wstr(g_cfg.vless_fp);
                RectF fp_rc;
                g.MeasureString(fp_str.c_str(), -1, &f_chip_ip, PointF(0, 0), StringFormat::GenericTypographic(), &fp_rc);
                float w_fp = fp_rc.Width + 14.0f;
                if (curr_chip_x + w_fp < R_CARD_VLESS.X + R_CARD_VLESS.Width - 40.0f) {
                    fill_round_card(g, RectF(curr_chip_x, 327.5f, w_fp, 20.0f), 5.0f, theme.chip, Color(0,0,0,0));
                    g.DrawString(fp_str.c_str(), -1, &f_chip_ip, RectF(curr_chip_x, 327.5f, w_fp, 20.0f), &sf_center, &chip_txt_br);
                    curr_chip_x += w_fp + 6.0f;
                }
            }

            // Chip 4: Remark Tag
            std::wstring rem_str = to_wstr(g_cfg.vless_remark);
            RectF rem_rc;
            g.MeasureString(rem_str.c_str(), -1, &f_chip_rem, PointF(0, 0), StringFormat::GenericTypographic(), &rem_rc);
            float max_rem_w = R_CARD_VLESS.X + R_CARD_VLESS.Width - 12.0f - curr_chip_x;
            float w3 = std::min(max_rem_w, rem_rc.Width + 14.0f);
            if (w3 > 24.0f) {
                fill_round_card(g, RectF(curr_chip_x, 327.5f, w3, 20.0f), 5.0f, theme.chip, Color(0,0,0,0));
                g.DrawString(rem_str.c_str(), -1, &f_chip_rem, RectF(curr_chip_x, 327.5f, w3, 20.0f), &sf_center, &chip_txt_br);
            }
        } else {
            RectF r_hint(24.0f, 327.5f, 352.0f, 20.0f);
            if (g_cfg.chain_type != CHAIN_NONE && !g_cfg.chain_addr_str.empty()) {
                std::wstring p_name = (g_cfg.chain_type == CHAIN_SOCKS5) ? L"SOCKS5" : L"HTTP";
                std::wstring msg = L"Direct " + p_name + L" Proxy mode (No VLESS URI needed)";
                g.DrawString(msg.c_str(), -1, &f_empty_msg, r_hint, &sf_center, &muted_br);
            } else if (g_cfg.raw_vless_uri.empty()) {
                g.DrawString(L"Type or paste a VLESS or Trojan URI above", -1, &f_empty_msg, r_hint, &sf_center, &muted_br);
            } else {
                g.DrawString(L"Invalid or incomplete server URI", -1, &f_empty_msg, r_hint, &sf_center, &muted_br);
            }
        }

        // ----------------------------------------------------
        // SECTION 5: UPSTREAM PROXY CARD (Y=370, H=118)
        // ----------------------------------------------------
        fill_round_card(g, R_CARD_PROXY, 8.0f, theme.card, theme.border, 1.0f);
        g.DrawString(L"UPSTREAM PROXY", -1, &f_sec_hdr, PointF(24.0f, 381.0f), &muted_br);

        // Optional badge
        RectF r_opt(318.0f, 379.0f, 58.0f, 18.0f);
        fill_round_card(g, r_opt, 4.0f, theme.chip, Color(0,0,0,0));
        g.DrawString(L"Optional", -1, &f_badge_lbl, r_opt, &sf_center, &muted_br);

        // Segmented Control background
        fill_round_card(g, RectF(24.0f, 403.0f, 352.0f, 34.0f), 7.0f, theme.field, Color(0,0,0,0));

        // Animated Sliding Indicator Pill
        Color pill_bg = is_dark ? theme.sky_border : Color(255, 3, 105, 161);
        fill_round_card(g, RectF(g_SegPillX, 406.0f, 112.0f, 28.0f), 5.0f, pill_bg, Color(0,0,0,0));

        auto draw_seg_tab = [&](const RectF& r, ChainType type, const wchar_t* txt, int btn_idx) {
            bool active = (g_cfg.chain_type == type);
            if (active) {
                SolidBrush active_txt_br(is_dark ? Color(255, 4, 18, 28) : Color(255, 255, 255, 255));
                g.DrawString(txt, -1, &f_btn, r, &sf_center, &active_txt_br);
            } else {
                if (g_HoverBtn == btn_idx) {
                    fill_round_card(g, r, 5.0f, theme.chip, Color(0,0,0,0));
                }
                g.DrawString(txt, -1, &f_btn, r, &sf_center, &ghost_br);
            }
        };
        draw_seg_tab(R_BTN_CH_NONE, CHAIN_NONE, L"Direct (off)", 10);
        draw_seg_tab(R_BTN_CH_SOCKS5, CHAIN_SOCKS5, L"SOCKS5", 11);
        draw_seg_tab(R_BTN_CH_HTTP, CHAIN_HTTP, L"HTTP", 12);

        if (g_cfg.chain_type == CHAIN_NONE) {
            g.DrawString(L"Direct connection, no upstream proxy.", -1, &f_direct_msg, PointF(24.0f, 451.0f), &muted_br);
        } else {
            draw_input_box(g, R_INP_CH_ADDR, FIELD_CHAIN_ADDR, g_cfg.chain_addr_str,
                           L"host:port", &f_mono_field, theme.text, g_CharW, theme);
            draw_input_box(g, R_INP_CH_AUTH, FIELD_CHAIN_AUTH, g_cfg.chain_auth_str,
                           L"user:pass", &f_mono_field, theme.text, g_CharW, theme);

            RectF r_p_ch = get_btn_rect(R_BTN_PASTE_CH, 8);
            Color pproxy_bg = (g_HoverBtn == 8) ? (is_dark ? Color(50, 14, 165, 233) : Color(45, 2, 132, 199)) : theme.sky_bg;
            fill_round_card(g, r_p_ch, 6.0f, pproxy_bg, theme.sky_border, 1.0f);
            draw_svg_clipboard(g, r_p_ch.X + (r_p_ch.Width - 14.0f) * 0.5f, r_p_ch.Y + (r_p_ch.Height - 14.0f) * 0.5f, 14.0f, theme.sky, 2.3f);
        }

        // ----------------------------------------------------
        // SECTION 6: FOOTER ACTIONS (Y=502, H=38)
        // ----------------------------------------------------
        // Flush DNS
        bool is_flushed = (GetTickCount64() < g_FlushFeedbackTicks);
        RectF r_flush = get_btn_rect(R_BTN_FLUSHDNS, 4);
        Color f_dns_bg = (g_HoverBtn == 4) ? (is_dark ? Color(255, 28, 34, 48) : Color(255, 238, 241, 246)) : theme.card;
        fill_round_card(g, r_flush, 7.0f, f_dns_bg, is_flushed ? theme.green : theme.border, 1.0f);
        const wchar_t* flush_txt = is_flushed ? L"Flushed!" : L"Flush DNS";
        Color flush_col = is_flushed ? theme.green : theme.text;
        SolidBrush flush_br(flush_col);
        RectF flush_b;
        g.MeasureString(flush_txt, -1, &f_btn_footer, PointF(0, 0), StringFormat::GenericTypographic(), &flush_b);
        float flush_cw = 14.0f + 6.0f + flush_b.Width;
        float flush_sx = r_flush.X + (r_flush.Width - flush_cw) / 2.0f;
        float flush_my = r_flush.Y + r_flush.Height / 2.0f;
        if (is_flushed) draw_svg_check(g, flush_sx, flush_my - 7.0f, 14.0f, theme.green);
        else draw_svg_refresh(g, flush_sx, flush_my - 7.0f, 14.0f, theme.text, 2.3f);
        g.DrawString(flush_txt, -1, &f_btn_footer, PointF(flush_sx + 20.0f, flush_my - flush_b.Height / 2.0f), &flush_br);

        // Quit Tunnel
        RectF r_quit = get_btn_rect(R_BTN_EXIT, 6);
        Color f_quit_bg = (g_HoverBtn == 6) ? Color(40, 248, 113, 113) : theme.danger_bg;
        fill_round_card(g, r_quit, 7.0f, f_quit_bg, theme.danger_border, 1.0f);
        SolidBrush danger_br(theme.danger_text);
        RectF quit_b;
        g.MeasureString(L"Quit Tunnel", -1, &f_btn_footer, PointF(0, 0), StringFormat::GenericTypographic(), &quit_b);
        float quit_cw = 14.0f + 6.0f + quit_b.Width;
        float quit_sx = r_quit.X + (r_quit.Width - quit_cw) / 2.0f;
        float quit_my = r_quit.Y + r_quit.Height / 2.0f;
        draw_svg_exit(g, quit_sx, quit_my - 7.0f, 14.0f, theme.danger_text);
        g.DrawString(L"Quit Tunnel", -1, &f_btn_footer, PointF(quit_sx + 20.0f, quit_my - quit_b.Height / 2.0f), &danger_br);
    }

static void update_layered_flyout() {
    if (!g_Hwnd || !IsWindowVisible(g_Hwnd)) return;
    float scale = get_dpi_scale();
    int cur_win_w = static_cast<int>(std::round(WIN_W * scale));
    int cur_win_h = static_cast<int>(std::round(WIN_H * scale));

    HDC screen_dc = GetDC(nullptr), mem_dc = CreateCompatibleDC(screen_dc);
    BITMAPINFO bmi{};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = cur_win_w; bmi.bmiHeader.biHeight = -cur_win_h;
    bmi.bmiHeader.biPlanes = 1; bmi.bmiHeader.biBitCount = 32; bmi.bmiHeader.biCompression = BI_RGB;
    void* pvBits = nullptr;
    HBITMAP hBmp = CreateDIBSection(mem_dc, &bmi, DIB_RGB_COLORS, &pvBits, nullptr, 0);
    HBITMAP hOldBmp = static_cast<HBITMAP>(SelectObject(mem_dc, hBmp));

    {
        Graphics g(mem_dc);
        render_flyout_graphics(g, scale, g_cfg.is_dark_mode);
    }

    RECT wnd_rect{}; GetWindowRect(g_Hwnd, &wnd_rect);
    POINT pt_dst = { wnd_rect.left, wnd_rect.top }, pt_src = { 0, 0 };
    SIZE wnd_sz = { cur_win_w, cur_win_h };
    BLENDFUNCTION blend{ AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    UpdateLayeredWindow(g_Hwnd, screen_dc, &pt_dst, &wnd_sz, mem_dc, &pt_src, 0, &blend, ULW_ALPHA);

    SelectObject(mem_dc, hOldBmp); DeleteObject(hBmp); DeleteDC(mem_dc); ReleaseDC(nullptr, screen_dc);
}

static int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0, size = 0;
    GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;
    ImageCodecInfo* pImageCodecInfo = (ImageCodecInfo*)(malloc(size));
    if (!pImageCodecInfo) return -1;
    GetImageEncoders(num, size, pImageCodecInfo);
    for (UINT j = 0; j < num; ++j) {
        if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[j].Clsid;
            free(pImageCodecInfo);
            return j;
        }
    }
    free(pImageCodecInfo);
    return -1;
}

void export_flyout_preview(const wchar_t* filename, bool is_dark) {
    Bitmap bmp(PANEL_W, PANEL_H, PixelFormat32bppARGB);
    Graphics g(&bmp);
    render_flyout_graphics(g, 1.0f, is_dark);
    CLSID pngClsid;
    if (GetEncoderClsid(L"image/png", &pngClsid) >= 0) {
        bmp.Save(filename, &pngClsid, nullptr);
    }
}

void request_flyout_repaint() {
    if (g_Hwnd) PostMessageW(g_Hwnd, WM_REPAINT_FLYOUT, 0, 0);
}

void show_tray_flyout() {
    float scale = get_dpi_scale();
    int cur_win_w = static_cast<int>(std::round(WIN_W * scale));
    int cur_win_h = static_cast<int>(std::round(WIN_H * scale));

    RECT work_area{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work_area, 0);

    NOTIFYICONIDENTIFIER nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_Hwnd;
    nid.uID = 1;

    RECT icon_rect{};
    HRESULT hr = Shell_NotifyIconGetRect(&nid, &icon_rect);

    int x = 0, y = 0;
    int pad = static_cast<int>(std::round(8.0f * scale));
    int margin = static_cast<int>(std::round(12.0f * scale));

    if (SUCCEEDED(hr) && icon_rect.right > icon_rect.left && icon_rect.bottom > icon_rect.top) {
        x = (icon_rect.left + icon_rect.right - cur_win_w) / 2;
        if (icon_rect.top >= work_area.bottom - static_cast<int>(100.0f * scale)) {
            y = icon_rect.top - cur_win_h - pad;
        } else if (icon_rect.bottom <= work_area.top + static_cast<int>(100.0f * scale)) {
            y = icon_rect.bottom + pad;
        } else {
            y = icon_rect.bottom - cur_win_h;
        }
    } else {
        x = work_area.right - cur_win_w - margin;
        y = work_area.bottom - cur_win_h - margin;
    }

    if (x + cur_win_w > work_area.right - pad) x = work_area.right - cur_win_w - pad;
    if (x < work_area.left + pad) x = work_area.left + pad;
    if (y + cur_win_h > work_area.bottom - pad) y = work_area.bottom - cur_win_h - pad;
    if (y < work_area.top + pad) y = work_area.top + pad;

    if (g_cfg.chain_type == CHAIN_NONE) g_SegTargetX = g_SegPillX = 27.0f;
    else if (g_cfg.chain_type == CHAIN_SOCKS5) g_SegTargetX = g_SegPillX = 143.0f;
    else if (g_cfg.chain_type == CHAIN_HTTP) g_SegTargetX = g_SegPillX = 259.0f;

    bool can_connect = g_cfg.vless_valid || (g_cfg.chain_type != CHAIN_NONE && !g_cfg.chain_addr_str.empty());
    if (!can_connect && g_State.load() == STATE_FAILED) {
        g_State = STATE_DISCONNECTED;
        set_status_msg("");
        update_tray_icon();
    }

    SetWindowPos(g_Hwnd, HWND_TOPMOST, x, y, cur_win_w, cur_win_h, SWP_SHOWWINDOW);
    SetForegroundWindow(g_Hwnd);
    SetActiveWindow(g_Hwnd);
    SetFocus(g_Hwnd);
    SetTimer(g_Hwnd, IDT_ANIM, 16, nullptr);
    SetTimer(g_Hwnd, IDT_STATS, 1000, nullptr);
    update_layered_flyout();
}

void update_flyout_stats() {
    uint64_t rx = g_TotalRx.load(), tx = g_TotalTx.load();
    if (g_LastRx > 0 && rx >= g_LastRx) g_SpeedRxKB = static_cast<double>(rx - g_LastRx) / 1024.0;
    else g_SpeedRxKB = 0.0;
    if (g_LastTx > 0 && tx >= g_LastTx) g_SpeedTxKB = static_cast<double>(tx - g_LastTx) / 1024.0;
    else g_SpeedTxKB = 0.0;
    g_LastRx = rx; g_LastTx = tx;

    for (int i = 0; i < SPARK_COUNT - 1; ++i) {
        g_SparkRx[i] = g_SparkRx[i + 1];
        g_SparkTx[i] = g_SparkTx[i + 1];
    }
    TunnelState st = g_State.load();
    if (st == STATE_CONNECTED) {
        if (g_SpeedRxKB > 0.0) {
            g_SparkRx[SPARK_COUNT - 1] = static_cast<float>(g_SpeedRxKB * 1024.0);
        } else {
            float idle_wave = 15000.0f + 12000.0f * std::sin(static_cast<float>(GetTickCount64()) / 800.0f);
            g_SparkRx[SPARK_COUNT - 1] = idle_wave;
        }
        if (g_SpeedTxKB > 0.0) {
            g_SparkTx[SPARK_COUNT - 1] = static_cast<float>(g_SpeedTxKB * 1024.0);
        } else {
            float idle_wave = 6000.0f + 4000.0f * std::cos(static_cast<float>(GetTickCount64()) / 900.0f);
            g_SparkTx[SPARK_COUNT - 1] = idle_wave;
        }
    } else {
        g_SparkRx[SPARK_COUNT - 1] = 0.0f;
        g_SparkTx[SPARK_COUNT - 1] = 0.0f;
    }

    static ULONGLONG s_last_ui_trim = 0;
    ULONGLONG now_ui = GetTickCount64();
    if (now_ui - s_last_ui_trim >= 20000) {
        s_last_ui_trim = now_ui;
        EmptyWorkingSet(GetCurrentProcess());
        SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
    }

    if (g_Hwnd && IsWindowVisible(g_Hwnd)) {
        update_layered_flyout();
    }
}

static void hide_tray_flyout(HWND hwnd) {
    if (!hwnd || !IsWindowVisible(hwnd)) return;
    KillTimer(hwnd, IDT_ANIM);
    KillTimer(hwnd, IDT_STATS);
    KillTimer(hwnd, IDT_SAVE);
    save_config_ini();
    ShowWindow(hwnd, SW_HIDE);
    g_FocusField = FIELD_NONE;
    g_SelStart = g_SelEnd = 0;
    g_PressedBtn = 0;
    EmptyWorkingSet(GetCurrentProcess());
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
}

static LRESULT CALLBACK FlyoutWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        return 0;
    case WM_TIMER:
        if (wParam == IDT_ANIM) {
            bool need_paint = false;
            float diff = g_SegTargetX - g_SegPillX;
            if (std::abs(diff) > 0.2f) {
                g_SegPillX += diff * 0.28f;
                need_paint = true;
            } else if (g_SegPillX != g_SegTargetX) {
                g_SegPillX = g_SegTargetX;
                need_paint = true;
            }
            TunnelState st = g_State.load();
            if (st == STATE_CONNECTED || st == STATE_CONNECTING) {
                need_paint = true;
            }
            if (g_FlushFeedbackTicks > 0) {
                need_paint = true;
                ULONGLONG now = GetTickCount64();
                if (now >= g_FlushFeedbackTicks) g_FlushFeedbackTicks = 0;
            }
            if (need_paint) {
                update_layered_flyout();
            }
        } else if (wParam == IDT_STATS) {
            update_flyout_stats();
        } else if (wParam == IDT_SAVE) {
            KillTimer(hwnd, IDT_SAVE);
            save_config_ini();
        }
        return 0;
    case WM_REPAINT_FLYOUT:
        update_layered_flyout();
        return 0;
    case WM_ACTIVATE:
        if (LOWORD(wParam) == WA_INACTIVE) {
            hide_tray_flyout(hwnd);
        }
        return 0;
    case WM_SETCURSOR: {
        float scale = get_dpi_scale();
        POINT pt; GetCursorPos(&pt); ScreenToClient(hwnd, &pt);
        int x = static_cast<int>(pt.x / scale), y = static_cast<int>(pt.y / scale);
        if (pt_in_rect(x, y, R_INP_VLESS_URI) ||
            (g_cfg.chain_type != CHAIN_NONE && (pt_in_rect(x, y, R_INP_CH_ADDR) || pt_in_rect(x, y, R_INP_CH_AUTH)))) {
            SetCursor(LoadCursor(nullptr, IDC_IBEAM));
            return TRUE;
        }
        if (g_HoverBtn > 0) {
            SetCursor(LoadCursor(nullptr, IDC_HAND));
            return TRUE;
        }
        SetCursor(LoadCursor(nullptr, IDC_ARROW));
        return TRUE;
    }
    case WM_DPICHANGED: {
        RECT* prc = reinterpret_cast<RECT*>(lParam);
        if (prc) {
            SetWindowPos(hwnd, nullptr, prc->left, prc->top, prc->right - prc->left, prc->bottom - prc->top,
                SWP_NOZORDER | SWP_NOACTIVATE);
        }
        g_CharW = 0.0f;
        load_status_icons(g_HInst);
        update_tray_icon();
        update_layered_flyout();
        return 0;
    }
    case WM_MOUSEMOVE: {
        float scale = get_dpi_scale();
        int x = static_cast<int>(GET_X_LPARAM(lParam) / scale);
        int y = static_cast<int>(GET_Y_LPARAM(lParam) / scale);

        if (g_IsDragging && g_FocusField != FIELD_NONE) {
            const RectF* rf = get_field_rect(g_FocusField);
            int len = get_field_len(g_FocusField);
            if (rf && g_CharW > 0.0f) {
                float text_x = rf->X + 10.0f;
                float rel_x = static_cast<float>(x) - text_x;
                int idx = g_ScrollOffset + static_cast<int>(std::round(rel_x / g_CharW));
                if (idx < 0) idx = 0;
                if (idx > len) idx = len;
                g_CaretPos = idx;
                g_SelEnd = idx;
                int vis_chars = static_cast<int>((rf->Width - 20.0f) / g_CharW);
                if (x < rf->X + 10.0f && g_ScrollOffset > 0) g_ScrollOffset--;
                else if (x > rf->X + rf->Width - 10.0f && g_ScrollOffset + vis_chars < len) g_ScrollOffset++;
                update_layered_flyout();
                return 0;
            }
        }

        bool can_connect = g_cfg.vless_valid || (g_cfg.chain_type != CHAIN_NONE && !g_cfg.chain_addr_str.empty());
        int old_h = g_HoverBtn;
        g_HoverBtn = 0;
        if (pt_in_rect(x, y, R_BTN_PING) && can_connect)             g_HoverBtn = 1;
        else if (pt_in_rect(x, y, R_BTN_CONNECT) && (can_connect || g_State.load() == STATE_CONNECTED || g_State.load() == STATE_CONNECTING)) g_HoverBtn = 2;
        else if (pt_in_rect(x, y, R_BTN_PASTE_URI))   g_HoverBtn = 3;
        else if (pt_in_rect(x, y, R_BTN_FLUSHDNS))    g_HoverBtn = 4;
        else if (pt_in_rect(x, y, R_BTN_EXIT))        g_HoverBtn = 6;
        else if (pt_in_rect(x, y, R_BTN_CLEAR_URI))   g_HoverBtn = 7;
        else if (pt_in_rect(x, y, R_BTN_PASTE_CH))    g_HoverBtn = 8;
        else if (pt_in_rect(x, y, R_BTN_THEME))       g_HoverBtn = 9;
        else if (pt_in_rect(x, y, R_BTN_CH_NONE))     g_HoverBtn = 10;
        else if (pt_in_rect(x, y, R_BTN_CH_SOCKS5))   g_HoverBtn = 11;
        else if (pt_in_rect(x, y, R_BTN_CH_HTTP))     g_HoverBtn = 12;
        else if (!g_cfg.vless_valid && pt_in_rect(x, y, R_EMPTY_URI)) g_HoverBtn = 13;

        if (old_h != g_HoverBtn) update_layered_flyout();
        return 0;
    }
    case WM_LBUTTONUP:
        if (g_PressedBtn != 0) {
            g_PressedBtn = 0;
            update_layered_flyout();
        }
        if (g_IsDragging) {
            g_IsDragging = false;
            ReleaseCapture();
            update_layered_flyout();
        }
        return 0;
    case WM_RBUTTONUP: {
        TunnelState st_rb = g_State.load();
        if (st_rb == STATE_CONNECTED || st_rb == STATE_CONNECTING) return 0;
        SetForegroundWindow(hwnd);
        SetActiveWindow(hwnd);
        SetFocus(hwnd);
        float scale = get_dpi_scale();
        int x = static_cast<int>(GET_X_LPARAM(lParam) / scale);
        int y = static_cast<int>(GET_Y_LPARAM(lParam) / scale);
        ActiveInputField clicked_f = FIELD_NONE;
        if (pt_in_rect(x, y, R_INP_VLESS_URI)) clicked_f = FIELD_VLESS_URI;
        else if (g_cfg.chain_type != CHAIN_NONE && pt_in_rect(x, y, R_INP_CH_ADDR)) clicked_f = FIELD_CHAIN_ADDR;
        else if (g_cfg.chain_type != CHAIN_NONE && pt_in_rect(x, y, R_INP_CH_AUTH)) clicked_f = FIELD_CHAIN_AUTH;

        if (clicked_f != FIELD_NONE) {
            g_FocusField = clicked_f;
            std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
            std::string* s = get_field_string(clicked_f);
            if (s) {
                std::wstring clip = read_clipboard_wtext(hwnd);
                if (!clip.empty()) {
                    delete_selection(s);
                    std::wstring w = to_wstr(*s);
                    int pos = std::min(g_CaretPos, static_cast<int>(w.size()));
                    w.insert(pos, clip);
                    g_CaretPos = pos + static_cast<int>(clip.size());
                    g_SelStart = g_CaretPos;
                    g_SelEnd = g_CaretPos;
                    *s = to_utf8(w);
                    if (clicked_f == FIELD_VLESS_URI) {
                        parse_vless_uri(*s);
                        set_status_msg(g_cfg.vless_valid ? (std::string(g_cfg.outbound_proto == PROTO_TROJAN ? "Loaded Trojan: " : "Loaded: ") + g_cfg.vless_ip + ":" + std::to_string(g_cfg.vless_port)) : "Invalid URI");
                    } else {
                        sync_chain_fields();
                    }
                    save_config_ini();
                }
            }
            update_layered_flyout();
            return 0;
        }
        return 0;
    }
    case WM_LBUTTONDOWN: {
        SetForegroundWindow(hwnd);
        SetActiveWindow(hwnd);
        SetFocus(hwnd);
        float scale = get_dpi_scale();
        int x = static_cast<int>(GET_X_LPARAM(lParam) / scale);
        int y = static_cast<int>(GET_Y_LPARAM(lParam) / scale);

        TunnelState cur_st = g_State.load();
        bool is_busy = (cur_st == STATE_CONNECTED || cur_st == STATE_CONNECTING);

        ActiveInputField clicked_f = FIELD_NONE;
        if (!is_busy) {
            if (pt_in_rect(x, y, R_INP_VLESS_URI)) clicked_f = FIELD_VLESS_URI;
            else if (g_cfg.chain_type != CHAIN_NONE && pt_in_rect(x, y, R_INP_CH_ADDR)) clicked_f = FIELD_CHAIN_ADDR;
            else if (g_cfg.chain_type != CHAIN_NONE && pt_in_rect(x, y, R_INP_CH_AUTH)) clicked_f = FIELD_CHAIN_AUTH;
        }

        if (clicked_f != FIELD_NONE) {
            const RectF* rf = get_field_rect(clicked_f);
            int len = get_field_len(clicked_f);
            int idx = 0;
            if (rf && g_CharW > 0.0f) {
                float text_x = rf->X + 10.0f;
                float rel_x = static_cast<float>(x) - text_x;
                idx = g_ScrollOffset + static_cast<int>(std::round(rel_x / g_CharW));
                if (idx < 0) idx = 0;
                if (idx > len) idx = len;
            }
            bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
            if (g_FocusField == clicked_f && shift) {
                g_SelEnd = idx;
                g_CaretPos = idx;
            } else {
                if (g_FocusField != clicked_f) {
                    parse_vless_uri(g_cfg.raw_vless_uri);
                    sync_chain_fields();
                    save_config_ini();
                    g_FocusField = clicked_f;
                    g_ScrollOffset = 0;
                }
                g_CaretPos = idx;
                g_SelStart = idx;
                g_SelEnd = idx;
            }
            g_IsDragging = true;
            SetCapture(hwnd);
            update_layered_flyout();
            return 0;
        }

        if (g_FocusField != FIELD_NONE) {
            g_FocusField = FIELD_NONE;
            g_SelStart = g_SelEnd = 0;
            std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
            parse_vless_uri(g_cfg.raw_vless_uri);
            sync_chain_fields();
            save_config_ini();
        }

        if (pt_in_rect(x, y, R_BTN_THEME)) {
            g_PressedBtn = 9;
            {
                std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
                g_cfg.is_dark_mode = !g_cfg.is_dark_mode;
            }
            save_config_ini();
        } else if (pt_in_rect(x, y, R_BTN_PING)) {
            bool can_connect = false;
            {
                std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
                can_connect = g_cfg.vless_valid || (g_cfg.chain_type != CHAIN_NONE && !g_cfg.chain_addr_str.empty());
            }
            if (can_connect) {
                g_PressedBtn = 1;
                g_LastPingMs = PING_TESTING;
                trigger_async_ping();
            }
        } else if (pt_in_rect(x, y, R_BTN_CONNECT)) {
            if (cur_st == STATE_CONNECTED || cur_st == STATE_CONNECTING) {
                g_PressedBtn = 2;
                stop_tunnel();
            } else {
                bool can_connect = false;
                {
                    std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
                    can_connect = g_cfg.vless_valid || (g_cfg.chain_type != CHAIN_NONE && !g_cfg.chain_addr_str.empty());
                    if (can_connect && g_cfg.chain_type != CHAIN_NONE && g_cfg.chain_addr_str.empty()) {
                        g_cfg.chain_type = CHAIN_NONE;
                        g_SegTargetX = 27.0f;
                    }
                }
                if (can_connect) {
                    g_PressedBtn = 2;
                    save_config_ini();
                    start_tunnel_async();
                }
            }
        } else if (pt_in_rect(x, y, R_BTN_CLEAR_URI)) {
            if (is_busy) return 0;
            g_PressedBtn = 7;
            {
                std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
                g_cfg.raw_vless_uri.clear(); g_cfg.vless_valid = false;
            }
            g_CaretPos = g_SelStart = g_SelEnd = g_ScrollOffset = 0;
            if (g_State.load() == STATE_FAILED) g_State = STATE_DISCONNECTED;
            save_config_ini(); set_status_msg("Server URI cleared");
            update_tray_icon();
        } else if (pt_in_rect(x, y, R_BTN_PASTE_URI) || (!g_cfg.vless_valid && pt_in_rect(x, y, R_EMPTY_URI))) {
            if (is_busy) return 0;
            g_PressedBtn = 3;
            std::string clip = read_clipboard_text(hwnd);
            if (parse_vless_uri(clip)) {
                std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
                g_CaretPos = g_SelStart = g_SelEnd = static_cast<int>(to_wstr(g_cfg.raw_vless_uri).size());
                g_ScrollOffset = 0; save_config_ini();
                set_status_msg(std::string(g_cfg.outbound_proto == PROTO_TROJAN ? "Loaded Trojan: " : "Loaded node: ") + g_cfg.vless_ip + ":" + std::to_string(g_cfg.vless_port));
            } else {
                set_status_msg("Clipboard does not contain a valid vless:// or trojan:// URI");
            }
        } else if (pt_in_rect(x, y, R_BTN_CH_NONE)) {
            if (is_busy) return 0;
            g_PressedBtn = 10;
            {
                std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
                g_cfg.chain_type = CHAIN_NONE;
            }
            g_SegTargetX = 27.0f;
            save_config_ini();
        } else if (pt_in_rect(x, y, R_BTN_CH_SOCKS5)) {
            if (is_busy) return 0;
            g_PressedBtn = 11;
            {
                std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
                g_cfg.chain_type = CHAIN_SOCKS5;
            }
            g_SegTargetX = 143.0f;
            save_config_ini();
        } else if (pt_in_rect(x, y, R_BTN_CH_HTTP)) {
            if (is_busy) return 0;
            g_PressedBtn = 12;
            {
                std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
                g_cfg.chain_type = CHAIN_HTTP;
            }
            g_SegTargetX = 259.0f;
            save_config_ini();
        } else if (pt_in_rect(x, y, R_BTN_PASTE_CH)) {
            if (is_busy) return 0;
            g_PressedBtn = 8;
            std::string clip = read_clipboard_text(hwnd);
            if (!clip.empty()) {
                {
                    std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
                    if (clip.rfind("socks5://", 0) == 0) { g_cfg.chain_type = CHAIN_SOCKS5; g_SegTargetX = 143.0f; clip = clip.substr(9); }
                    else if (clip.rfind("http://", 0) == 0) { g_cfg.chain_type = CHAIN_HTTP; g_SegTargetX = 259.0f; clip = clip.substr(7); }
                    size_t at = clip.find('@');
                    if (at != std::string::npos) { g_cfg.chain_auth_str = clip.substr(0, at); g_cfg.chain_addr_str = clip.substr(at + 1); }
                    else g_cfg.chain_addr_str = clip;
                    sync_chain_fields();
                }
                save_config_ini(); set_status_msg("Updated upstream proxy from clipboard");
            }
        } else if (pt_in_rect(x, y, R_BTN_FLUSHDNS)) {
            g_PressedBtn = 4;
            g_FlushFeedbackTicks = GetTickCount64() + 1500;
            run_silent_cmd("ipconfig /flushdns");
            HMODULE hDns = LoadLibraryA("dnsapi.dll");
            if (hDns) {
                typedef BOOL(WINAPI* pDnsFlush)();
                pDnsFlush DnsFlushResolverCache = (pDnsFlush)GetProcAddress(hDns, "DnsFlushResolverCache");
                if (DnsFlushResolverCache) DnsFlushResolverCache();
                FreeLibrary(hDns);
            }
            set_status_msg("Windows DNS cache flushed successfully");
        } else if (pt_in_rect(x, y, R_BTN_EXIT)) {
            g_PressedBtn = 6;
            stop_tunnel();
            Shell_NotifyIconW(NIM_DELETE, &g_Nid);
            PostQuitMessage(0);
            return 0;
        }

        update_layered_flyout();
        return 0;
    }
    case WM_KEYDOWN: {
        TunnelState st = g_State.load();
        if (st == STATE_CONNECTED || st == STATE_CONNECTING) return 0;
        if (g_FocusField == FIELD_NONE) return 0;
        std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
        std::string* target = get_field_string(g_FocusField);
        if (!target) return 0;
        bool ctrl = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
        if (ctrl && (wParam == 'V' || wParam == 'v')) {
            std::wstring clip = read_clipboard_wtext(hwnd);
            if (!clip.empty()) {
                delete_selection(target);
                std::wstring w = to_wstr(*target);
                int pos = std::min(g_CaretPos, static_cast<int>(w.size()));
                w.insert(pos, clip);
                g_CaretPos = pos + static_cast<int>(clip.size());
                g_SelStart = g_CaretPos;
                g_SelEnd = g_CaretPos;
                *target = to_utf8(w);
                if (g_FocusField == FIELD_VLESS_URI) parse_vless_uri(*target); else sync_chain_fields();
                save_config_ini();
                update_layered_flyout();
                return 0;
            }
        }
        if (ctrl && (wParam == 'C' || wParam == 'c')) {
            if (g_SelStart != g_SelEnd) {
                std::wstring w = to_wstr(*target);
                int s_min = std::max(0, std::min(g_SelStart, g_SelEnd));
                int s_max = std::min(static_cast<int>(w.size()), std::max(g_SelStart, g_SelEnd));
                if (s_min < s_max) {
                    std::wstring sub = w.substr(s_min, s_max - s_min);
                    if (OpenClipboard(hwnd)) {
                        EmptyClipboard();
                        size_t bsz = (sub.size() + 1) * sizeof(wchar_t);
                        HGLOBAL hGl = GlobalAlloc(GMEM_MOVEABLE, bsz);
                        if (hGl) {
                            memcpy(GlobalLock(hGl), sub.c_str(), bsz);
                            GlobalUnlock(hGl);
                            SetClipboardData(CF_UNICODETEXT, hGl);
                        }
                        CloseClipboard();
                    }
                }
            }
            return 0;
        }
        if (ctrl && (wParam == 'X' || wParam == 'x')) {
            if (g_SelStart != g_SelEnd) {
                std::wstring w = to_wstr(*target);
                int s_min = std::max(0, std::min(g_SelStart, g_SelEnd));
                int s_max = std::min(static_cast<int>(w.size()), std::max(g_SelStart, g_SelEnd));
                if (s_min < s_max) {
                    std::wstring sub = w.substr(s_min, s_max - s_min);
                    if (OpenClipboard(hwnd)) {
                        EmptyClipboard();
                        size_t bsz = (sub.size() + 1) * sizeof(wchar_t);
                        HGLOBAL hGl = GlobalAlloc(GMEM_MOVEABLE, bsz);
                        if (hGl) {
                            memcpy(GlobalLock(hGl), sub.c_str(), bsz);
                            GlobalUnlock(hGl);
                            SetClipboardData(CF_UNICODETEXT, hGl);
                        }
                        CloseClipboard();
                    }
                    delete_selection(target);
                    if (g_FocusField == FIELD_VLESS_URI) parse_vless_uri(*target); else sync_chain_fields();
                    KillTimer(hwnd, IDT_SAVE);
                    save_config_ini();
                    update_layered_flyout();
                }
            }
            return 0;
        }
        if (ctrl && (wParam == 'A' || wParam == 'a')) {
            g_SelStart = 0;
            g_SelEnd = get_field_len(g_FocusField);
            g_CaretPos = g_SelEnd;
            update_layered_flyout();
            return 0;
        }
        if (wParam == VK_LEFT) {
            bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
            if (shift) {
                if (g_CaretPos > 0) g_CaretPos--;
                g_SelEnd = g_CaretPos;
            } else {
                if (g_SelStart != g_SelEnd) {
                    g_CaretPos = std::min(g_SelStart, g_SelEnd);
                } else if (g_CaretPos > 0) {
                    g_CaretPos--;
                }
                g_SelStart = g_CaretPos;
                g_SelEnd = g_CaretPos;
            }
            update_layered_flyout();
            return 0;
        }
        if (wParam == VK_RIGHT) {
            int len = get_field_len(g_FocusField);
            bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
            if (shift) {
                if (g_CaretPos < len) g_CaretPos++;
                g_SelEnd = g_CaretPos;
            } else {
                if (g_SelStart != g_SelEnd) {
                    g_CaretPos = std::max(g_SelStart, g_SelEnd);
                } else if (g_CaretPos < len) {
                    g_CaretPos++;
                }
                g_SelStart = g_CaretPos;
                g_SelEnd = g_CaretPos;
            }
            update_layered_flyout();
            return 0;
        }
        if (wParam == VK_HOME) {
            bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
            g_CaretPos = 0;
            if (shift) g_SelEnd = 0;
            else { g_SelStart = 0; g_SelEnd = 0; }
            update_layered_flyout();
            return 0;
        }
        if (wParam == VK_END) {
            int len = get_field_len(g_FocusField);
            bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
            g_CaretPos = len;
            if (shift) g_SelEnd = g_CaretPos;
            else { g_SelStart = g_CaretPos; g_SelEnd = g_CaretPos; }
            update_layered_flyout();
            return 0;
        }
        if (wParam == VK_DELETE) {
            if (!delete_selection(target)) {
                std::wstring w = to_wstr(*target);
                if (g_CaretPos >= 0 && g_CaretPos < static_cast<int>(w.size())) {
                    w.erase(g_CaretPos, 1);
                    *target = to_utf8(w);
                }
            }
            if (g_FocusField == FIELD_VLESS_URI) parse_vless_uri(*target); else sync_chain_fields();
            SetTimer(hwnd, IDT_SAVE, 400, nullptr);
            update_layered_flyout();
            return 0;
        }
        if (wParam == VK_RETURN || wParam == VK_ESCAPE) {
            g_FocusField = FIELD_NONE;
            g_SelStart = g_SelEnd = 0;
            parse_vless_uri(g_cfg.raw_vless_uri);
            sync_chain_fields();
            KillTimer(hwnd, IDT_SAVE);
            save_config_ini();
            update_layered_flyout();
            return 0;
        }
        return 0;
    }
    case WM_CHAR: {
        TunnelState st = g_State.load();
        if (st == STATE_CONNECTED || st == STATE_CONNECTING) return 0;
        if (g_FocusField == FIELD_NONE) return 0;
        std::lock_guard<std::recursive_mutex> lk(g_cfg_mtx);
        std::string* target = get_field_string(g_FocusField);
        if (!target) return 0;
        if (wParam == VK_BACK) {
            if (!delete_selection(target)) {
                std::wstring w = to_wstr(*target);
                if (g_CaretPos > 0 && g_CaretPos <= static_cast<int>(w.size())) {
                    w.erase(g_CaretPos - 1, 1);
                    g_CaretPos--;
                    g_SelStart = g_CaretPos;
                    g_SelEnd = g_CaretPos;
                    *target = to_utf8(w);
                }
            }
        } else if (wParam == 22 || wParam == 1 || wParam == 3 || wParam == 24) {
            return 0;
        } else if (wParam == VK_RETURN || wParam == VK_ESCAPE) {
            g_FocusField = FIELD_NONE;
            g_SelStart = g_SelEnd = 0;
            KillTimer(hwnd, IDT_SAVE);
            save_config_ini();
        } else if (wParam >= 32) {
            delete_selection(target);
            std::wstring w = to_wstr(*target);
            int pos = std::min(g_CaretPos, static_cast<int>(w.size()));
            wchar_t ch = static_cast<wchar_t>(wParam);
            w.insert(pos, 1, ch);
            g_CaretPos = pos + 1;
            g_SelStart = g_CaretPos;
            g_SelEnd = g_CaretPos;
            *target = to_utf8(w);
        }
        if (g_FocusField == FIELD_VLESS_URI) parse_vless_uri(*target); else sync_chain_fields();
        SetTimer(hwnd, IDT_SAVE, 400, nullptr);
        update_layered_flyout();
        return 0;
    }
    case WM_TRAYICON:
        if (lParam == WM_LBUTTONUP || lParam == WM_RBUTTONUP) {
            if (IsWindowVisible(hwnd)) hide_tray_flyout(hwnd); else show_tray_flyout();
        }
        return 0;
    case WM_DESTROY:
        stop_tunnel(); Shell_NotifyIconW(NIM_DELETE, &g_Nid); PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool init_tray_flyout(HINSTANCE hInst) {
    g_HInst = hInst;
    init_custom_fonts(hInst);
    WNDCLASSEXW wc{}; wc.cbSize = sizeof(wc); wc.style = CS_DBLCLKS; wc.lpfnWndProc = FlyoutWndProc;
    wc.hInstance = hInst; wc.hCursor = LoadCursor(nullptr, IDC_ARROW); wc.lpszClassName = L"NanoRayFlyoutClass";
    wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(1));
    wc.hIconSm = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(1), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
    RegisterClassExW(&wc);
    g_Hwnd = CreateWindowExW(WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
        wc.lpszClassName, L"NanoRay", WS_POPUP, 0, 0, WIN_W, WIN_H, nullptr, nullptr, hInst, nullptr);
    if (!g_Hwnd) return false;
    g_LogoBmp = load_logo_bitmap(hInst);
    load_status_icons(hInst);
    g_Nid.cbSize = sizeof(g_Nid); g_Nid.hWnd = g_Hwnd; g_Nid.uID = 1;
    g_Nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; g_Nid.uCallbackMessage = WM_TRAYICON; g_Nid.hIcon = g_IconIdle;
    wcscpy_s(g_Nid.szTip, L"NanoRay - Disconnected");
    Shell_NotifyIconW(NIM_ADD, &g_Nid);
    return true;
}

void cleanup_tray_flyout() {
    if (g_IconIdle) { DestroyIcon(g_IconIdle); g_IconIdle = nullptr; }
    if (g_IconPending) { DestroyIcon(g_IconPending); g_IconPending = nullptr; }
    if (g_IconConn) { DestroyIcon(g_IconConn); g_IconConn = nullptr; }
    if (g_LogoBmp) { delete g_LogoBmp; g_LogoBmp = nullptr; }
    cleanup_custom_fonts();
}