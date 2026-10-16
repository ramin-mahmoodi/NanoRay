# NanoRay (System Tunnel)

Ultra-lightweight system-wide VLESS & Trojan tunnel client for Windows 10 and Windows 11 in pure C++ (Win32 + GDI+ + Wintun).

## Features
- **RAM Footprint:** ~2.5 MB - 4.5 MB working set.
- **Protocols:** Native VLESS and Trojan over TCP, TLS, REALITY, WebSocket, HTTPUpgrade, and XHTTP.
- **uTLS Fingerprinting:** Bit-exact browser TLS ClientHello camouflage (Chrome 120+, Firefox, Safari).
- **Identical Windows 10 & Windows 11 UI:** Modern minimal tray flyout rendered via `WS_EX_LAYERED` + `UpdateLayeredWindow` (32-bit per-pixel alpha).
- **System-Wide Layer-3 Tunnel:** Uses `wintun.dll` + zero-copy Layer-3/Layer-4 Kernel NAT (`10.66.66.1` <-> `10.66.66.2`).
- **Instant Connect & Routing:** Native Win32 IP Helper API (`iphlpapi.dll`) route insertion with zero batch script overhead.
- **In-Memory DNS Cache:** 0.05ms DNS response time with 3-minute TTL.
- **Loop Prevention:** Outbound sockets bind directly to the physical NIC via `IP_UNICAST_IF`.
- **DNS Hijacking:** Intercepts port 53 UDP traffic and tunnels it over TCP (`1.1.1.1:53`).
- **Upstream Proxy Chain:** Supports `SOCKS5` and `HTTP CONNECT` (with optional authentication).

## Build
Run `build_mingw.bat` (MinGW-w64) or `build_msvc.bat` (Visual Studio x64 Native Tools), or use `CMakeLists.txt`.
Place 64-bit `wintun.dll` next to `NanoRay.exe` and run as Administrator.