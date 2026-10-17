# NanoRay

Ultra-lightweight, native system-wide VLESS and Trojan tunnel client for Windows 10 and Windows 11, written in pure C++17.

NanoRay operates directly at Layer 3 using the official signed Wintun driver and the native Windows IP Helper API. It contains no runtime dependencies, no Electron, no Qt, no .NET, and no external interpreters. The entire application compiles into a single standalone executable of approximately 1.4 MB with a typical operating memory footprint between 2 MB and 4.5 MB.

---

## Architectural Highlights

- **Pure C++17 Implementation**: Built from scratch using native Windows APIs (Win32, GDI+, Schannel, Winsock2, and IP Helper). Zero external third-party frameworks.
- **Minimal Resource Consumption**: Working set memory typically stays between 2.5 MB and 4.5 MB RAM during active traffic relay. Memory is automatically trimmed via `EmptyWorkingSet` when the UI flyout closes.
- **Layer-3 Kernel Virtual Adapter**: Utilizes the high-performance WireGuard Wintun driver (`wintun.dll`) paired with an in-process, zero-copy packet processing and NAT translation pipeline (`10.66.66.1` <-> `10.66.66.2`).
- **Instantaneous Native Routing**: Injects and removes system routing entries directly through the Windows IP Helper API (`CreateIpForwardEntry2` / `DeleteIpForwardEntry2`) in under 1 millisecond. No batch scripts, no command shell invocation.
- **Routing Loop Immunity**: Dynamically identifies the default physical gateway and binds outbound transport sockets directly to the underlying physical network adapter via `IP_UNICAST_IF`.
- **Integrated DNS Hijacking**: Intercepts UDP port 53 traffic on the virtual interface and securely resolves domain names over the tunnel via TCP (`1.1.1.1:53`). Includes an in-memory LRU cache offering ~0.05ms resolution for frequent queries.
- **IPv6 Leak Blackholing**: Native IPv6 routing entries (`::/1` and `8000::/1`) direct all IPv6 packets into the virtual interface where they are safely dropped, forcing applications to fall back to IPv4 over the secure tunnel.
- **Clean Antivirus Profile**: Spawns zero background `cmd.exe` processes and makes zero modifications to Windows Defender Firewall. All cache flushes and routing operations use native Win32 APIs.
- **Modern Hardware-Accelerated UI**: Custom Windows system tray flyout built with layered window rendering (`WS_EX_LAYERED`, 32-bit per-pixel alpha channel) and GDI+, delivering identical rendering across both Windows 10 and Windows 11.

---

## Protocol and Transport Specifications

### Protocols
- **VLESS**: Native client implementation supporting standard stream and Vision flow (`xtls-rprx-vision`).
- **Trojan**: Native client implementation with SHA-224 password digest hashing.

### Transports
- **Direct TCP**: Raw stream communication.
- **WebSocket**: RFC 6455 compliant WebSocket framing with custom handshake headers, path routing, and host header spoofing.
- **HTTPUpgrade**: HTTP/1.1 Upgrade protocol tunneling.
- **XHTTP**: Chunked HTTP transport with session multiplexing.

### Cryptography and Security Layers
- **TLS**: Windows native Schannel SSL/TLS engine supporting TLS 1.2 and TLS 1.3.
- **REALITY**: Embedded custom handshake engine implementing x25519 elliptic-curve Diffie-Hellman key exchange, ChaCha20-Poly1305 encryption, and HKDF key derivation.
- **uTLS ClientHello Emulation**: Bit-exact ClientHello signature matching for popular browsers (Chrome 120+, Firefox, Safari).

### Proxy Chaining
- Supports routing outbound tunnel connections through an upstream proxy before reaching the destination server:
  - **SOCKS5** (with optional username/password authentication)
  - **HTTP CONNECT** (with optional Basic authentication)

---

## System Requirements

- **Operating System**: Windows 10 (version 1809 or later, 64-bit) or Windows 11 (64-bit).
- **Permissions**: Administrator privileges (required by Windows to create the virtual network interface and modify IP routing tables).
- **Driver**: 64-bit `wintun.dll` located in the same directory as `NanoRay.exe`.

---

## Quick Start

### Installation

1. Download the latest release package (`NanoRay-windows-x64.zip`) from the Releases page.
2. Extract the archive contents (`NanoRay.exe` and `wintun.dll`) into a single folder.
3. Right-click `NanoRay.exe` and select **Run as administrator**.

### Connecting to a Server

1. Click the NanoRay icon in the Windows taskbar notification area (system tray).
2. Paste your `vless://` or `trojan://` URI into the configuration input field.
3. Click the **Connect** button.
4. The tray icon and status message will indicate the active connection status and current ping latency.

### Example Supported URIs

VLESS with REALITY:
```text
vless://uuid@domain.com:443?security=reality&sni=target.com&pbk=public_key&sid=short_id&fp=chrome&type=tcp&flow=xtls-rprx-vision#MyVLESS
```

Trojan with TLS:
```text
trojan://password@domain.com:443?security=tls&sni=domain.com#MyTrojan
```

VLESS over WebSocket:
```text
vless://uuid@domain.com:443?security=tls&sni=domain.com&type=ws&path=%2Fwebsocket#MyWS
```

---

## Building from Source

### Prerequisites

- A 64-bit Windows environment.
- Either:
  - **MinGW-w64** (GCC 10.0 or higher with Win32 threads), OR
  - **Microsoft Visual Studio 2019+** (MSVC x64 command tools), OR
  - **CMake 3.16+**.

### Option A: Build with MinGW-w64

Run the provided batch file:
```cmd
build_mingw.bat
```

Or run the compiler directly:
```cmd
windres resources\resource.rc -O coff -o resource.o
g++ -O3 -s -std=c++17 -D_WIN32_WINNT=0x0A00 -DNOMINMAX -Isrc src\main.cpp src\config.cpp src\tunnel.cpp src\ui_flyout.cpp resource.o -o NanoRay.exe -static -static-libgcc -static-libstdc++ -lws2_32 -liphlpapi -lgdiplus -ldwmapi -lshell32 -lpsapi -lole32 -lgdi32 -luser32 -lwinhttp -lsecur32 -lcrypt32 -lbcrypt -mwindows
del resource.o
```

### Option B: Build with Visual Studio (MSVC)

Open the **x64 Native Tools Command Prompt for VS** and run:
```cmd
build_msvc.bat
```

Or run `cl.exe`:
```cmd
rc /nologo resources\resource.rc
cl /nologo /O2 /EHsc /std:c++17 /D_WIN32_WINNT=0x0A00 /Isrc src\main.cpp src\config.cpp src\tunnel.cpp src\ui_flyout.cpp resources\resource.res /Fe:NanoRay.exe /link /SUBSYSTEM:WINDOWS /MANIFEST:NO ws2_32.lib iphlpapi.lib gdiplus.lib dwmapi.lib shell32.lib psapi.lib ole32.lib gdi32.lib user32.lib winhttp.lib secur32.lib crypt32.lib bcrypt.lib
del *.obj resources\resource.res
```

### Option C: Build with CMake

```cmd
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

After building, ensure the 64-bit `wintun.dll` driver file is placed in the output directory adjacent to `NanoRay.exe`.

---

## Configuration Reference (`nanoray.ini`)

NanoRay stores its persistent settings in a standard Windows INI file named `nanoray.ini` next to the executable.

```ini
[VLESS]
URI=vless://...

[CHAIN]
Type=0
Addr=
Auth=

[UI]
DarkMode=1
```

### Configuration Parameters

| Section | Key | Type | Description |
|---|---|---|---|
| `[VLESS]` | `URI` | string | Raw VLESS or Trojan connection URI. |
| `[CHAIN]` | `Type` | integer | Upstream proxy mode: `0` (Direct), `1` (SOCKS5), `2` (HTTP). |
| `[CHAIN]` | `Addr` | string | Upstream proxy host and port formatted as `host:port`. |
| `[CHAIN]` | `Auth` | string | Optional upstream authentication formatted as `user:password`. |
| `[UI]` | `DarkMode` | integer | Theme mode: `1` for Dark Mode, `0` for Light Mode. |

---

## Security and Privacy Design

1. **Zero External Logging**: NanoRay does not transmit telemetry, analytics, or hardware identifiers.
2. **Local Loopback NAT**: Network address translation occurs entirely in memory within the local process space. Traffic between the virtual TUN adapter and the local relay is never exposed to external local area networks.
3. **No Shell Invocations**: All routing, network configuration, and cache operations interface directly with standard Windows system libraries (`iphlpapi.dll`, `dnsapi.dll`). NanoRay does not execute commands via `cmd.exe` or PowerShell.
4. **Clean Route Restoration**: On tunnel disconnection or unexpected exit, routing tables and DNS configurations are restored to their original physical network state.

---

## License

This project is licensed under the terms of the GNU General Public License v3.0 (GPLv3). See the [LICENSE](LICENSE) file for complete details.

Wintun is a registered trademark of Jason A. Donenfeld. Wintun is distributed under the terms of the MIT license.