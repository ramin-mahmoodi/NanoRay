@echo off
rc /nologo resources\resource.rc
cl /nologo /O2 /EHsc /std:c++17 /D_WIN32_WINNT=0x0A00 /Isrc src\main.cpp src\config.cpp src\tunnel.cpp src\ui_flyout.cpp resources\resource.res /Fe:NanoRay.exe /link /SUBSYSTEM:WINDOWS /MANIFEST:NO ws2_32.lib iphlpapi.lib gdiplus.lib dwmapi.lib shell32.lib psapi.lib ole32.lib gdi32.lib user32.lib winhttp.lib secur32.lib crypt32.lib bcrypt.lib
del /q *.obj resources\resource.res 2>nul
echo Done. Place wintun.dll (x64) next to NanoRay.exe.
pause