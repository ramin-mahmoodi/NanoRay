@echo off
windres resources\resource.rc -O coff -o resource.o
if %errorlevel% neq 0 (
    g++ -O3 -s -std=c++17 -D_WIN32_WINNT=0x0A00 -Isrc src\main.cpp src\config.cpp src\tunnel.cpp src\ui_flyout.cpp -o NanoRay.exe -lws2_32 -liphlpapi -lgdiplus -ldwmapi -lshell32 -lpsapi -lole32 -lgdi32 -luser32 -lwinhttp -lsecur32 -lcrypt32 -lbcrypt -mwindows
    goto :done
)
g++ -O3 -s -std=c++17 -D_WIN32_WINNT=0x0A00 -Isrc src\main.cpp src\config.cpp src\tunnel.cpp src\ui_flyout.cpp resource.o -o NanoRay.exe -lws2_32 -liphlpapi -lgdiplus -ldwmapi -lshell32 -lpsapi -lole32 -lgdi32 -luser32 -lwinhttp -lsecur32 -lcrypt32 -lbcrypt -mwindows
del /q resource.o 2>nul
:done
echo Done. Place wintun.dll (x64) next to NanoRay.exe.
pause