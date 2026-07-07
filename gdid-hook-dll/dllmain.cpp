#include <windows.h>
#include "hook.h"

// Mutex for thread-safe hook management
static CRITICAL_SECTION hookCs;
static bool csInitialized = false;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&hookCs);
        csInitialized = true;
        EnterCriticalSection(&hookCs);
        if (!InstallHooks()) {
            OutputDebugStringW(L"gdid-hook: InstallHooks() failed");
        } else {
            OutputDebugStringW(L"gdid-hook: hooks installed successfully");
        }
        LeaveCriticalSection(&hookCs);
        break;

    case DLL_PROCESS_DETACH:
        EnterCriticalSection(&hookCs);
        RemoveHooks();
        LeaveCriticalSection(&hookCs);
        if (csInitialized) {
            DeleteCriticalSection(&hookCs);
            csInitialized = false;
        }
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void SetGDIDLogging(BOOL enable) {
    EnableLogging(enable);
}

extern "C" __declspec(dllexport) BOOL ToggleHooks(BOOL install) {
    EnterCriticalSection(&hookCs);
    BOOL result;
    if (install) {
        result = InstallHooks();
    } else {
        RemoveHooks();
        result = TRUE;
    }
    LeaveCriticalSection(&hookCs);
    return result;
}