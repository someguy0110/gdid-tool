#pragma once
#include <windows.h>
#include <string>

// Install/remove the RegQueryValueExW hook
BOOL InstallHooks();
void RemoveHooks();

// Toggle debug logging to OutputDebugString
void EnableLogging(BOOL enable);

// Generate a fake GDID (16 hex chars with 0018 prefix)
std::wstring GenerateFakeGDID();

// Hooked version of RegQueryValueExW
LSTATUS WINAPI HookRegQueryValueExW(
    HKEY hKey,
    LPCWSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
);