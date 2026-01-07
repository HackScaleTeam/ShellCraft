#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>
#include <string>
#include <sstream>

struct RunMeArgs {
    const wchar_t* arg1;
    const wchar_t* arg2;
};

// Silent error function - no console output
void PrintError(const std::wstring msg)
{
    // Use OutputDebugString for debugging only
    // OutputDebugStringW(msg.c_str());
}

DWORD_PTR GetRemoteModuleBaseAddress(DWORD pid, const std::wstring moduleName)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        PrintError(L"CreateToolhelp32Snapshot failed");
        return 0;
    }

    MODULEENTRY32W me32 = { sizeof(MODULEENTRY32W) };
    if (!Module32FirstW(snapshot, &me32))
    {
        PrintError(L"Module32FirstW failed");
        CloseHandle(snapshot);
        return 0;
    }
    do
    {
        if (_wcsicmp(me32.szModule, moduleName.c_str()) == 0)
        {
            CloseHandle(snapshot);
            return reinterpret_cast<DWORD_PTR>(me32.modBaseAddr);
        }
    } while (Module32NextW(snapshot, &me32));
    PrintError(L"Module not found");
    CloseHandle(snapshot);
    return 0;
}

bool InjectDLL(HANDLE hProcess, const std::wstring dllPath)
{
    SIZE_T size = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMem)
    {
        PrintError(L"VirtualAllocEx failed");
        return false;
    }
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), size, nullptr)) {
        PrintError(L"WriteProcessMemory failed");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32)
    {
        PrintError(L"GetModuleHandleW(kernel32.dll) failed");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    LPVOID loadLibAddr = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!loadLibAddr)
    {
        PrintError(L"GetProcAddress(LoadLibraryW) failed");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)loadLibAddr, remoteMem, 0, nullptr);

    if (!hThread)
    {
        PrintError(L"CreateRemoteThread failed");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    return true;
}

DWORD CallRemoteRunMe(HANDLE hProcess, DWORD_PTR runMeAddr, const std::wstring arg1, const std::wstring arg2)
{
    SIZE_T size1 = (arg1.length() + 1) * sizeof(wchar_t);
    SIZE_T size2 = (arg2.length() + 1) * sizeof(wchar_t);
    LPVOID remoteArg1 = VirtualAllocEx(hProcess, nullptr, size1, MEM_COMMIT, PAGE_READWRITE);
    LPVOID remoteArg2 = VirtualAllocEx(hProcess, nullptr, size2, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteArg1 || !remoteArg2)
    {
        PrintError(L"VirtualAllocEx for arguments failed");
        return -1;
    }
    if (!WriteProcessMemory(hProcess, remoteArg1, arg1.c_str(), size1, nullptr) ||
        !WriteProcessMemory(hProcess, remoteArg2, arg2.c_str(), size2, nullptr))
    {
        PrintError(L"WriteProcessMemory for arguments failed");
        VirtualFreeEx(hProcess, remoteArg1, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteArg2, 0, MEM_RELEASE);
        return -1;
    }
    RunMeArgs args = { (wchar_t*)remoteArg1, (wchar_t*)remoteArg2 };
    LPVOID remoteArgs = VirtualAllocEx(hProcess, nullptr, sizeof(RunMeArgs), MEM_COMMIT, PAGE_READWRITE);
    if (!remoteArgs)
    {
        PrintError(L"VirtualAllocEx for RunMeArgs failed");
        VirtualFreeEx(hProcess, remoteArg1, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteArg2, 0, MEM_RELEASE);
        return -1;
    }
    WriteProcessMemory(hProcess, remoteArgs, &args, sizeof(RunMeArgs), nullptr);

    // Create remote thread to call RunMe(RunMeArgs)
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)runMeAddr, remoteArgs, 0, nullptr);
    if (!hThread)
    {
        PrintError(L"CreateRemoteThread for RunMe failed");
        VirtualFreeEx(hProcess, remoteArg1, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteArg2, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteArgs, 0, MEM_RELEASE);
        return -1;
    }
    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = -1;
    if (!GetExitCodeThread(hThread, &exitCode))
    {
        PrintError(L"GetExitCodeThread failed");
    }
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteArg1, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, remoteArg2, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, remoteArgs, 0, MEM_RELEASE);

    return exitCode;
}

// Windows entry point without console
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Get command line arguments
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    
    if (!argv || argc < 4)
    {
        if (argv) LocalFree(argv);
        return 1;
    }
    
    // Parse arguments (same as original)
    std::wstring exePath = argv[1];
    std::wstring dllPath = argv[2];
    std::wstring pathToWrite = argv[3];
    
    BOOL copyFile = FALSE;
    if (argc == 5 && wcscmp(argv[4], L"c") == 0)
    {
        copyFile = TRUE;
    }
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    
    // Create suspended process
    if (!CreateProcessW(exePath.c_str(), nullptr, nullptr, nullptr, FALSE,
        CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
    {
        LocalFree(argv);
        return 2;
    }
    HANDLE hProcess = pi.hProcess;
    DWORD pid = pi.dwProcessId;
    
    // Inject DLL
    if (!InjectDLL(hProcess, dllPath))
    {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
        LocalFree(argv);
        return 3;
    }
    
    std::wstring dllName = dllPath.substr(dllPath.find_last_of(L"\\/") + 1);
    DWORD_PTR baseAddr = GetRemoteModuleBaseAddress(pid, dllName);
    if (!baseAddr)
    {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
        LocalFree(argv);
        return 4;
    }
    
    HMODULE hLocalDLL = LoadLibraryW(dllPath.c_str());
    if (!hLocalDLL)
    {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
        LocalFree(argv);
        return 5;
    }
    
    DWORD_PTR localRunMe = (DWORD_PTR)GetProcAddress(hLocalDLL, "RunMe");
    if (!localRunMe)
    {
        FreeLibrary(hLocalDLL);
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
        LocalFree(argv);
        return 6;
    }
    
    DWORD_PTR offset = localRunMe - (DWORD_PTR)hLocalDLL;
    DWORD_PTR remoteRunMe = baseAddr + offset;
    
    DWORD result = 1;
    if (copyFile)
    {
        result = CallRemoteRunMe(hProcess, remoteRunMe, dllPath, pathToWrite);
    }
    else
    {
        result = CallRemoteRunMe(hProcess, remoteRunMe, pathToWrite, L"0");
    }
    
    FreeLibrary(hLocalDLL);
    
    // Resume the process (important!)
    ResumeThread(pi.hThread);
    
    // Wait a bit for execution
    WaitForSingleObject(hProcess, 3000);
    
    // Cleanup
    TerminateProcess(hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(hProcess);
    LocalFree(argv);
    
    return 0;
}