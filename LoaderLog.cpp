// DebugLog.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <sstream>
#include <fstream>
#include <windows.h>


// Documentation for NtQueryInformationProcess and PROCESS_BASIC_INFORMATION is:
// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
using NtQueryInformationProcess_t = NTSTATUS(NTAPI* )(HANDLE ProcessHandle, int ProcessInformationClass, __out void* ProcessInformation, ULONG ProcessInformationLength, __out PULONG ReturnLength);
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    void* PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

DWORD pid;

using namespace std;

wofstream logFile;

void HandleDebugOutputString(const DEBUG_EVENT &dbgEvent, HANDLE hProcess)
{
    // Don't bother with output over 4k
    uint8_t buffer[4096];
    auto size = static_cast<int>(min(sizeof(buffer) - 2, dbgEvent.u.DebugString.nDebugStringLength));
    SIZE_T read;
    ReadProcessMemory(hProcess, dbgEvent.u.DebugString.lpDebugStringData, buffer, size, &read);

    size = static_cast<int>(min(read, size));
    buffer[size] = 0;
    buffer[size + 1] = 0;

    if (dbgEvent.u.DebugString.fUnicode)
    {
        logFile << (wchar_t*)buffer;
    }
    else
    {
        wchar_t wbuffer[4096];
        auto mbRet = MultiByteToWideChar(CP_ACP, 0, (char*)buffer, size, wbuffer, ARRAYSIZE(wbuffer));
        if (mbRet != 0)
        {
            logFile << wbuffer;
        }
    }
}

int main()
{
    auto cmdLine = GetCommandLineW();

    if (cmdLine[0] == '\"')
    {
        cmdLine++;
        while (*cmdLine != 0 && *cmdLine != '\"')
        {
            cmdLine++;
        }

        if (*cmdLine == '\"')
        {
            cmdLine++;
        }

        while (*cmdLine == ' ')
        {
            cmdLine++;
        }
    }
    else
    {
        while (*cmdLine != ' ')
        {
            cmdLine++;
        }
        while (*cmdLine == ' ')
        {
            cmdLine++;
        }
    }

    // Probably need to strip the beginning.
    STARTUPINFO si = { 0 };
    si.cb = sizeof(STARTUPINFO);
    PROCESS_INFORMATION pi;
    BOOL ret = CreateProcessW(NULL, cmdLine, nullptr, nullptr, FALSE, DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &pi);

    if (ret)
    {
        pid = pi.dwProcessId;
    }
    else
    {
        // Use our own pid as a fallback.
        pid = GetCurrentProcessId();
    }

    wstringstream fname;
    fname << L"DebugLog-" << pid << ".txt";
    logFile.open(fname.str());

    logFile << L"Child command line is: " << cmdLine << endl;

    if (!ret)
    {
        logFile << L"Error creating process: " << GetLastError() << endl;
        return 1;
    }

    auto hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll == NULL)
    {
        logFile << L"Couldn't find ntdll.dll" << endl;
        return 1;
    }

    auto ntQuery = (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    PROCESS_BASIC_INFORMATION pbi;
    ULONG len;
    auto status = ntQuery(pi.hProcess, 0, &pbi, sizeof(pbi), &len);
    if (!NT_SUCCESS(status))
    {
        logFile << L"Couldn't find PEB of process" << endl;
        return 1;
    }

    uint64_t peb = (uint64_t)pbi.PebBaseAddress;
    
    // Enable loader snaps in global flags

    // global flags are in PEB->NtGlobalFlag, which is offset 0xBC (unsigned long).
    // This can be seen by dumping _PEB using windows public symbols.
    // 0:000> dt ntdll!_PEB NtGlobalFlag
    //    +0x0bc NtGlobalFlag : Uint4B

    // SLS = flag 0x2
    // You can see this by using the "!gflags +sls" and see what flags change.
    
    ULONG gflags;
    SIZE_T actual;
    if (!ReadProcessMemory(pi.hProcess, (LPVOID)(peb + 0xBC), &gflags, sizeof(gflags), &actual))
    {
        logFile << L"Couldn't read gflags" << endl;
        return 1;
    }
    gflags |= 0x2;
    if (!WriteProcessMemory(pi.hProcess, (LPVOID)(peb + 0xBC), &gflags, sizeof(gflags), &actual))
    {
        logFile << L"Couldn't write gflags" << endl;
        return 1;
    }

    CloseHandle(pi.hThread);

    while (true)
    {
        DEBUG_EVENT dbgEvent;
        WaitForDebugEventEx(&dbgEvent, INFINITE);


        switch (dbgEvent.dwDebugEventCode)
        {
        case EXCEPTION_DEBUG_EVENT:
            logFile << L"Exeption event" << endl;
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            logFile << L"Thread created" << endl;
            break;
        case CREATE_PROCESS_DEBUG_EVENT:
            logFile << "Process created" << endl;
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            logFile << "Thread exited" << endl;
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            logFile << L"Process exited" << endl;
            break;
        case LOAD_DLL_DEBUG_EVENT:
            logFile << L"Dll loaded" << endl;
            break;
        case UNLOAD_DLL_DEBUG_EVENT:
            logFile << "Dll unloaded" << endl;
            break;
        case OUTPUT_DEBUG_STRING_EVENT:
            HandleDebugOutputString(dbgEvent, pi.hProcess);
            break;
        case RIP_EVENT:
            logFile << L"RIP event" << endl;
            break;
        }

        if (dbgEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        {
            break;
        }

        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
    }
    CloseHandle(pi.hProcess);
}