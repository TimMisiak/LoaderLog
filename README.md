# LoaderLog

This tool can be used to capture debug output and loader logs (also known as "show loader snaps"). This is the same information you can get from enabling "Show loader snaps" using gflags, but can be used without a full debugger attached.

## Usage

```
LoaderLog <command line>
```

This will create a DebugLog-<pid>.txt file in the current working directory, containing a log that looks like this:

```
Child command line is: notepad.exe
Other debug event: 3
Other debug event: 6
6c80:cc80 @ 516860140 - LdrpInitializeProcess - INFO: Beginning execution of notepad.exe (C:\windows\SYSTEM32\notepad.exe)
	Current directory: D:\git\LoaderLog\x64\Debug\
	Package directories: (null)
6c80:cc80 @ 516860140 - LdrLoadDll - ENTER: DLL name: KERNEL32.DLL
6c80:cc80 @ 516860140 - LdrpLoadDllInternal - ENTER: DLL name: KERNEL32.DLL
6c80:cc80 @ 516860140 - LdrpFindKnownDll - ENTER: DLL name: KERNEL32.DLL
6c80:cc80 @ 516860140 - LdrpFindKnownDll - RETURN: Status: 0x00000000
6c80:cc80 @ 516860140 - LdrpMinimalMapModule - ENTER: DLL name: C:\windows\System32\KERNEL32.DLL
Other debug event: 6
6c80:cc80 @ 516860140 - LdrpMinimalMapModule - RETURN: Status: 0x00000000
6c80:cc80 @ 516860140 - LdrpPreprocessDllName - INFO: DLL api-ms-win-core-rtlsupport-l1-1-0.dll was redirected to C:\windows\SYSTEM32\ntdll.dll by API set
6c80:cc80 @ 516860140 - LdrpFindKnownDll - ENTER: DLL name: KERNELBASE.dll
6c80:cc80 @ 516860140 - LdrpFindKnownDll - RETURN: Status: 0x00000000
...
```

LoaderLog acts uses the debugging APIs such as DEBUG_ONLY_THIS_PROCESS with WaitForDebugEvent, so it does not allow debugging the target application at the same time.

You can use IFEO (Image File Execution Options) to have LoaderLog always enabled for a binary. For instance:

```
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dotnet.exe" /v "Debugger" /t REG_SZ /d "C:\Tools\LoaderLog.exe"
```

This tool has had minimal testing, but I used it to successfully diagnose a DLL load failure in a pipeline where I couldn't use a debugger, so I thought it might be helpful to other people as well.