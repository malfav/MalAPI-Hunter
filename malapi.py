# ============================================================
#  mal_api_hunter.py  —  IDA Pro Plugin  v1.0
#  Highlights malicious / suspicious API calls and provides
#  a clean GUI panel for navigation and classification.
#
#  Install : copy to  <IDA>/plugins/mal_api_hunter.py
#  Shortcut: Ctrl+Shift+A
# ============================================================

import idaapi
import idautils
import idc
import ida_funcs
import ida_kernwin

from PyQt5 import QtWidgets, QtGui, QtCore

PLUGIN_NAME    = "MalAPI"
PLUGIN_HOTKEY  = "Ctrl+Shift+A"
PLUGIN_VERSION = "1.0"
Plugin_Author  = "Diyar Saadi"

# ── Instruction highlight colour (IDA BGR format) ──────────
IDA_HIGHLIGHT_COLOR = 0x8D8C7F   # #7f8c8d muted grey-blue

# ══════════════════════════════════════════════════════════
#  DATABASE  ── original Win32 malicious APIs (COMPLETE)
# ══════════════════════════════════════════════════════════
MAL_APIS = {
    # ── Enumeration ───────────────────────────────────────
    "CreateToolhelp32Snapshot":           "Enumeration",
    "EnumDeviceDrivers":                  "Enumeration",
    "EnumProcesses":                      "Enumeration",
    "EnumProcessModules":                 "Enumeration",
    "EnumProcessModulesEx":               "Enumeration",
    "FindFirstFileA":                     "Enumeration",
    "FindNextFileA":                      "Enumeration",
    "GetLogicalProcessorInformation":     "Enumeration",
    "GetLogicalProcessorInformationEx":   "Enumeration",
    "GetModuleBaseNameA":                 "Enumeration",
    "GetSystemDefaultLangId":             "Enumeration",
    "GetVersionExA":                      "Enumeration",
    "GetWindowsDirectoryA":               "Enumeration",
    "IsWoW64Process":                     "Enumeration",
    "Module32First":                      "Enumeration",
    "Module32Next":                       "Enumeration",
    "Process32First":                     "Enumeration",
    "Process32Next":                      "Enumeration",
    "ReadProcessMemory":                  "Enumeration",
    "Thread32First":                      "Enumeration",
    "Thread32Next":                       "Enumeration",
    "GetSystemDirectoryA":                "Enumeration",
    "GetSystemTime":                      "Enumeration",
    "ReadFile":                           "Enumeration",
    "GetComputerNameA":                   "Enumeration",
    "VirtualQueryEx":                     "Enumeration",
    "GetProcessIdOfThread":               "Enumeration",
    "GetProcessId":                       "Enumeration",
    "GetCurrentThread":                   "Enumeration",
    "GetCurrentThreadId":                 "Enumeration",
    "GetThreadId":                        "Enumeration",
    "GetThreadInformation":               "Enumeration",
    "GetCurrentProcess":                  "Enumeration",
    "GetCurrentProcessId":                "Enumeration",
    "SearchPathA":                        "Enumeration",
    "GetFileTime":                        "Enumeration",
    "GetFileAttributesA":                 "Enumeration",
    "LookupPrivilegeValueA":              "Enumeration",
    "LookupAccountNameA":                 "Enumeration",
    "GetCurrentHwProfileA":               "Enumeration",
    "GetUserNameA":                       "Enumeration",
    "RegEnumKeyExA":                      "Enumeration",
    "RegEnumValueA":                      "Enumeration",
    "RegQueryInfoKeyA":                   "Enumeration",
    "RegQueryMultipleValuesA":            "Enumeration",
    "RegQueryValueExA":                   "Enumeration",
    "NtQueryDirectoryFile":               "Enumeration",
    "NtQueryInformationProcess":          "Enumeration",
    "NtQuerySystemEnvironmentValueEx":    "Enumeration",
    "EnumDesktopWindows":                 "Enumeration",
    "EnumWindows":                        "Enumeration",
    "NetShareEnum":                       "Enumeration",
    "NetShareGetInfo":                    "Enumeration",
    "NetShareCheck":                      "Enumeration",
    "GetAdaptersInfo":                    "Enumeration",
    "PathFileExistsA":                    "Enumeration",
    "GetNativeSystemInfo":                "Enumeration",
    "RtlGetVersion":                      "Enumeration",
    "GetIpNetTable":                      "Enumeration",
    "GetLogicalDrives":                   "Enumeration",
    "GetDriveTypeA":                      "Enumeration",
    "RegEnumKeyA":                        "Enumeration",
    "WNetEnumResourceA":                  "Enumeration",
    "WNetCloseEnum":                      "Enumeration",
    "FindFirstUrlCacheEntryA":            "Enumeration",
    "FindNextUrlCacheEntryA":             "Enumeration",
    "WNetAddConnection2A":                "Enumeration",
    "WNetAddConnectionA":                 "Enumeration",
    "EnumResourceTypesA":                 "Enumeration",
    "EnumResourceTypesExA":               "Enumeration",
    "GetSystemTimeAsFileTime":            "Enumeration",
    "GetThreadLocale":                    "Enumeration",
    "EnumSystemLocalesA":                 "Enumeration",

    # ── Injection ─────────────────────────────────────────
    "CreateFileMappingA":                 "Injection",
    "CreateProcessA":                     "Injection",
    "CreateRemoteThread":                 "Injection",
    "CreateRemoteThreadEx":               "Injection",
    "GetModuleHandleA":                   "Injection",
    "GetProcAddress":                     "Injection",
    "GetThreadContext":                   "Injection",
    "HeapCreate":                         "Injection",
    "LoadLibraryA":                       "Injection",
    "LoadLibraryExA":                     "Injection",
    "LocalAlloc":                         "Injection",
    "MapViewOfFile":                      "Injection",
    "MapViewOfFile2":                     "Injection",
    "MapViewOfFile3":                     "Injection",
    "MapViewOfFileEx":                    "Injection",
    "OpenThread":                         "Injection",
    "QueueUserAPC":                       "Injection",
    "ResumeThread":                       "Injection",
    "SetProcessDEPPolicy":                "Injection",
    "SetThreadContext":                   "Injection",
    "SuspendThread":                      "Injection",
    "Toolhelp32ReadProcessMemory":        "Injection",
    "VirtualAlloc":                       "Injection",
    "VirtualAllocEx":                     "Injection",
    "VirtualProtect":                     "Injection",
    "VirtualProtectEx":                   "Injection",
    "WriteProcessMemory":                 "Injection",
    "VirtualAllocExNuma":                 "Injection",
    "VirtualAlloc2":                      "Injection",
    "VirtualAlloc2FromApp":               "Injection",
    "VirtualAllocFromApp":                "Injection",
    "VirtualProtectFromApp":              "Injection",
    "CreateThread":                       "Injection",
    "WaitForSingleObject":                "Injection",
    "OpenProcess":                        "Injection",
    "OpenFileMappingA":                   "Injection",
    "GetProcessHeap":                     "Injection",
    "GetProcessHeaps":                    "Injection",
    "HeapAlloc":                          "Injection",
    "HeapReAlloc":                        "Injection",
    "GlobalAlloc":                        "Injection",
    "AdjustTokenPrivileges":              "Injection",
    "CreateProcessAsUserA":               "Injection",
    "OpenProcessToken":                   "Injection",
    "CreateProcessWithTokenW":            "Injection",
    "NtAdjustPrivilegesToken":            "Injection",
    "NtAllocateVirtualMemory":            "Injection",
    "NtContinue":                         "Injection",
    "NtCreateProcess":                    "Injection",
    "NtCreateProcessEx":                  "Injection",
    "NtCreateSection":                    "Injection",
    "NtCreateThread":                     "Injection",
    "NtCreateThreadEx":                   "Injection",
    "NtCreateUserProcess":                "Injection",
    "NtDuplicateObject":                  "Injection",
    "NtMapViewOfSection":                 "Injection",
    "NtOpenProcess":                      "Injection",
    "NtOpenThread":                       "Injection",
    "NtProtectVirtualMemory":             "Injection",
    "NtQueueApcThread":                   "Injection",
    "NtQueueApcThreadEx":                 "Injection",
    "NtQueueApcThreadEx2":                "Injection",
    "NtReadVirtualMemory":                "Injection",
    "NtResumeThread":                     "Injection",
    "NtUnmapViewOfSection":               "Injection",
    "NtWaitForMultipleObjects":           "Injection",
    "NtWaitForSingleObject":              "Injection",
    "NtWriteVirtualMemory":               "Injection",
    "RtlCreateHeap":                      "Injection",
    "LdrLoadDll":                         "Injection",
    "RtlMoveMemory":                      "Injection",
    "RtlCopyMemory":                      "Injection",
    "SetPropA":                           "Injection",
    "WaitForSingleObjectEx":              "Injection",
    "WaitForMultipleObjects":             "Injection",
    "WaitForMultipleObjectsEx":           "Injection",
    "KeInsertQueueApc":                   "Injection",
    "Wow64SetThreadContext":              "Injection",
    "NtSuspendProcess":                   "Injection",
    "NtResumeProcess":                    "Injection",
    "DuplicateToken":                     "Injection",
    "NtReadVirtualMemoryEx":              "Injection",
    "CreateProcessInternal":              "Injection",
    "EnumSystemLocalesA":                 "Injection",
    "UuidFromStringA":                    "Injection",
    "DebugActiveProcessStop":             "Injection",

    # ── Evasion ───────────────────────────────────────────
    "DeleteFileA":                        "Evasion",
    "LoadResource":                       "Evasion",
    "SetEnvironmentVariableA":            "Evasion",
    "SetFileTime":                        "Evasion",
    "Sleep":                              "Evasion",
    "SetFileAttributesA":                 "Evasion",
    "SleepEx":                            "Evasion",
    "NtDelayExecution":                   "Evasion",
    "CreateWindowExA":                    "Evasion",
    "RegisterHotKey":                     "Evasion",
    "timeSetEvent":                       "Evasion",
    "IcmpSendEcho":                       "Evasion",
    "SetWaitableTimer":                   "Evasion",
    "CreateTimerQueueTimer":              "Evasion",
    "CreateWaitableTimer":                "Evasion",
    "SetTimer":                           "Evasion",
    "Select":                             "Evasion",
    "ImpersonateLoggedOnUser":            "Evasion",
    "SetThreadToken":                     "Evasion",
    "SizeOfResource":                     "Evasion",
    "LockResource":                       "Evasion",
    "TimeGetTime":                        "Evasion",
    "CryptProtectData":                   "Evasion",

    # ── Spying ────────────────────────────────────────────
    "AttachThreadInput":                  "Spying",
    "CallNextHookEx":                     "Spying",
    "GetAsyncKeyState":                   "Spying",
    "GetClipboardData":                   "Spying",
    "GetDC":                              "Spying",
    "GetDCEx":                            "Spying",
    "GetForegroundWindow":                "Spying",
    "GetKeyboardState":                   "Spying",
    "GetKeyState":                        "Spying",
    "GetMessageA":                        "Spying",
    "GetRawInputData":                    "Spying",
    "GetWindowDC":                        "Spying",
    "MapVirtualKeyA":                     "Spying",
    "MapVirtualKeyExA":                   "Spying",
    "PeekMessageA":                       "Spying",
    "PostMessageA":                       "Spying",
    "PostThreadMessageA":                 "Spying",
    "RegisterRawInputDevices":            "Spying",
    "SendMessageA":                       "Spying",
    "SendMessageCallbackA":               "Spying",
    "SendMessageTimeoutA":                "Spying",
    "SendNotifyMessageA":                 "Spying",
    "SetWindowsHookExA":                  "Spying",
    "SetWinEventHook":                    "Spying",
    "UnhookWindowsHookEx":                "Spying",
    "BitBlt":                             "Spying",
    "StretchBlt":                         "Spying",
    "GetKeynameTextA":                    "Spying",

    # ── Internet ──────────────────────────────────────────
    "WinExec":                            "Internet",
    "FtpPutFileA":                        "Internet",
    "HttpOpenRequestA":                   "Internet",
    "HttpSendRequestA":                   "Internet",
    "HttpSendRequestExA":                 "Internet",
    "InternetCloseHandle":                "Internet",
    "InternetOpenA":                      "Internet",
    "InternetOpenUrlA":                   "Internet",
    "InternetReadFile":                   "Internet",
    "InternetReadFileExA":                "Internet",
    "InternetWriteFile":                  "Internet",
    "URLDownloadToFile":                  "Internet",
    "URLDownloadToCacheFile":             "Internet",
    "URLOpenBlockingStream":              "Internet",
    "URLOpenStream":                      "Internet",
    "Accept":                             "Internet",
    "Bind":                               "Internet",
    "Connect":                            "Internet",
    "Gethostbyname":                      "Internet",
    "Inet_addr":                          "Internet",
    "Recv":                               "Internet",
    "Send":                               "Internet",
    "WSAStartup":                         "Internet",
    "Gethostname":                        "Internet",
    "Socket":                             "Internet",
    "WSACleanup":                         "Internet",
    "Listen":                             "Internet",
    "ShellExecuteA":                      "Internet",
    "ShellExecuteExA":                    "Internet",
    "DnsQuery_A":                         "Internet",
    "DnsQueryEx":                         "Internet",
    "WNetOpenEnumA":                      "Internet",
    "InternetConnectA":                   "Internet",
    "InternetSetOptionA":                 "Internet",
    "WSASocketA":                         "Internet",
    "Closesocket":                        "Internet",
    "WSAIoctl":                           "Internet",
    "ioctlsocket":                        "Internet",
    "HttpAddRequestHeaders":              "Internet",

    # ── Anti-Debugging ────────────────────────────────────
    "GetTickCount":                       "Anti-Debugging",
    "OutputDebugStringA":                 "Anti-Debugging",
    "CheckRemoteDebuggerPresent":         "Anti-Debugging",
    "IsDebuggerPresent":                  "Anti-Debugging",
    "NtQueryInformationProcess":          "Anti-Debugging",
    "ExitWindowsEx":                      "Anti-Debugging",
    "FindWindowA":                        "Anti-Debugging",
    "FindWindowExA":                      "Anti-Debugging",
    "GetTickCount64":                     "Anti-Debugging",
    "QueryPerformanceFrequency":          "Anti-Debugging",
    "QueryPerformanceCounter":            "Anti-Debugging",
    "CountClipboardFormats":              "Anti-Debugging",

    # ── Ransomware ────────────────────────────────────────
    "CryptAcquireContextA":               "Ransomware",
    "EncryptFileA":                       "Ransomware",
    "CryptEncrypt":                       "Ransomware",
    "CryptDecrypt":                       "Ransomware",
    "CryptCreateHash":                    "Ransomware",
    "CryptHashData":                      "Ransomware",
    "CryptDeriveKey":                     "Ransomware",
    "CryptSetKeyParam":                   "Ransomware",
    "CryptGetHashParam":                  "Ransomware",
    "CryptDestroyKey":                    "Ransomware",
    "CryptGenRandom":                     "Ransomware",
    "DecryptFileA":                       "Ransomware",
    "FlushEfsCache":                      "Ransomware",
    "CryptStringToBinary":                "Ransomware",
    "CryptBinaryToString":                "Ransomware",
    "CryptReleaseContext":                "Ransomware",
    "CryptDestroyHash":                   "Ransomware",

    # ── Helper ────────────────────────────────────────────
    "ConnectNamedPipe":                   "Helper",
    "CopyFileA":                          "Helper",
    "CreateFileA":                        "Helper",
    "CreateMutexA":                       "Helper",
    "CreateMutexExA":                     "Helper",
    "DeviceIoControl":                    "Helper",
    "FindResourceA":                      "Helper",
    "FindResourceExA":                    "Helper",
    "GetModuleFileNameA":                 "Helper",
    "GetModuleFileNameExA":               "Helper",
    "GetTempPathA":                       "Helper",
    "MoveFileA":                          "Helper",
    "MoveFileExA":                        "Helper",
    "PeekNamedPipe":                      "Helper",
    "WriteFile":                          "Helper",
    "TerminateThread":                    "Helper",
    "CopyFile2":                          "Helper",
    "CopyFileExA":                        "Helper",
    "CreateFile2":                        "Helper",
    "GetTempFileNameA":                   "Helper",
    "TerminateProcess":                   "Helper",
    "SetCurrentDirectory":                "Helper",
    "FindClose":                          "Helper",
    "SetThreadPriority":                  "Helper",
    "UnmapViewOfFile":                    "Helper",
    "ControlService":                     "Helper",
    "ControlServiceExA":                  "Helper",
    "CreateServiceA":                     "Helper",
    "DeleteService":                      "Helper",
    "OpenSCManagerA":                     "Helper",
    "OpenServiceA":                       "Helper",
    "RegOpenKeyA":                        "Helper",
    "RegOpenKeyExA":                      "Helper",
    "StartServiceA":                      "Helper",
    "StartServiceCtrlDispatcherA":        "Helper",
    "RegCreateKeyExA":                    "Helper",
    "RegCreateKeyA":                      "Helper",
    "RegSetValueExA":                     "Helper",
    "RegSetKeyValueA":                    "Helper",
    "RegDeleteValueA":                    "Helper",
    "RegGetValueA":                       "Helper",
    "RegFlushKey":                        "Helper",
    "RegGetKeySecurity":                  "Helper",
    "RegLoadKeyA":                        "Helper",
    "RegLoadMUIStringA":                  "Helper",
    "RegOpenCurrentUser":                 "Helper",
    "RegOpenKeyTransactedA":              "Helper",
    "RegOpenUserClassesRoot":             "Helper",
    "RegOverridePredefKey":               "Helper",
    "RegReplaceKeyA":                     "Helper",
    "RegRestoreKeyA":                     "Helper",
    "RegSaveKeyA":                        "Helper",
    "RegSaveKeyExA":                      "Helper",
    "RegSetKeySecurity":                  "Helper",
    "RegUnLoadKeyA":                      "Helper",
    "RegConnectRegistryA":                "Helper",
    "RegCopyTreeA":                       "Helper",
    "RegCreateKeyTransactedA":            "Helper",
    "RegDeleteKeyA":                      "Helper",
    "RegDeleteKeyExA":                    "Helper",
    "RegDeleteKeyTransactedA":            "Helper",
    "RegDeleteKeyValueA":                 "Helper",
    "RegDeleteTreeA":                     "Helper",
    "RegCloseKey":                        "Helper",
    "NtClose":                            "Helper",
    "NtCreateFile":                       "Helper",
    "NtDeleteKey":                        "Helper",
    "NtDeleteValueKey":                   "Helper",
    "NtMakeTemporaryObject":              "Helper",
    "NtSetContextThread":                 "Helper",
    "NtSetInformationProcess":            "Helper",
    "NtSetInformationThread":             "Helper",
    "NtSetSystemEnvironmentValueEx":      "Helper",
    "NtSetValueKey":                      "Helper",
    "NtShutdownSystem":                   "Helper",
    "NtTerminateProcess":                 "Helper",
    "NtTerminateThread":                  "Helper",
    "RtlSetProcessIsCritical":            "Helper",
    "DrawTextExA":                        "Helper",
    "GetDesktopWindow":                   "Helper",
    "SetClipboardData":                   "Helper",
    "SetWindowLongA":                     "Helper",
    "SetWindowLongPtrA":                  "Helper",
    "OpenClipboard":                      "Helper",
    "SetForegroundWindow":                "Helper",
    "BringWindowToTop":                   "Helper",
    "SetFocus":                           "Helper",
    "ShowWindow":                         "Helper",
    "NetShareSetInfo":                    "Helper",
    "NetShareAdd":                        "Helper",
    "NtQueryTimer":                       "Helper",
    "CreatePipe":                         "Helper",
    "WNetAddConnection2A":                "Helper",
    "CallWindowProcA":                    "Helper",
    "lstrcatA":                           "Helper",

    # ──────────────────────────────────────────────────────────
    #  NEW API CATEGORIES ADDED BELOW
    # ──────────────────────────────────────────────────────────

    # ── Dynamic Data Exchange (DDE) ───────────────────────────
    "DdeSetQualityOfService":             "DDE",
    "FreeDDElParam":                      "DDE",
    "ImpersonateDdeClientWindow":         "DDE",
    "PackDDElParam":                      "DDE",
    "ReuseDDElParam":                     "DDE",
    "UnpackDDElParam":                    "DDE",
    "DdeAbandonTransaction":              "DDE",
    "DdeAccessData":                      "DDE",
    "DdeAddData":                         "DDE",
    "DdeCallback":                        "DDE",
    "DdeClientTransaction":               "DDE",
    "DdeCmpStringHandles":                "DDE",
    "DdeConnect":                         "DDE",
    "DdeConnectList":                     "DDE",
    "DdeCreateDataHandle":                "DDE",
    "DdeCreateStringHandle":              "DDE",
    "DdeDisconnect":                      "DDE",
    "DdeDisconnectList":                  "DDE",
    "DdeEnableCallback":                  "DDE",
    "DdeFreeDataHandle":                  "DDE",
    "DdeFreeStringHandle":                "DDE",
    "DdeGetData":                         "DDE",
    "DdeGetLastError":                    "DDE",
    "DdeImpersonateClient":               "DDE",
    "DdeInitialize":                      "DDE",
    "DdeKeepStringHandle":                "DDE",
    "DdeNameService":                     "DDE",
    "DdePostAdvise":                      "DDE",
    "DdeQueryConvInfo":                   "DDE",
    "DdeQueryNextServer":                 "DDE",
    "DdeQueryString":                     "DDE",
    "DdeReconnect":                       "DDE",
    "DdeSetUserHandle":                   "DDE",
    "DdeUnaccessData":                    "DDE",
    "DdeUninitialize":                    "DDE",

    # ── Windows Sockets (Winsock) ────────────────────────────
    "accept":                             "Winsock",
    "AcceptEx":                           "Winsock",
    "bind":                               "Winsock",
    "closesocket":                        "Winsock",
    "connect":                            "Winsock",
    "ConnectEx":                          "Winsock",
    "DisconnectEx":                       "Winsock",
    "EnumProtocols":                      "Winsock",
    "freeaddrinfo":                       "Winsock",
    "getaddrinfo":                        "Winsock",
    "FreeAddrInfoEx":                     "Winsock",
    "GetAddrInfoEx":                      "Winsock",
    "FreeAddrInfoW":                      "Winsock",
    "GetAddrInfoW":                       "Winsock",
    "gai_strerror":                       "Winsock",
    "GetAcceptExSockaddrs":               "Winsock",
    "GetAddressByName":                   "Winsock",
    "GetAddrInfoExCancel":                "Winsock",
    "GetAddrInfoExOverlappedResult":      "Winsock",
    "gethostbyaddr":                      "Winsock",
    "gethostbyname":                      "Winsock",
    "gethostname":                        "Winsock",
    "GetHostNameW":                       "Winsock",
    "getipv4sourcefilter":                "Winsock",
    "GetNameByType":                      "Winsock",
    "getnameinfo":                        "Winsock",
    "GetNameInfoW":                       "Winsock",
    "getpeername":                        "Winsock",
    "getprotobyname":                     "Winsock",
    "getprotobynumber":                   "Winsock",
    "getservbyname":                      "Winsock",
    "getservbyport":                      "Winsock",
    "GetService":                         "Winsock",
    "getsockname":                        "Winsock",
    "getsockopt":                         "Winsock",
    "getsourcefilter":                    "Winsock",
    "GetTypeByName":                      "Winsock",
    "htond":                              "Winsock",
    "htonf":                              "Winsock",
    "htonl":                              "Winsock",
    "htonll":                             "Winsock",
    "htons":                              "Winsock",
    "inet_addr":                          "Winsock",
    "inet_ntoa":                          "Winsock",
    "InetNtop":                           "Winsock",
    "InetPton":                           "Winsock",
    "listen":                             "Winsock",
    "ntohd":                              "Winsock",
    "ntohf":                              "Winsock",
    "ntohl":                              "Winsock",
    "ntohll":                             "Winsock",
    "ntohs":                              "Winsock",
    "recv":                               "Winsock",
    "recvfrom":                           "Winsock",
    "RIOCloseCompletionQueue":            "Winsock",
    "RIOCreateCompletionQueue":           "Winsock",
    "RIOCreateRequestQueue":              "Winsock",
    "RIODequeueCompletion":               "Winsock",
    "RIODeregisterBuffer":                "Winsock",
    "RIONotify":                          "Winsock",
    "RIOReceive":                         "Winsock",
    "RIOReceiveEx":                       "Winsock",
    "RIORegisterBuffer":                  "Winsock",
    "RIOResizeCompletionQueue":           "Winsock",
    "RIOResizeRequestQueue":              "Winsock",
    "RIOSend":                            "Winsock",
    "RIOSendEx":                          "Winsock",
    "select":                             "Winsock",
    "send":                               "Winsock",
    "sendto":                             "Winsock",
    "SetAddrInfoEx":                      "Winsock",
    "setipv4sourcefilter":                "Winsock",
    "SetSocketMediaStreamingMode":        "Winsock",
    "setsockopt":                         "Winsock",
    "setsourcefilter":                    "Winsock",
    "shutdown":                           "Winsock",
    "socket":                             "Winsock",
    "TransmitFile":                       "Winsock",
    "TransmitPackets":                    "Winsock",
    "WSAAccept":                          "Winsock",
    "WSAAddressToString":                 "Winsock",
    "WSAAsyncGetHostByAddr":              "Winsock",
    "WSAAsyncGetHostByName":              "Winsock",
    "WSAAsyncGetProtoByName":             "Winsock",
    "WSAAsyncGetProtoByNumber":           "Winsock",
    "WSAAsyncGetServByName":              "Winsock",
    "WSAAsyncGetServByPort":              "Winsock",
    "WSAAsyncSelect":                     "Winsock",
    "WSACancelAsyncRequest":              "Winsock",
    "WSACloseEvent":                      "Winsock",
    "WSAConnect":                         "Winsock",
    "WSAConnectByList":                   "Winsock",
    "WSAConnectByName":                   "Winsock",
    "WSACreateEvent":                     "Winsock",
    "WSADeleteSocketPeerTargetName":      "Winsock",
    "WSADuplicateSocket":                 "Winsock",
    "WSAEnumNameSpaceProviders":          "Winsock",
    "WSAEnumNameSpaceProvidersEx":        "Winsock",
    "WSAEnumNetworkEvents":               "Winsock",
    "WSAEnumProtocols":                   "Winsock",
    "WSAEventSelect":                     "Winsock",
    "__WSAFDIsSet":                       "Winsock",
    "WSAGetLastError":                    "Winsock",
    "WSAGetOverlappedResult":             "Winsock",
    "WSAGetServiceClassInfo":             "Winsock",
    "WSAGetServiceClassNameByClassId":    "Winsock",
    "WSAHtonl":                           "Winsock",
    "WSAHtons":                           "Winsock",
    "WSAImpersonateSocketPeer":           "Winsock",
    "WSAInstallServiceClass":             "Winsock",
    "WSAJoinLeaf":                        "Winsock",
    "WSALookupServiceBegin":              "Winsock",
    "WSALookupServiceEnd":                "Winsock",
    "WSALookupServiceNext":               "Winsock",
    "WSANSPIoctl":                        "Winsock",
    "WSANtohl":                           "Winsock",
    "WSANtohs":                           "Winsock",
    "WSAPoll":                            "Winsock",
    "WSAProviderConfigChange":            "Winsock",
    "WSAQuerySocketSecurity":             "Winsock",
    "WSARecv":                            "Winsock",
    "WSARecvDisconnect":                  "Winsock",
    "WSARecvEx":                          "Winsock",
    "WSARecvFrom":                        "Winsock",
    "WSARecvMsg":                         "Winsock",
    "WSARemoveServiceClass":              "Winsock",
    "WSAResetEvent":                      "Winsock",
    "WSARevertImpersonation":             "Winsock",
    "WSASend":                            "Winsock",
    "WSASendDisconnect":                  "Winsock",
    "WSASendMsg":                         "Winsock",
    "WSASendTo":                          "Winsock",
    "WSASetEvent":                        "Winsock",
    "WSASetLastError":                    "Winsock",
    "WSASetService":                      "Winsock",
    "WSASetSocketPeerTargetName":         "Winsock",
    "WSASetSocketSecurity":               "Winsock",
    "WSASocket":                          "Winsock",
    "WSAStringToAddress":                 "Winsock",
    "WSAWaitForMultipleEvents":           "Winsock",
    "NSPStartup":                         "Winsock",

    # ── Carets ──────────────────────────────────────────────
    "CreateCaret":                        "Carets",
    "DestroyCaret":                       "Carets",
    "GetCaretBlinkTime":                  "Carets",
    "GetCaretPos":                        "Carets",
    "HideCaret":                          "Carets",
    "SetCaretBlinkTime":                  "Carets",
    "SetCaretPos":                        "Carets",
    "ShowCaret":                          "Carets",

    # ── Windows Web Services ────────────────────────────────
    "WS_ABANDON_MESSAGE_CALLBACK":        "WWS",
    "WS_ABORT_CHANNEL_CALLBACK":          "WWS",
    "WS_ABORT_LISTENER_CALLBACK":         "WWS",
    "WS_ACCEPT_CHANNEL_CALLBACK":         "WWS",
    "WS_ASYNC_CALLBACK":                  "WWS",
    "WS_ASYNC_FUNCTION":                  "WWS",
    "WS_CERT_ISSUER_LIST_NOTIFICATION_CALLBACK": "WWS",
    "WS_CERTIFICATE_VALIDATION_CALLBACK": "WWS",
    "WS_CLOSE_CHANNEL_CALLBACK":          "WWS",
    "WS_CLOSE_LISTENER_CALLBACK":         "WWS",
    "WS_CREATE_CHANNEL_CALLBACK":         "WWS",
    "WS_CREATE_CHANNEL_FOR_LISTENER_CALLBACK": "WWS",
    "WS_CREATE_DECODER_CALLBACK":         "WWS",
    "WS_CREATE_ENCODER_CALLBACK":         "WWS",
    "WS_CREATE_LISTENER_CALLBACK":        "WWS",
    "WS_DECODER_DECODE_CALLBACK":         "WWS",
    "WS_DECODER_END_CALLBACK":            "WWS",
    "WS_DECODER_GET_CONTENT_TYPE_CALLBACK": "WWS",
    "WS_DECODER_START_CALLBACK":          "WWS",
    "WS_DURATION_COMPARISON_CALLBACK":    "WWS",
    "WS_DYNAMIC_STRING_CALLBACK":         "WWS",
    "WS_ENCODER_ENCODE_CALLBACK":         "WWS",
    "WS_ENCODER_END_CALLBACK":            "WWS",
    "WS_ENCODER_GET_CONTENT_TYPE_CALLBACK": "WWS",
    "WS_ENCODER_START_CALLBACK":          "WWS",
    "WS_FREE_CHANNEL_CALLBACK":           "WWS",
    "WS_FREE_DECODER_CALLBACK":           "WWS",
    "WS_FREE_ENCODER_CALLBACK":           "WWS",
    "WS_FREE_LISTENER_CALLBACK":          "WWS",
    "WS_GET_CERT_CALLBACK":               "WWS",
    "WS_GET_CHANNEL_PROPERTY_CALLBACK":   "WWS",
    "WS_GET_LISTENER_PROPERTY_CALLBACK":  "WWS",
    "WS_HTTP_REDIRECT_CALLBACK":          "WWS",
    "WS_IS_DEFAULT_VALUE_CALLBACK":       "WWS",
    "WS_MESSAGE_DONE_CALLBACK":           "WWS",
    "WS_OPEN_CHANNEL_CALLBACK":           "WWS",
    "WS_OPEN_LISTENER_CALLBACK":          "WWS",
    "WS_OPERATION_CANCEL_CALLBACK":       "WWS",
    "WS_OPERATION_FREE_STATE_CALLBACK":   "WWS",
    "WS_PROXY_MESSAGE_CALLBACK":          "WWS",
    "WS_PULL_BYTES_CALLBACK":             "WWS",
    "WS_PUSH_BYTES_CALLBACK":             "WWS",
    "WS_READ_CALLBACK":                   "WWS",
    "WS_READ_MESSAGE_END_CALLBACK":       "WWS",
    "WS_READ_MESSAGE_START_CALLBACK":     "WWS",
    "WS_READ_TYPE_CALLBACK":              "WWS",
    "WS_RESET_CHANNEL_CALLBACK":          "WWS",
    "WS_RESET_LISTENER_CALLBACK":         "WWS",
    "WS_SERVICE_ACCEPT_CHANNEL_CALLBACK": "WWS",
    "WS_SERVICE_CLOSE_CHANNEL_CALLBACK":  "WWS",
    "WS_SERVICE_MESSAGE_RECEIVE_CALLBACK": "WWS",
    "WS_SERVICE_SECURITY_CALLBACK":       "WWS",
    "WS_SERVICE_STUB_CALLBACK":           "WWS",
    "WS_SET_CHANNEL_PROPERTY_CALLBACK":   "WWS",
    "WS_SET_LISTENER_PROPERTY_CALLBACK":  "WWS",
    "WS_SHUTDOWN_SESSION_CHANNEL_CALLBACK": "WWS",
    "WS_VALIDATE_PASSWORD_CALLBACK":      "WWS",
    "WS_VALIDATE_SAML_CALLBACK":          "WWS",
    "WS_WRITE_CALLBACK":                  "WWS",
    "WS_WRITE_MESSAGE_END_CALLBACK":      "WWS",
    "WS_WRITE_MESSAGE_START_CALLBACK":    "WWS",
    "WS_WRITE_TYPE_CALLBACK":             "WWS",

    # ── Directory Management ─────────────────────────────────
    "CreateDirectory":                    "Directory",
    "CreateDirectoryEx":                  "Directory",
    "CreateDirectoryTransacted":          "Directory",
    "FindCloseChangeNotification":        "Directory",
    "FindFirstChangeNotification":        "Directory",
    "FindNextChangeNotification":         "Directory",
    "GetCurrentDirectory":                "Directory",
    "ReadDirectoryChangesW":              "Directory",
    "RemoveDirectory":                    "Directory",
    "RemoveDirectoryTransacted":          "Directory",

    # ── Cryptography (Extended) ─────────────────────────────
    "A_SHAFinal":                         "Cryptography",
    "A_SHAInit":                          "Cryptography",
    "A_SHAUpdate":                        "Cryptography",
    "CryptXmlCreateReference":            "Cryptography",
    "CryptXmlAddObject":                  "Cryptography",
    "CryptXmlClose":                      "Cryptography",
    "CryptXmlDigestReference":            "Cryptography",
    "CryptXmlDllCloseDigest":             "Cryptography",
    "CryptXmlDllCreateDigest":            "Cryptography",
    "CryptXmlDllCreateKey":               "Cryptography",
    "CryptXmlDllDigestData":              "Cryptography",
    "CryptXmlDllEncodeAlgorithm":         "Cryptography",
    "CryptXmlDllEncodeKeyValue":          "Cryptography",
    "CryptXmlDllFinalizeDigest":          "Cryptography",
    "CryptXmlDllGetAlgorithmInfo":        "Cryptography",
    "CryptXmlDllGetInterface":            "Cryptography",
    "CryptXmlDllSignData":                "Cryptography",
    "CryptXmlDllVerifySignature":         "Cryptography",
    "CryptXmlEncode":                     "Cryptography",
    "CryptXmlGetAlgorithmInfo":           "Cryptography",
    "CryptXmlGetDocContext":              "Cryptography",
    "CryptXmlGetReference":               "Cryptography",
    "CryptXmlGetSignature":               "Cryptography",
    "CryptXmlGetStatus":                  "Cryptography",
    "CryptXmlGetTransforms":              "Cryptography",
    "CryptXmlImportPublicKey":            "Cryptography",
    "CryptXmlOpenToEncode":               "Cryptography",
    "CryptXmlOpenToDecode":               "Cryptography",
    "CryptXmlSetHMACSecret":              "Cryptography",
    "CryptXmlSign":                       "Cryptography",
    "CryptXmlVerifySignature":            "Cryptography",
    "SignerFreeSignerContext":            "Cryptography",
    "SignerSignEx":                       "Cryptography",
    "SignError":                          "Cryptography",
    "SignerSign":                         "Cryptography",
    "SignerSignEx2":                      "Cryptography",
    "SignerTimeStamp":                    "Cryptography",
    "SignerTimeStampEx2":                 "Cryptography",
    "SignerTimeStampEx":                  "Cryptography",
    "SignerTimeStampEx3":                 "Cryptography",
    "CryptAcquireContext":                "Cryptography",
    "CryptContextAddRef":                 "Cryptography",
    "CryptEnumProviders":                 "Cryptography",
    "CryptEnumProviderTypes":             "Cryptography",
    "CryptGetDefaultProvider":            "Cryptography",
    "CryptGetProvParam":                  "Cryptography",
    "CryptInstallDefaultContext":         "Cryptography",
    "CryptSetProvider":                   "Cryptography",
    "CryptSetProviderEx":                 "Cryptography",
    "CryptSetProvParam":                  "Cryptography",
    "CryptUninstallDefaultContext":       "Cryptography",
    "FreeCryptProvFromCertEx":            "Cryptography",
    "CryptDuplicateKey":                  "Cryptography",
    "CryptExportKey":                     "Cryptography",
    "CryptGenKey":                        "Cryptography",
    "CryptGetKeyParam":                   "Cryptography",
    "CryptGetUserKey":                    "Cryptography",
    "CryptImportKey":                     "Cryptography",
    "CryptDecodeObject":                  "Cryptography",
    "CryptDecodeObjectEx":                "Cryptography",
    "CryptEncodeObject":                  "Cryptography",
    "CryptEncodeObjectEx":                "Cryptography",
    "CryptProtectMemory":                 "Cryptography",
    "CryptUnprotectData":                 "Cryptography",
    "CryptUnprotectMemory":               "Cryptography",
    "CryptDuplicateHash":                 "Cryptography",
    "CryptHashSessionKey":                "Cryptography",
    "CryptSetHashParam":                  "Cryptography",
    "CryptSignHash":                      "Cryptography",
    "CryptUIWizDigitalSign":              "Cryptography",
    "CryptUIWizFreeDigitalSignContext":   "Cryptography",
    "CryptVerifySignature":               "Cryptography",
    "CertAddStoreToCollection":           "Cryptography",
    "CertCloseStore":                     "Cryptography",
    "CertControlStore":                   "Cryptography",
    "CertDuplicateStore":                 "Cryptography",
    "CertEnumPhysicalStore":              "Cryptography",
    "CertEnumSystemStore":                "Cryptography",
    "CertEnumSystemStoreLocation":        "Cryptography",
    "CertGetStoreProperty":               "Cryptography",
    "CertOpenStore":                      "Cryptography",
    "CertOpenSystemStore":                "Cryptography",
    "CertRegisterPhysicalStore":          "Cryptography",
    "CertRegisterSystemStore":            "Cryptography",
    "CertRemoveStoreFromCollection":      "Cryptography",
    "CertSaveStore":                      "Cryptography",
    "CertSetStoreProperty":               "Cryptography",
    "CertUnregisterPhysicalStore":        "Cryptography",
    "CertUnregisterSystemStore":          "Cryptography",
    "CryptUIWizExport":                   "Cryptography",
    "CryptUIWizImport":                   "Cryptography",
    "CertAddCertificateContextToStore":   "Cryptography",
    "CertAddCertificateLinkToStore":      "Cryptography",
    "CertAddEncodedCertificateToStore":   "Cryptography",
    "CertCreateCertificateContext":       "Cryptography",
    "CertCreateSelfSignCertificate":      "Cryptography",
    "CertDeleteCertificateFromStore":     "Cryptography",
    "CertDuplicateCertificateContext":    "Cryptography",
    "CertEnumCertificatesInStore":        "Cryptography",
    "CertFindCertificateInStore":         "Cryptography",
    "CertFreeCertificateContext":         "Cryptography",
    "CertGetCertificateChain":            "Cryptography",
    "CertVerifyCertificateChainPolicy":   "Cryptography",
    "CryptMsgClose":                      "Cryptography",
    "CryptMsgControl":                    "Cryptography",
    "CryptMsgUpdate":                     "Cryptography",
    "CryptMsgGetParam":                   "Cryptography",
    "CryptMsgOpenToDecode":               "Cryptography",
    "CryptMsgOpenToEncode":               "Cryptography",
    "CryptDecryptMessage":                "Cryptography",
    "CryptEncryptMessage":                "Cryptography",
    "CryptSignMessage":                   "Cryptography",
    "CryptVerifyMessageSignature":        "Cryptography",
    "CryptBinaryToString":                "Cryptography",
    "CryptFormatObject":                  "Cryptography",
}

# ══════════════════════════════════════════════════════════
#  DATABASE  ── Native NT APIs (new, untouched addition)
# ══════════════════════════════════════════════════════════
NATIVE_APIS = {
    # Memory Management
    "NtVirtualAllocX":                    "Native-Memory",
    "NtAllocateVirtualMemory":            "Native-Memory",
    "NtFreeVirtualMemory":                "Native-Memory",
    "NtProtectVirtualMemory":             "Native-Memory",
    "NtMapViewOfSection":                 "Native-Memory",
    "NtUnmapViewOfSection":               "Native-Memory",
    # File Operations
    "NtCreateFile":                       "Native-File",
    "NtReadFile":                         "Native-File",
    "NtWriteFile":                        "Native-File",
    "NtQueryDirectoryFile":               "Native-File",
    "NtSetInformationFile":               "Native-File",
    "NtQueryInformationFile":             "Native-File",
    "NtQueryVolumeInformationFile":       "Native-File",
    # Process Management
    "NtTerminateProcess":                 "Native-Process",
    "NtOpenProcess":                      "Native-Process",
    "NtQueryInformationProcess":          "Native-Process",
    "NtCreateUserProcess":                "Native-Process",
    # Thread Management
    "NtOpenThread":                       "Native-Thread",
    "NtSuspendThread":                    "Native-Thread",
    "NtResumeThread":                     "Native-Thread",
    "NtSetInformationThread":             "Native-Thread",
    "NtDelayExecution":                   "Native-Thread",
    # Handle Management
    "NtClose":                            "Native-Handle",
    "NtDuplicateObject":                  "Native-Handle",
    # System Monitoring
    "NtQuerySystemInformation":           "Native-System",
    "NtQueryPerformanceCounter":          "Native-System",
    # Registry Operations
    "NtQueryKey":                         "Native-Registry",
    "NtSetValueKey":                      "Native-Registry",
    "NtOpenKey":                          "Native-Registry",
    "NtQueryValueKey":                    "Native-Registry",
    "NtEnumerateValueKey":                "Native-Registry",
    # Security Management
    "NtAdjustPrivilegesToken":            "Native-Security",
    # Driver Operations
    "NtLoadDriver":                       "Native-Driver",
    "NtUnloadDriver":                     "Native-Driver",
    # Device Operations
    "NtDeviceIoControlFile":              "Native-Device",
    # Synchronization
    "NtWaitForSingleObject":              "Native-Sync",
    "NtWaitForMultipleObjects":           "Native-Sync",
    "NtSetEvent":                         "Native-Sync",
    "NtResetEvent":                       "Native-Sync",
    "NtCreateMutant":                     "Native-Sync",
    "NtReleaseMutant":                    "Native-Sync",
    "NtQuerySemaphore":                   "Native-Sync",
    # Timer Operations
    "NtSetTimer":                         "Native-Timer",
    "NtCancelTimer":                      "Native-Timer",
}

# ══════════════════════════════════════════════════════════
#  DATABASE  ── DLL-classified suspicious APIs (new, untouched)
# ══════════════════════════════════════════════════════════
DLL_APIS = {
    # ADVAPI32
    "AdjustTokenPrivileges":              "ADVAPI32",
    "ChangeServiceConfig2":               "ADVAPI32",
    "ControlService":                     "ADVAPI32",
    "CreateProcessAsUserW":               "ADVAPI32",
    "CreateProcessWithTokenW":            "ADVAPI32",
    "CreateService":                      "ADVAPI32",
    "CredEnumerateW":                     "ADVAPI32",
    "CredReadW":                          "ADVAPI32",
    "CryptEnumProviders":                 "ADVAPI32",
    "DuplicateTokenEx":                   "ADVAPI32",
    "ImpersonateLoggedOnUser":            "ADVAPI32",
    "LsaOpenPolicy":                      "ADVAPI32",
    "LsaRetrievePrivateData":             "ADVAPI32",
    "OpenProcessToken":                   "ADVAPI32",
    "OpenSCManager":                      "ADVAPI32",
    "QueryServiceStatusEx":               "ADVAPI32",
    "RegCreateKeyEx":                     "ADVAPI32",
    "RegEnumKeyEx":                       "ADVAPI32",
    "RegSetValueEx":                      "ADVAPI32",
    # AMSI
    "AmsiInitialize":                     "AMSI",
    "AmsiOpenSession":                    "AMSI",
    "AmsiScanBuffer":                     "AMSI",
    "AmsiScanString":                     "AMSI",
    # DBGHELP
    "MiniDumpWriteDump":                  "DBGHELP",
    # DNSAPI
    "DnsQuery":                           "DNSAPI",
    # FWPUCLNT
    "FwpmCalloutAdd":                     "FWPUCLNT",
    "FwpmCalloutRegister":                "FWPUCLNT",
    "FwpmEngineOpen":                     "FWPUCLNT",
    "FwpmFilterAdd":                      "FWPUCLNT",
    "FwpIpsecRoutine0":                   "FWPUCLNT",
    # KERNEL32
    "ConvertThreadToFiber":               "KERNEL32",
    "CreateEvent":                        "KERNEL32",
    "CreateFiber":                        "KERNEL32",
    "CreateFileMapping":                  "KERNEL32",
    "CreateFileTransacted":               "KERNEL32",
    "CreateNamedPipe":                    "KERNEL32",
    "CreateProcessInternalW":             "KERNEL32",
    "CreateRemoteThread":                 "KERNEL32",
    "CreateToolhelp32Snapshot":           "KERNEL32",
    "EnumProcesses":                      "KERNEL32",
    "EnumSystemLocalesW":                 "KERNEL32",
    "GetSystemFirmwareTable":             "KERNEL32",
    "LoadLibrary":                        "KERNEL32",
    "PssCaptureSnapshot":                 "KERNEL32",
    "QueueUserAPC":                       "KERNEL32",
    "SetDllDirectory":                    "KERNEL32",
    "SetProcessMitigationPolicy":         "KERNEL32",
    "SetSearchPathMode":                  "KERNEL32",
    "SetThreadContext":                   "KERNEL32",
    "UpdateProcThreadAttribute":          "KERNEL32",
    "VirtualAllocEx":                     "KERNEL32",
    "VirtualProtectEx":                   "KERNEL32",
    "WriteProcessMemory":                 "KERNEL32",
    "WriteProfileString":                 "KERNEL32",
    # MPR
    "WNetAddConnection2":                 "MPR",
    # NETAPI32
    "DsGetDcName":                        "NETAPI32",
    "NetLocalGroupGetMembers":            "NETAPI32",
    "NetRemoteTOD":                       "NETAPI32",
    "NetSessionEnum":                     "NETAPI32",
    "NetUserAdd":                         "NETAPI32",
    "NetWkstaUserEnum":                   "NETAPI32",
    # NTDLL
    "DbgUiRemoteBreakin":                 "NTDLL",
    "EtwEventWrite":                      "NTDLL",
    "EtwNotificationRegister":            "NTDLL",
    "EtwProviderEnabled":                 "NTDLL",
    "LdrGetProcedureAddress":             "NTDLL",
    "LdrLoadDll":                         "NTDLL",
    "NtAlpcConnectPort":                  "NTDLL",
    "NtCreateKey":                        "NTDLL",
    "NtCreateSection":                    "NTDLL",
    "NtCreateThreadEx":                   "NTDLL",
    "NtImpersonateThread":                "NTDLL",
    "NtLoadDriver":                       "NTDLL",
    "NtOpenProcessToken":                 "NTDLL",
    "NtQueueApcThread":                   "NTDLL",
    "NtQueryVirtualMemory":               "NTDLL",
    "NtRaiseHardError":                   "NTDLL",
    "NtReadVirtualMemory":                "NTDLL",
    "NtSetDebugFilterState":              "NTDLL",
    "NtSuspendProcess":                   "NTDLL",
    "NtSystemDebugControl":               "NTDLL",
    "NtTraceEvent":                       "NTDLL",
    "NtWriteVirtualMemory":               "NTDLL",
    "RtlCreateUserProcess":               "NTDLL",
    "RtlCreateUserThread":                "NTDLL",
    "Wow64DisableWow64FsRedirection":     "NTDLL",
    "ZwQuerySystemInformationEx":         "NTDLL",
    "ZwUnmapViewOfSection":               "NTDLL",
    # OLE32
    "CoCreateInstance":                   "OLE32",
    "CoCreateInstanceEx":                 "OLE32",
    "CoGetClassObject":                   "OLE32",
    "CoSetProxyBlanket":                  "OLE32",
    # PSAPI
    "EnumProcessModules":                 "PSAPI",
    "GetModuleFileNameEx":                "PSAPI",
    "GetModuleInformation":               "PSAPI",
    "GetProcessMemoryInfo":               "PSAPI",
    # RASAPI32
    "RasEnumConnections":                 "RASAPI32",
    "RasGetEntryDialParams":              "RASAPI32",
    "RasGetEntryProperties":              "RASAPI32",
    # SETUPAPI
    "InstallHinfSection":                 "SETUPAPI",
    "SetupCopyOEMInf":                    "SETUPAPI",
    "SetupDiGetClassDevs":                "SETUPAPI",
    "SetupDiEnumClassDeviceInfo":         "SETUPAPI",
    "SetupInstallFile":                   "SETUPAPI",
    "SetupUninstallOEMInf":               "SETUPAPI",
    # SHELL32
    "ShellExecute":                       "SHELL32",
    "SHGetKnownFolderPath":               "SHELL32",
    # UIAUTOMATIONCORE
    "AddAutomationEventHandler":          "UIAUTOMATION",
    # URLMON
    "URLDownloadToFile":                  "URLMON",
    # USER32
    "LockWorkStation":                    "USER32",
    "OpenDesktop":                        "USER32",
    "SetClipboardData":                   "USER32",
    "SetWindowsHookEx":                   "USER32",
    # WINHTTP
    "WinHttpConnect":                     "WINHTTP",
    # WINSTA
    "WinStationQueryInformationW":        "WINSTA",
}

# ══════════════════════════════════════════════════════════
#  DATABASE  ── Extended APIs from Windows API reference
#  (https://learn.microsoft.com/en-us/windows/win32/api/)
#  Added without altering any entry above.
# ══════════════════════════════════════════════════════════

# ── Debugging ────────────────────────────────────────────
DEBUGGING_APIS = {
    "CheckRemoteDebuggerPresent":         "Debugging",
    "ContinueDebugEvent":                 "Debugging",
    "DebugActiveProcess":                 "Debugging",
    "DebugActiveProcessStop":             "Debugging",
    "DebugBreak":                         "Debugging",
    "DebugBreakProcess":                  "Debugging",
    "DebugSetProcessKillOnExit":          "Debugging",
    "FatalExit":                          "Debugging",
    "FlushInstructionCache":              "Debugging",
    "GetThreadSelectorEntry":             "Debugging",
    "IsDebuggerPresent":                  "Debugging",
    "OutputDebugString":                  "Debugging",
    "WaitForDebugEvent":                  "Debugging",
    "Wow64GetThreadContext":              "Debugging",
    "Wow64GetThreadSelectorEntry":        "Debugging",
    "Wow64SetThreadContext":              "Debugging",
}

# ── Process Snapshotting ──────────────────────────────────
SNAPSHOT_APIS = {
    "PssCaptureSnapshot":                 "ProcessSnapshot",
    "PssDuplicateSnapshot":               "ProcessSnapshot",
    "PssFreeSnapshot":                    "ProcessSnapshot",
    "PssQuerySnapshot":                   "ProcessSnapshot",
    "PssWalkMarkerCreate":                "ProcessSnapshot",
    "PssWalkMarkerFree":                  "ProcessSnapshot",
    "PssWalkMarkerGetPosition":           "ProcessSnapshot",
    "PssWalkMarkerSeekToBeginning":       "ProcessSnapshot",
    "PssWalkMarkerSetPosition":           "ProcessSnapshot",
    "PssWalkSnapshot":                    "ProcessSnapshot",
}

# ── Volume Shadow Copy ────────────────────────────────────
VSS_APIS = {
    "CreateVssBackupComponents":          "VolumeShadow",
    "CreateVssExamineWriterMetadata":     "VolumeShadow",
    "CreateVssExpressWriter":             "VolumeShadow",
    "IsVolumeSnapshotted":                "VolumeShadow",
    "ShouldBlockRevert":                  "VolumeShadow",
    "VssFreeSnapshotProperties":          "VolumeShadow",
}

# ── Windows Internet (WinINet) ────────────────────────────
WININET_APIS = {
    "CommitUrlCacheEntryA":               "WinINet",
    "CommitUrlCacheEntryW":               "WinINet",
    "CreateUrlCacheEntry":                "WinINet",
    "CreateUrlCacheGroup":                "WinINet",
    "DeleteUrlCacheEntry":                "WinINet",
    "DeleteUrlCacheGroup":                "WinINet",
    "FindFirstUrlCacheEntry":             "WinINet",
    "FindFirstUrlCacheEntryEx":           "WinINet",
    "FindFirstUrlCacheGroup":             "WinINet",
    "FindNextUrlCacheEntry":              "WinINet",
    "FindNextUrlCacheEntryEx":            "WinINet",
    "FindNextUrlCacheGroup":              "WinINet",
    "FtpCommand":                         "WinINet",
    "FtpCreateDirectory":                 "WinINet",
    "FtpDeleteFile":                      "WinINet",
    "FtpFindFirstFile":                   "WinINet",
    "FtpGetCurrentDirectory":             "WinINet",
    "FtpGetFile":                         "WinINet",
    "FtpGetFileSize":                     "WinINet",
    "FtpOpenFile":                        "WinINet",
    "FtpPutFile":                         "WinINet",
    "FtpRemoveDirectory":                 "WinINet",
    "FtpRenameFile":                      "WinINet",
    "FtpSetCurrentDirectory":             "WinINet",
    "GetUrlCacheEntryInfo":               "WinINet",
    "GetUrlCacheEntryInfoEx":             "WinINet",
    "GetUrlCacheGroupAttribute":          "WinINet",
    "HttpAddRequestHeaders":              "WinINet",
    "HttpEndRequest":                     "WinINet",
    "HttpOpenRequest":                    "WinINet",
    "HttpQueryInfo":                      "WinINet",
    "HttpSendRequest":                    "WinINet",
    "HttpSendRequestEx":                  "WinINet",
    "InternetAttemptConnect":             "WinINet",
    "InternetAutodial":                   "WinINet",
    "InternetAutodialHangup":             "WinINet",
    "InternetCanonicalizeUrl":            "WinINet",
    "InternetCheckConnection":            "WinINet",
    "InternetCloseHandle":                "WinINet",
    "InternetCombineUrl":                 "WinINet",
    "InternetConfirmZoneCrossing":        "WinINet",
    "InternetConnect":                    "WinINet",
    "InternetCrackUrl":                   "WinINet",
    "InternetCreateUrl":                  "WinINet",
    "InternetDial":                       "WinINet",
    "InternetErrorDlg":                   "WinINet",
    "InternetFindNextFile":               "WinINet",
    "InternetGetConnectedState":          "WinINet",
    "InternetGetConnectedStateEx":        "WinINet",
    "InternetGetCookie":                  "WinINet",
    "InternetGetCookieEx":                "WinINet",
    "InternetGetLastResponseInfo":        "WinINet",
    "InternetGetProxyInfo":               "WinINet",
    "InternetGoOnline":                   "WinINet",
    "InternetHangUp":                     "WinINet",
    "InternetLockRequestFile":            "WinINet",
    "InternetOpen":                       "WinINet",
    "InternetOpenUrl":                    "WinINet",
    "InternetQueryDataAvailable":         "WinINet",
    "InternetQueryOption":                "WinINet",
    "InternetReadFile":                   "WinINet",
    "InternetReadFileEx":                 "WinINet",
    "InternetSetCookie":                  "WinINet",
    "InternetSetCookieEx":                "WinINet",
    "InternetSetFilePointer":             "WinINet",
    "InternetSetOption":                  "WinINet",
    "InternetSetStatusCallback":          "WinINet",
    "InternetWriteFile":                  "WinINet",
    "RetrieveUrlCacheEntryFile":          "WinINet",
    "RetrieveUrlCacheEntryStream":        "WinINet",
    "SetUrlCacheEntryGroup":              "WinINet",
    "SetUrlCacheEntryInfo":               "WinINet",
    "SetUrlCacheGroupAttribute":          "WinINet",
    "UnlockUrlCacheEntryFile":            "WinINet",
    "UnlockUrlCacheEntryStream":          "WinINet",
}

# ── WinHTTP ───────────────────────────────────────────────
WINHTTP_APIS = {
    "WinHttpAddRequestHeaders":           "WinHTTP",
    "WinHttpCheckPlatform":               "WinHTTP",
    "WinHttpCloseHandle":                 "WinHTTP",
    "WinHttpConnect":                     "WinHTTP",
    "WinHttpCrackUrl":                    "WinHTTP",
    "WinHttpCreateUrl":                   "WinHTTP",
    "WinHttpDetectAutoProxyConfigUrl":    "WinHTTP",
    "WinHttpGetDefaultProxyConfiguration": "WinHTTP",
    "WinHttpGetIEProxyConfigForCurrentUser": "WinHTTP",
    "WinHttpGetProxyForUrl":              "WinHTTP",
    "WinHttpOpen":                        "WinHTTP",
    "WinHttpOpenRequest":                 "WinHTTP",
    "WinHttpQueryAuthSchemes":            "WinHTTP",
    "WinHttpQueryDataAvailable":          "WinHTTP",
    "WinHttpQueryHeaders":                "WinHTTP",
    "WinHttpQueryOption":                 "WinHTTP",
    "WinHttpReadData":                    "WinHTTP",
    "WinHttpReceiveResponse":             "WinHTTP",
    "WinHttpSendRequest":                 "WinHTTP",
    "WinHttpSetCredentials":              "WinHTTP",
    "WinHttpSetOption":                   "WinHTTP",
    "WinHttpSetStatusCallback":           "WinHTTP",
    "WinHttpSetTimeouts":                 "WinHTTP",
    "WinHttpWriteData":                   "WinHTTP",
}

# ── Network Management ────────────────────────────────────
NETMGMT_APIS = {
    "NetUserAdd":                         "NetManagement",
    "NetUserDel":                         "NetManagement",
    "NetUserEnum":                        "NetManagement",
    "NetUserGetInfo":                     "NetManagement",
    "NetUserSetInfo":                     "NetManagement",
    "NetUserChangePassword":              "NetManagement",
    "NetGroupAdd":                        "NetManagement",
    "NetGroupDel":                        "NetManagement",
    "NetGroupEnum":                       "NetManagement",
    "NetGroupAddUser":                    "NetManagement",
    "NetGroupDelUser":                    "NetManagement",
    "NetLocalGroupAdd":                   "NetManagement",
    "NetLocalGroupDel":                   "NetManagement",
    "NetLocalGroupEnum":                  "NetManagement",
    "NetLocalGroupAddMembers":            "NetManagement",
    "NetLocalGroupDelMembers":            "NetManagement",
    "NetLocalGroupGetMembers":            "NetManagement",
    "NetShareAdd":                        "NetManagement",
    "NetShareDel":                        "NetManagement",
    "NetShareEnum":                       "NetManagement",
    "NetShareGetInfo":                    "NetManagement",
    "NetShareSetInfo":                    "NetManagement",
    "NetServerEnum":                      "NetManagement",
    "NetServerGetInfo":                   "NetManagement",
    "NetSessionEnum":                     "NetManagement",
    "NetSessionGetInfo":                  "NetManagement",
    "NetSessionDel":                      "NetManagement",
    "NetFileEnum":                        "NetManagement",
    "NetFileClose":                       "NetManagement",
    "NetConnectionEnum":                  "NetManagement",
    "NetWkstaGetInfo":                    "NetManagement",
    "NetWkstaUserEnum":                   "NetManagement",
    "NetScheduleJobAdd":                  "NetManagement",
    "NetScheduleJobDel":                  "NetManagement",
    "NetScheduleJobEnum":                 "NetManagement",
    "DsGetDcName":                        "NetManagement",
    "NetGetJoinInformation":              "NetManagement",
    "NetJoinDomain":                      "NetManagement",
    "NetUnjoinDomain":                    "NetManagement",
}

# ── IP Helper ─────────────────────────────────────────────
IPHELPER_APIS = {
    "GetAdaptersInfo":                    "IPHelper",
    "GetAdaptersAddresses":               "IPHelper",
    "GetIpNetTable":                      "IPHelper",
    "GetIpNetTable2":                     "IPHelper",
    "GetIpForwardTable":                  "IPHelper",
    "GetIpForwardTable2":                 "IPHelper",
    "GetTcpTable":                        "IPHelper",
    "GetTcpTable2":                       "IPHelper",
    "GetTcp6Table":                       "IPHelper",
    "GetUdpTable":                        "IPHelper",
    "GetUdp6Table":                       "IPHelper",
    "GetNetworkParams":                   "IPHelper",
    "GetIfTable":                         "IPHelper",
    "GetIfTable2":                        "IPHelper",
    "GetIfEntry":                         "IPHelper",
    "GetIfEntry2":                        "IPHelper",
    "GetBestRoute":                       "IPHelper",
    "GetBestRoute2":                      "IPHelper",
    "SendARP":                            "IPHelper",
    "IcmpSendEcho":                       "IPHelper",
    "IcmpSendEcho2":                      "IPHelper",
    "Icmp6SendEcho2":                     "IPHelper",
    "IcmpCreateFile":                     "IPHelper",
    "IcmpCloseHandle":                    "IPHelper",
    "AddIPAddress":                       "IPHelper",
    "DeleteIPAddress":                    "IPHelper",
    "GetUnicastIpAddressTable":           "IPHelper",
    "NotifyRouteChange":                  "IPHelper",
    "NotifyAddrChange":                   "IPHelper",
    "GetExtendedTcpTable":                "IPHelper",
    "GetExtendedUdpTable":                "IPHelper",
    "GetOwnerModuleFromTcpEntry":         "IPHelper",
    "GetOwnerModuleFromUdpEntry":         "IPHelper",
}

# ── Authorization / Security ──────────────────────────────
AUTHZ_APIS = {
    "OpenProcessToken":                   "Authorization",
    "OpenThreadToken":                    "Authorization",
    "GetTokenInformation":                "Authorization",
    "SetTokenInformation":                "Authorization",
    "DuplicateTokenEx":                   "Authorization",
    "CreateRestrictedToken":              "Authorization",
    "AdjustTokenPrivileges":              "Authorization",
    "AdjustTokenGroups":                  "Authorization",
    "LookupPrivilegeValue":               "Authorization",
    "LookupPrivilegeName":                "Authorization",
    "LookupPrivilegeDisplayName":         "Authorization",
    "PrivilegeCheck":                     "Authorization",
    "ImpersonateLoggedOnUser":            "Authorization",
    "ImpersonateSelf":                    "Authorization",
    "ImpersonateAnonymousToken":          "Authorization",
    "RevertToSelf":                       "Authorization",
    "IsTokenRestricted":                  "Authorization",
    "CheckTokenMembership":               "Authorization",
    "CheckTokenCapability":               "Authorization",
    "AllocateAndInitializeSid":           "Authorization",
    "FreeSid":                            "Authorization",
    "EqualSid":                           "Authorization",
    "IsValidSid":                         "Authorization",
    "ConvertSidToStringSid":              "Authorization",
    "ConvertStringSidToSid":              "Authorization",
    "GetLengthSid":                       "Authorization",
    "LookupAccountName":                  "Authorization",
    "LookupAccountSid":                   "Authorization",
    "GetNamedSecurityInfo":               "Authorization",
    "SetNamedSecurityInfo":               "Authorization",
    "GetSecurityInfo":                    "Authorization",
    "SetSecurityInfo":                    "Authorization",
    "GetFileSecurity":                    "Authorization",
    "SetFileSecurity":                    "Authorization",
    "AccessCheck":                        "Authorization",
    "AuthzInitializeResourceManager":     "Authorization",
    "AuthzAccessCheck":                   "Authorization",
    "AuthzInitializeContextFromToken":    "Authorization",
    "AuthzInitializeContextFromSid":      "Authorization",
    "LsaOpenPolicy":                      "Authorization",
    "LsaRetrievePrivateData":             "Authorization",
    "LsaStorePrivateData":                "Authorization",
    "LsaQueryInformationPolicy":          "Authorization",
    "LsaSetInformationPolicy":            "Authorization",
    "LogonUser":                          "Authorization",
    "LogonUserEx":                        "Authorization",
    "CreateProcessAsUser":                "Authorization",
    "CreateProcessWithLogonW":            "Authorization",
}

# ── Event Logging / ETW ───────────────────────────────────
ETW_APIS = {
    "RegisterEventSource":                "EventLog",
    "ReportEvent":                        "EventLog",
    "OpenEventLog":                       "EventLog",
    "ReadEventLog":                       "EventLog",
    "CloseEventLog":                      "EventLog",
    "ClearEventLog":                      "EventLog",
    "BackupEventLog":                     "EventLog",
    "DeregisterEventSource":              "EventLog",
    "GetEventLogInformation":             "EventLog",
    "GetNumberOfEventLogRecords":         "EventLog",
    "GetOldestEventLogRecord":            "EventLog",
    "NotifyChangeEventLog":               "EventLog",
    "OpenBackupEventLog":                 "EventLog",
    "StartTrace":                         "EventTrace",
    "StopTrace":                          "EventTrace",
    "ControlTrace":                       "EventTrace",
    "EnableTrace":                        "EventTrace",
    "EnableTraceEx":                      "EventTrace",
    "EnableTraceEx2":                     "EventTrace",
    "QueryTrace":                         "EventTrace",
    "FlushTrace":                         "EventTrace",
    "QueryAllTraces":                     "EventTrace",
    "EnumerateTraceGuids":                "EventTrace",
    "EnumerateTraceGuidsEx":              "EventTrace",
    "OpenTrace":                          "EventTrace",
    "ProcessTrace":                       "EventTrace",
    "CloseTrace":                         "EventTrace",
    "RegisterTraceGuids":                 "EventTrace",
    "UnregisterTraceGuids":               "EventTrace",
    "TraceEvent":                         "EventTrace",
    "EventRegister":                      "EventTrace",
    "EventUnregister":                    "EventTrace",
    "EventWrite":                         "EventTrace",
    "EventWriteEx":                       "EventTrace",
    "EventWriteTransfer":                 "EventTrace",
    "EventEnabled":                       "EventTrace",
    "EventProviderEnabled":               "EventTrace",
    "EventActivityIdControl":             "EventTrace",
}

# ── Registry (extended) ───────────────────────────────────
REGISTRY_APIS = {
    "RegCreateKey":                       "Registry",
    "RegCreateKeyEx":                     "Registry",
    "RegCreateKeyTransacted":             "Registry",
    "RegOpenKey":                         "Registry",
    "RegOpenKeyEx":                       "Registry",
    "RegOpenKeyTransacted":               "Registry",
    "RegCloseKey":                        "Registry",
    "RegDeleteKey":                       "Registry",
    "RegDeleteKeyEx":                     "Registry",
    "RegDeleteKeyTransacted":             "Registry",
    "RegDeleteValue":                     "Registry",
    "RegDeleteKeyValue":                  "Registry",
    "RegDeleteTree":                      "Registry",
    "RegEnumKey":                         "Registry",
    "RegEnumKeyEx":                       "Registry",
    "RegEnumValue":                       "Registry",
    "RegFlushKey":                        "Registry",
    "RegGetValue":                        "Registry",
    "RegLoadKey":                         "Registry",
    "RegUnLoadKey":                       "Registry",
    "RegQueryInfoKey":                    "Registry",
    "RegQueryValueEx":                    "Registry",
    "RegQueryMultipleValues":             "Registry",
    "RegSetValueEx":                      "Registry",
    "RegSetKeyValue":                     "Registry",
    "RegSaveKey":                         "Registry",
    "RegSaveKeyEx":                       "Registry",
    "RegRestoreKey":                      "Registry",
    "RegReplaceKey":                      "Registry",
    "RegConnectRegistry":                 "Registry",
    "RegCopyTree":                        "Registry",
    "RegNotifyChangeKeyValue":            "Registry",
    "RegOpenCurrentUser":                 "Registry",
    "RegOpenUserClassesRoot":             "Registry",
    "RegOverridePredefKey":               "Registry",
    "NtCreateKey":                        "Registry",
    "NtOpenKey":                          "Registry",
    "NtOpenKeyEx":                        "Registry",
    "NtQueryKey":                         "Registry",
    "NtQueryValueKey":                    "Registry",
    "NtSetValueKey":                      "Registry",
    "NtEnumerateKey":                     "Registry",
    "NtEnumerateValueKey":                "Registry",
    "NtDeleteKey":                        "Registry",
    "NtDeleteValueKey":                   "Registry",
}

# ── Services (extended) ───────────────────────────────────
SERVICES_APIS = {
    "OpenSCManager":                      "Services",
    "CreateService":                      "Services",
    "OpenService":                        "Services",
    "StartService":                       "Services",
    "ControlService":                     "Services",
    "ControlServiceEx":                   "Services",
    "DeleteService":                      "Services",
    "CloseServiceHandle":                 "Services",
    "QueryServiceStatus":                 "Services",
    "QueryServiceStatusEx":               "Services",
    "QueryServiceConfig":                 "Services",
    "QueryServiceConfig2":                "Services",
    "ChangeServiceConfig":                "Services",
    "ChangeServiceConfig2":               "Services",
    "EnumServicesStatus":                 "Services",
    "EnumServicesStatusEx":               "Services",
    "EnumDependentServices":              "Services",
    "SetServiceStatus":                   "Services",
    "RegisterServiceCtrlHandler":         "Services",
    "RegisterServiceCtrlHandlerEx":       "Services",
    "StartServiceCtrlDispatcher":         "Services",
    "NotifyBootConfigStatus":             "Services",
    "SetServiceObjectSecurity":           "Services",
    "QueryServiceObjectSecurity":         "Services",
    "GetServiceKeyName":                  "Services",
    "GetServiceDisplayName":              "Services",
    "NotifyServiceStatusChange":          "Services",
}

# ── Files / I-O (extended) ────────────────────────────────
FILEIO_APIS = {
    "CreateFile":                         "FileIO",
    "CreateFile2":                        "FileIO",
    "CreateFileTransacted":               "FileIO",
    "OpenFile":                           "FileIO",
    "ReadFile":                           "FileIO",
    "ReadFileEx":                         "FileIO",
    "ReadFileScatter":                    "FileIO",
    "WriteFile":                          "FileIO",
    "WriteFileEx":                        "FileIO",
    "WriteFileGather":                    "FileIO",
    "CopyFile":                           "FileIO",
    "CopyFile2":                          "FileIO",
    "CopyFileEx":                         "FileIO",
    "CopyFileTransacted":                 "FileIO",
    "MoveFile":                           "FileIO",
    "MoveFileEx":                         "FileIO",
    "MoveFileTransacted":                 "FileIO",
    "MoveFileWithProgress":               "FileIO",
    "DeleteFile":                         "FileIO",
    "DeleteFileTransacted":               "FileIO",
    "ReplaceFile":                        "FileIO",
    "SetEndOfFile":                       "FileIO",
    "SetFilePointer":                     "FileIO",
    "SetFilePointerEx":                   "FileIO",
    "GetFileSize":                        "FileIO",
    "GetFileSizeEx":                      "FileIO",
    "GetFileType":                        "FileIO",
    "GetFileAttributes":                  "FileIO",
    "GetFileAttributesEx":                "FileIO",
    "GetFileAttributesTransacted":        "FileIO",
    "SetFileAttributes":                  "FileIO",
    "SetFileAttributesTransacted":        "FileIO",
    "GetFileInformationByHandle":         "FileIO",
    "GetFileInformationByHandleEx":       "FileIO",
    "SetFileInformationByHandle":         "FileIO",
    "FlushFileBuffers":                   "FileIO",
    "LockFile":                           "FileIO",
    "LockFileEx":                         "FileIO",
    "UnlockFile":                         "FileIO",
    "UnlockFileEx":                       "FileIO",
    "FindFirstFile":                      "FileIO",
    "FindFirstFileEx":                    "FileIO",
    "FindFirstFileTransacted":            "FileIO",
    "FindNextFile":                       "FileIO",
    "FindClose":                          "FileIO",
    "GetTempPath":                        "FileIO",
    "GetTempFileName":                    "FileIO",
    "GetFullPathName":                    "FileIO",
    "GetFullPathNameTransacted":          "FileIO",
    "GetShortPathName":                   "FileIO",
    "GetLongPathName":                    "FileIO",
    "SearchPath":                         "FileIO",
    "CreateHardLink":                     "FileIO",
    "CreateHardLinkTransacted":           "FileIO",
    "CreateSymbolicLink":                 "FileIO",
    "CreateSymbolicLinkTransacted":       "FileIO",
    "GetFinalPathNameByHandle":           "FileIO",
    "CreateIoCompletionPort":             "FileIO",
    "GetQueuedCompletionStatus":          "FileIO",
    "GetQueuedCompletionStatusEx":        "FileIO",
    "PostQueuedCompletionStatus":         "FileIO",
    "CancelIo":                           "FileIO",
    "CancelIoEx":                         "FileIO",
    "EncryptFile":                        "FileIO",
    "DecryptFile":                        "FileIO",
    "FileEncryptionStatus":               "FileIO",
    "OpenEncryptedFileRaw":               "FileIO",
    "ReadEncryptedFileRaw":               "FileIO",
    "WriteEncryptedFileRaw":              "FileIO",
    "CloseEncryptedFileRaw":              "FileIO",
    "NtCreateFile":                       "FileIO",
    "NtOpenFile":                         "FileIO",
    "NtReadFile":                         "FileIO",
    "NtWriteFile":                        "FileIO",
    "NtDeleteFile":                       "FileIO",
    "NtQueryInformationFile":             "FileIO",
    "NtSetInformationFile":               "FileIO",
    "NtQueryDirectoryFile":               "FileIO",
    "NtQueryFullAttributesFile":          "FileIO",
}

# ── Memory Management (extended) ─────────────────────────
MEMORY_APIS = {
    "VirtualAlloc":                       "MemoryMgmt",
    "VirtualAllocEx":                     "MemoryMgmt",
    "VirtualAllocFromApp":                "MemoryMgmt",
    "VirtualAllocExNuma":                 "MemoryMgmt",
    "VirtualFree":                        "MemoryMgmt",
    "VirtualFreeEx":                      "MemoryMgmt",
    "VirtualProtect":                     "MemoryMgmt",
    "VirtualProtectEx":                   "MemoryMgmt",
    "VirtualProtectFromApp":              "MemoryMgmt",
    "VirtualQuery":                       "MemoryMgmt",
    "VirtualQueryEx":                     "MemoryMgmt",
    "VirtualLock":                        "MemoryMgmt",
    "VirtualUnlock":                      "MemoryMgmt",
    "CreateFileMapping":                  "MemoryMgmt",
    "CreateFileMappingFromApp":           "MemoryMgmt",
    "CreateFileMappingNuma":              "MemoryMgmt",
    "OpenFileMapping":                    "MemoryMgmt",
    "MapViewOfFile":                      "MemoryMgmt",
    "MapViewOfFileEx":                    "MemoryMgmt",
    "MapViewOfFileFromApp":               "MemoryMgmt",
    "MapViewOfFileNuma2":                 "MemoryMgmt",
    "UnmapViewOfFile":                    "MemoryMgmt",
    "UnmapViewOfFile2":                   "MemoryMgmt",
    "FlushViewOfFile":                    "MemoryMgmt",
    "HeapCreate":                         "MemoryMgmt",
    "HeapDestroy":                        "MemoryMgmt",
    "HeapAlloc":                          "MemoryMgmt",
    "HeapReAlloc":                        "MemoryMgmt",
    "HeapFree":                           "MemoryMgmt",
    "HeapSize":                           "MemoryMgmt",
    "HeapValidate":                       "MemoryMgmt",
    "HeapWalk":                           "MemoryMgmt",
    "HeapCompact":                        "MemoryMgmt",
    "GetProcessHeap":                     "MemoryMgmt",
    "GetProcessHeaps":                    "MemoryMgmt",
    "GlobalAlloc":                        "MemoryMgmt",
    "GlobalFree":                         "MemoryMgmt",
    "GlobalLock":                         "MemoryMgmt",
    "GlobalUnlock":                       "MemoryMgmt",
    "GlobalReAlloc":                      "MemoryMgmt",
    "GlobalSize":                         "MemoryMgmt",
    "LocalAlloc":                         "MemoryMgmt",
    "LocalFree":                          "MemoryMgmt",
    "LocalLock":                          "MemoryMgmt",
    "LocalUnlock":                        "MemoryMgmt",
    "LocalReAlloc":                       "MemoryMgmt",
    "LocalSize":                          "MemoryMgmt",
    "AllocateUserPhysicalPages":          "MemoryMgmt",
    "FreeUserPhysicalPages":              "MemoryMgmt",
    "MapUserPhysicalPages":               "MemoryMgmt",
    "ReadProcessMemory":                  "MemoryMgmt",
    "WriteProcessMemory":                 "MemoryMgmt",
    "NtAllocateVirtualMemory":            "MemoryMgmt",
    "NtFreeVirtualMemory":                "MemoryMgmt",
    "NtMapViewOfSection":                 "MemoryMgmt",
    "NtUnmapViewOfSection":               "MemoryMgmt",
    "NtReadVirtualMemory":                "MemoryMgmt",
    "NtWriteVirtualMemory":               "MemoryMgmt",
    "NtProtectVirtualMemory":             "MemoryMgmt",
    "NtQueryVirtualMemory":               "MemoryMgmt",
    "NtCreateSection":                    "MemoryMgmt",
    "NtOpenSection":                      "MemoryMgmt",
    "memcpy":                             "MemoryMgmt",
    "memmove":                            "MemoryMgmt",
    "RtlCopyMemory":                      "MemoryMgmt",
    "RtlMoveMemory":                      "MemoryMgmt",
    "RtlFillMemory":                      "MemoryMgmt",
    "RtlZeroMemory":                      "MemoryMgmt",
    "RtlCompareMemory":                   "MemoryMgmt",
    "SecureZeroMemory":                   "MemoryMgmt",
    "GlobalMemoryStatusEx":               "MemoryMgmt",
    "GetPhysicallyInstalledSystemMemory": "MemoryMgmt",
    "GetLargePageMinimum":                "MemoryMgmt",
    "PrefetchVirtualMemory":              "MemoryMgmt",
}

# ── Process and Thread (extended) ────────────────────────
PROCTHREAD_APIS = {
    "CreateProcess":                      "ProcThread",
    "CreateProcessA":                     "ProcThread",
    "CreateProcessW":                     "ProcThread",
    "CreateProcessAsUser":                "ProcThread",
    "CreateProcessWithLogonW":            "ProcThread",
    "CreateProcessWithTokenW":            "ProcThread",
    "OpenProcess":                        "ProcThread",
    "TerminateProcess":                   "ProcThread",
    "ExitProcess":                        "ProcThread",
    "GetCurrentProcess":                  "ProcThread",
    "GetCurrentProcessId":                "ProcThread",
    "GetProcessId":                       "ProcThread",
    "GetProcessIdOfThread":               "ProcThread",
    "GetExitCodeProcess":                 "ProcThread",
    "GetProcessTimes":                    "ProcThread",
    "GetProcessHandleCount":              "ProcThread",
    "GetProcessMitigationPolicy":         "ProcThread",
    "SetProcessMitigationPolicy":         "ProcThread",
    "QueryFullProcessImageName":          "ProcThread",
    "IsWow64Process":                     "ProcThread",
    "CreateThread":                       "ProcThread",
    "CreateRemoteThread":                 "ProcThread",
    "CreateRemoteThreadEx":               "ProcThread",
    "OpenThread":                         "ProcThread",
    "TerminateThread":                    "ProcThread",
    "ExitThread":                         "ProcThread",
    "GetCurrentThread":                   "ProcThread",
    "GetCurrentThreadId":                 "ProcThread",
    "GetThreadId":                        "ProcThread",
    "SuspendThread":                      "ProcThread",
    "ResumeThread":                       "ProcThread",
    "GetThreadContext":                   "ProcThread",
    "SetThreadContext":                   "ProcThread",
    "GetExitCodeThread":                  "ProcThread",
    "GetThreadPriority":                  "ProcThread",
    "SetThreadPriority":                  "ProcThread",
    "GetThreadTimes":                     "ProcThread",
    "QueueUserAPC":                       "ProcThread",
    "WaitForSingleObject":                "ProcThread",
    "WaitForSingleObjectEx":              "ProcThread",
    "WaitForMultipleObjects":             "ProcThread",
    "WaitForMultipleObjectsEx":           "ProcThread",
    "AttachThreadInput":                  "ProcThread",
    "CreateFiber":                        "ProcThread",
    "ConvertThreadToFiber":               "ProcThread",
    "SwitchToFiber":                      "ProcThread",
    "DeleteFiber":                        "ProcThread",
    "NtCreateUserProcess":                "ProcThread",
    "NtOpenProcess":                      "ProcThread",
    "NtTerminateProcess":                 "ProcThread",
    "NtQueryInformationProcess":          "ProcThread",
    "NtSetInformationProcess":            "ProcThread",
    "NtCreateThreadEx":                   "ProcThread",
    "NtOpenThread":                       "ProcThread",
    "NtTerminateThread":                  "ProcThread",
    "NtSuspendThread":                    "ProcThread",
    "NtResumeThread":                     "ProcThread",
    "NtGetContextThread":                 "ProcThread",
    "NtSetContextThread":                 "ProcThread",
    "NtQueueApcThread":                   "ProcThread",
    "NtSuspendProcess":                   "ProcThread",
    "NtResumeProcess":                    "ProcThread",
    "NtDelayExecution":                   "ProcThread",
    "Wow64SuspendThread":                 "ProcThread",
    "NtWow64WriteVirtualMemory64":        "ProcThread",
    "PsSetCreateProcessNotifyRoutine":    "ProcThread",
    "PsSetCreateThreadNotifyRoutine":     "ProcThread",
    "PsSetLoadImageNotifyRoutine":        "ProcThread",
}

# ── Dynamic-Link Libraries ────────────────────────────────
DLL_LOAD_APIS = {
    "LoadLibrary":                        "DllLoad",
    "LoadLibraryA":                       "DllLoad",
    "LoadLibraryW":                       "DllLoad",
    "LoadLibraryEx":                      "DllLoad",
    "LoadLibraryExA":                     "DllLoad",
    "LoadLibraryExW":                     "DllLoad",
    "LoadPackagedLibrary":                "DllLoad",
    "FreeLibrary":                        "DllLoad",
    "FreeLibraryAndExitThread":           "DllLoad",
    "GetProcAddress":                     "DllLoad",
    "GetModuleHandle":                    "DllLoad",
    "GetModuleHandleA":                   "DllLoad",
    "GetModuleHandleW":                   "DllLoad",
    "GetModuleHandleEx":                  "DllLoad",
    "GetModuleFileName":                  "DllLoad",
    "GetModuleFileNameA":                 "DllLoad",
    "GetModuleFileNameW":                 "DllLoad",
    "SetDllDirectory":                    "DllLoad",
    "SetDefaultDllDirectories":           "DllLoad",
    "AddDllDirectory":                    "DllLoad",
    "RemoveDllDirectory":                 "DllLoad",
    "DisableThreadLibraryCalls":          "DllLoad",
    "LdrLoadDll":                         "DllLoad",
    "LdrGetDllHandle":                    "DllLoad",
    "LdrGetProcedureAddress":             "DllLoad",
    "LdrGetProcedureAddressForCaller":    "DllLoad",
}

# ── Hooks ─────────────────────────────────────────────────
HOOKS_APIS = {
    "SetWindowsHookEx":                   "Hooks",
    "SetWindowsHookExA":                  "Hooks",
    "SetWindowsHookExW":                  "Hooks",
    "UnhookWindowsHookEx":                "Hooks",
    "CallNextHookEx":                     "Hooks",
    "SetWinEventHook":                    "Hooks",
    "UnhookWinEvent":                     "Hooks",
    "RtlAddVectoredExceptionHandler":     "Hooks",
    "AddVectoredExceptionHandler":        "Hooks",
    "RemoveVectoredExceptionHandler":     "Hooks",
    "AddVectoredContinueHandler":         "Hooks",
    "RemoveVectoredContinueHandler":      "Hooks",
    "SetUnhandledExceptionFilter":        "Hooks",
}

# ── Keyboard / Mouse Input ────────────────────────────────
INPUT_APIS = {
    "GetAsyncKeyState":                   "Input",
    "GetKeyState":                        "Input",
    "GetKeyboardState":                   "Input",
    "SetKeyboardState":                   "Input",
    "MapVirtualKey":                      "Input",
    "MapVirtualKeyEx":                    "Input",
    "GetKeyNameText":                     "Input",
    "VkKeyScan":                          "Input",
    "VkKeyScanEx":                        "Input",
    "ToAscii":                            "Input",
    "ToUnicode":                          "Input",
    "ToAsciiEx":                          "Input",
    "ToUnicodeEx":                        "Input",
    "RegisterHotKey":                     "Input",
    "UnregisterHotKey":                   "Input",
    "SendInput":                          "Input",
    "keybd_event":                        "Input",
    "mouse_event":                        "Input",
    "BlockInput":                         "Input",
    "GetRawInputData":                    "Input",
    "GetRawInputBuffer":                  "Input",
    "RegisterRawInputDevices":            "Input",
    "GetLastInputInfo":                   "Input",
    "TrackMouseEvent":                    "Input",
    "GetCapture":                         "Input",
    "SetCapture":                         "Input",
    "ReleaseCapture":                     "Input",
    "GetMouseMovePointsEx":               "Input",
    "ActivateKeyboardLayout":             "Input",
    "LoadKeyboardLayout":                 "Input",
    "GetKeyboardLayout":                  "Input",
    "GetKeyboardLayoutList":              "Input",
    "GetKeyboardType":                    "Input",
}

# ── Clipboard ─────────────────────────────────────────────
CLIPBOARD_APIS = {
    "OpenClipboard":                      "Clipboard",
    "CloseClipboard":                     "Clipboard",
    "EmptyClipboard":                     "Clipboard",
    "GetClipboardData":                   "Clipboard",
    "SetClipboardData":                   "Clipboard",
    "IsClipboardFormatAvailable":         "Clipboard",
    "EnumClipboardFormats":               "Clipboard",
    "RegisterClipboardFormat":            "Clipboard",
    "GetClipboardFormatName":             "Clipboard",
    "GetClipboardOwner":                  "Clipboard",
    "GetClipboardSequenceNumber":         "Clipboard",
    "CountClipboardFormats":              "Clipboard",
    "AddClipboardFormatListener":         "Clipboard",
    "RemoveClipboardFormatListener":      "Clipboard",
    "GetPriorityClipboardFormat":         "Clipboard",
    "GetUpdatedClipboardFormats":         "Clipboard",
    "SetClipboardViewer":                 "Clipboard",
    "ChangeClipboardChain":               "Clipboard",
    "GetClipboardViewer":                 "Clipboard",
}

# ── Window Station and Desktop ────────────────────────────
WINSTATION_APIS = {
    "OpenWindowStation":                  "WinStation",
    "CreateWindowStation":                "WinStation",
    "CloseWindowStation":                 "WinStation",
    "EnumWindowStations":                 "WinStation",
    "GetProcessWindowStation":            "WinStation",
    "SetProcessWindowStation":            "WinStation",
    "OpenDesktop":                        "WinStation",
    "CreateDesktop":                      "WinStation",
    "CreateDesktopEx":                    "WinStation",
    "CloseDesktop":                       "WinStation",
    "EnumDesktops":                       "WinStation",
    "EnumDesktopWindows":                 "WinStation",
    "GetThreadDesktop":                   "WinStation",
    "SetThreadDesktop":                   "WinStation",
    "SwitchDesktop":                      "WinStation",
    "OpenInputDesktop":                   "WinStation",
    "GetUserObjectInformation":           "WinStation",
    "SetUserObjectInformation":           "WinStation",
}

# ── COM / OLE ─────────────────────────────────────────────
COM_APIS = {
    "CoCreateInstance":                   "COM",
    "CoCreateInstanceEx":                 "COM",
    "CoCreateInstanceFromApp":            "COM",
    "CoGetClassObject":                   "COM",
    "CoGetObject":                        "COM",
    "CoGetObjectContext":                 "COM",
    "CoInitialize":                       "COM",
    "CoInitializeEx":                     "COM",
    "CoUninitialize":                     "COM",
    "CoInitializeSecurity":               "COM",
    "CoSetProxyBlanket":                  "COM",
    "CoCopyProxy":                        "COM",
    "CoQueryProxyBlanket":                "COM",
    "CoQueryClientBlanket":               "COM",
    "CoImpersonateClient":                "COM",
    "CoRevertToSelf":                     "COM",
    "CoMarshalInterface":                 "COM",
    "CoUnmarshalInterface":               "COM",
    "CoMarshalInterThreadInterfaceInStream": "COM",
    "CoRegisterClassObject":              "COM",
    "CoRevokeClassObject":                "COM",
    "CoLockObjectExternal":               "COM",
    "CoDisconnectObject":                 "COM",
    "CoGetMalloc":                        "COM",
    "CoTaskMemAlloc":                     "COM",
    "CoTaskMemFree":                      "COM",
    "CoTaskMemRealloc":                   "COM",
    "DllGetClassObject":                  "COM",
    "DllRegisterServer":                  "COM",
    "DllUnregisterServer":                "COM",
    "CLSIDFromProgID":                    "COM",
    "CLSIDFromString":                    "COM",
    "ProgIDFromCLSID":                    "COM",
    "StringFromCLSID":                    "COM",
    "StringFromGUID2":                    "COM",
    "CoCreateGuid":                       "COM",
    "OleInitialize":                      "COM",
    "OleUninitialize":                    "COM",
    "OleRun":                             "COM",
    "OleGetClipboard":                    "COM",
    "OleSetClipboard":                    "COM",
    "OleFlushClipboard":                  "COM",
    "DoDragDrop":                         "COM",
    "RegisterDragDrop":                   "COM",
    "RevokeDragDrop":                     "COM",
}

# ── Shell / Windows Shell ─────────────────────────────────
SHELL_APIS = {
    "ShellExecute":                       "Shell",
    "ShellExecuteA":                      "Shell",
    "ShellExecuteW":                      "Shell",
    "ShellExecuteEx":                     "Shell",
    "ShellExecuteExA":                    "Shell",
    "ShellExecuteExW":                    "Shell",
    "SHGetKnownFolderPath":               "Shell",
    "SHGetFolderPath":                    "Shell",
    "SHGetSpecialFolderPath":             "Shell",
    "SHGetSpecialFolderLocation":         "Shell",
    "SHGetPathFromIDList":                "Shell",
    "SHGetPathFromIDListEx":              "Shell",
    "SHFileOperation":                    "Shell",
    "SHCreateDirectoryEx":                "Shell",
    "SHCreateDirectory":                  "Shell",
    "SHEmptyRecycleBin":                  "Shell",
    "SHQueryRecycleBin":                  "Shell",
    "FindExecutable":                     "Shell",
    "CommandLineToArgvW":                 "Shell",
    "CreateProfile":                      "Shell",
    "LoadUserProfile":                    "Shell",
    "UnloadUserProfile":                  "Shell",
    "GetUserProfileDirectory":            "Shell",
    "GetAllUsersProfileDirectory":        "Shell",
    "GetDefaultUserProfileDirectory":     "Shell",
    "GetProfilesDirectory":               "Shell",
    "CreateEnvironmentBlock":             "Shell",
    "DestroyEnvironmentBlock":            "Shell",
    "ExpandEnvironmentStringsForUser":    "Shell",
    "SHGetMalloc":                        "Shell",
    "Shell_NotifyIcon":                   "Shell",
    "SHAddToRecentDocs":                  "Shell",
    "ShellDDEInit":                       "Shell",
    "SHCreateShellItem":                  "Shell",
    "SHCreateItemFromParsingName":        "Shell",
    "SHParseDisplayName":                 "Shell",
    "SHOpenFolderAndSelectItems":         "Shell",
    "SHBrowseForFolder":                  "Shell",
    "PathFileExists":                     "Shell",
    "PathIsDirectory":                    "Shell",
    "PathIsRelative":                     "Shell",
    "PathIsNetworkPath":                  "Shell",
    "PathGetDriveNumber":                 "Shell",
    "PathFindFileName":                   "Shell",
    "PathFindExtension":                  "Shell",
    "PathRemoveExtension":                "Shell",
    "PathRemoveFileSpec":                 "Shell",
    "PathAppend":                         "Shell",
    "PathCombine":                        "Shell",
    "PathGetArgs":                        "Shell",
    "PathQuoteSpaces":                    "Shell",
    "PathUnquoteSpaces":                  "Shell",
    "PathMatchSpec":                      "Shell",
    "UrlIs":                              "Shell",
    "UrlEscape":                          "Shell",
    "UrlUnescape":                        "Shell",
    "UrlCanonicalize":                    "Shell",
    "UrlCombine":                         "Shell",
    "UrlCreateFromPath":                  "Shell",
    "IsValidURL":                         "Shell",
    "StrStr":                             "Shell",
    "StrStrI":                            "Shell",
    "StrChr":                             "Shell",
    "SHRegGetValue":                      "Shell",
}

# ── System Information ────────────────────────────────────
SYSINFO_APIS = {
    "GetSystemInfo":                      "SystemInfo",
    "GetNativeSystemInfo":                "SystemInfo",
    "GetVersionEx":                       "SystemInfo",
    "GetVersion":                         "SystemInfo",
    "RtlGetVersion":                      "SystemInfo",
    "VerifyVersionInfo":                  "SystemInfo",
    "GetWindowsDirectory":                "SystemInfo",
    "GetSystemDirectory":                 "SystemInfo",
    "GetSystemWindowsDirectory":          "SystemInfo",
    "GetSystemWow64Directory":            "SystemInfo",
    "GetComputerName":                    "SystemInfo",
    "GetComputerNameEx":                  "SystemInfo",
    "SetComputerName":                    "SystemInfo",
    "SetComputerNameEx":                  "SystemInfo",
    "GetUserName":                        "SystemInfo",
    "GetUserNameEx":                      "SystemInfo",
    "GetCurrentHwProfile":                "SystemInfo",
    "GetFirmwareEnvironmentVariable":     "SystemInfo",
    "GetFirmwareEnvironmentVariableEx":   "SystemInfo",
    "SetFirmwareEnvironmentVariable":     "SystemInfo",
    "GetSystemFirmwareTable":             "SystemInfo",
    "EnumSystemFirmwareTables":           "SystemInfo",
    "GetFirmwareType":                    "SystemInfo",
    "GetProductInfo":                     "SystemInfo",
    "IsProcessorFeaturePresent":          "SystemInfo",
    "GetSystemMetrics":                   "SystemInfo",
    "SystemParametersInfo":               "SystemInfo",
    "GetTickCount":                       "SystemInfo",
    "GetTickCount64":                     "SystemInfo",
    "QueryPerformanceCounter":            "SystemInfo",
    "QueryPerformanceFrequency":          "SystemInfo",
    "GetSystemTime":                      "SystemInfo",
    "GetSystemTimeAsFileTime":            "SystemInfo",
    "GetLocalTime":                       "SystemInfo",
    "GetTimeZoneInformation":             "SystemInfo",
    "GetEnvironmentVariable":             "SystemInfo",
    "SetEnvironmentVariable":             "SystemInfo",
    "GetEnvironmentStrings":              "SystemInfo",
    "ExpandEnvironmentStrings":           "SystemInfo",
    "GetLogicalDrives":                   "SystemInfo",
    "GetLogicalDriveStrings":             "SystemInfo",
    "GetDriveType":                       "SystemInfo",
    "GetVolumeInformation":               "SystemInfo",
    "GetDiskFreeSpace":                   "SystemInfo",
    "GetDiskFreeSpaceEx":                 "SystemInfo",
    "NtQuerySystemInformation":           "SystemInfo",
    "ZwQuerySystemInformation":           "SystemInfo",
}

# ── Synchronization (extended) ────────────────────────────
SYNC_APIS = {
    "CreateMutex":                        "Synchronization",
    "CreateMutexEx":                      "Synchronization",
    "OpenMutex":                          "Synchronization",
    "ReleaseMutex":                       "Synchronization",
    "CreateSemaphore":                    "Synchronization",
    "CreateSemaphoreEx":                  "Synchronization",
    "OpenSemaphore":                      "Synchronization",
    "ReleaseSemaphore":                   "Synchronization",
    "CreateEvent":                        "Synchronization",
    "CreateEventEx":                      "Synchronization",
    "OpenEvent":                          "Synchronization",
    "SetEvent":                           "Synchronization",
    "ResetEvent":                         "Synchronization",
    "PulseEvent":                         "Synchronization",
    "CreateWaitableTimer":                "Synchronization",
    "CreateWaitableTimerEx":              "Synchronization",
    "OpenWaitableTimer":                  "Synchronization",
    "SetWaitableTimer":                   "Synchronization",
    "SetWaitableTimerEx":                 "Synchronization",
    "CancelWaitableTimer":                "Synchronization",
    "InitializeCriticalSection":          "Synchronization",
    "InitializeCriticalSectionEx":        "Synchronization",
    "EnterCriticalSection":               "Synchronization",
    "LeaveCriticalSection":               "Synchronization",
    "TryEnterCriticalSection":            "Synchronization",
    "DeleteCriticalSection":              "Synchronization",
    "SignalObjectAndWait":                 "Synchronization",
    "MsgWaitForMultipleObjects":          "Synchronization",
    "MsgWaitForMultipleObjectsEx":        "Synchronization",
    "RegisterWaitForSingleObject":        "Synchronization",
    "UnregisterWait":                     "Synchronization",
    "UnregisterWaitEx":                   "Synchronization",
    "QueueUserWorkItem":                  "Synchronization",
    "BindIoCompletionCallback":           "Synchronization",
    "InitializeSListHead":                "Synchronization",
    "InterlockedFlushSList":              "Synchronization",
    "InterlockedPopEntrySList":           "Synchronization",
    "InterlockedPushEntrySList":          "Synchronization",
    "InitOnceExecuteOnce":                "Synchronization",
    "InitOnceBeginInitialize":            "Synchronization",
    "InitOnceComplete":                   "Synchronization",
    "NtCreateMutant":                     "Synchronization",
    "NtOpenMutant":                       "Synchronization",
    "NtReleaseMutant":                    "Synchronization",
    "NtCreateEvent":                      "Synchronization",
    "NtSetEvent":                         "Synchronization",
    "NtResetEvent":                       "Synchronization",
    "NtWaitForSingleObject":              "Synchronization",
    "NtWaitForMultipleObjects":           "Synchronization",
}

# ── Handle and Objects ────────────────────────────────────
HANDLE_APIS = {
    "CloseHandle":                        "HandleObjects",
    "DuplicateHandle":                    "HandleObjects",
    "GetHandleInformation":               "HandleObjects",
    "SetHandleInformation":               "HandleObjects",
    "CompareObjectHandles":               "HandleObjects",
    "NtClose":                            "HandleObjects",
    "NtDuplicateObject":                  "HandleObjects",
    "NtOpenEvent":                        "HandleObjects",
    "ObReferenceObjectByHandle":          "HandleObjects",
    "ObDereferenceObject":                "HandleObjects",
}

# ── Power Management ──────────────────────────────────────
POWER_APIS = {
    "SetSuspendState":                    "PowerMgmt",
    "GetSystemPowerStatus":               "PowerMgmt",
    "GetDevicePowerState":                "PowerMgmt",
    "PowerClearRequest":                  "PowerMgmt",
    "PowerCreateRequest":                 "PowerMgmt",
    "PowerSetRequest":                    "PowerMgmt",
    "SetThreadExecutionState":            "PowerMgmt",
    "CallNtPowerInformation":             "PowerMgmt",
    "PowerGetActiveScheme":               "PowerMgmt",
    "PowerSetActiveScheme":               "PowerMgmt",
    "RegisterSuspendResumeNotification":  "PowerMgmt",
    "UnregisterSuspendResumeNotification": "PowerMgmt",
    "RegisterPowerSettingNotification":   "PowerMgmt",
    "UnregisterPowerSettingNotification": "PowerMgmt",
    "PowerSettingRegisterNotification":   "PowerMgmt",
    "PowerSettingUnregisterNotification": "PowerMgmt",
    "IsSystemResumeAutomatic":            "PowerMgmt",
    "ExitWindowsEx":                      "PowerMgmt",
    "InitiateSystemShutdown":             "PowerMgmt",
    "InitiateSystemShutdownEx":           "PowerMgmt",
    "AbortSystemShutdown":                "PowerMgmt",
}

# ── Pipes ─────────────────────────────────────────────────
PIPES_APIS = {
    "CreatePipe":                         "Pipes",
    "CreateNamedPipe":                    "Pipes",
    "CreateNamedPipeA":                   "Pipes",
    "ConnectNamedPipe":                   "Pipes",
    "DisconnectNamedPipe":                "Pipes",
    "TransactNamedPipe":                  "Pipes",
    "CallNamedPipe":                      "Pipes",
    "PeekNamedPipe":                      "Pipes",
    "GetNamedPipeInfo":                   "Pipes",
    "GetNamedPipeHandleState":            "Pipes",
    "SetNamedPipeHandleState":            "Pipes",
    "WaitNamedPipe":                      "Pipes",
    "ImpersonateNamedPipeClient":         "Pipes",
    "GetNamedPipeClientComputerName":     "Pipes",
    "GetNamedPipeClientProcessId":        "Pipes",
    "GetNamedPipeClientSessionId":        "Pipes",
    "GetNamedPipeServerProcessId":        "Pipes",
    "GetNamedPipeServerSessionId":        "Pipes",
    "NtCreateNamedPipeFile":              "Pipes",
}

# ── Compression API ───────────────────────────────────────
COMPRESSION_APIS = {
    "CreateCompressor":                   "Compression",
    "CloseCompressor":                    "Compression",
    "Compress":                           "Compression",
    "QueryCompressorInformation":         "Compression",
    "SetCompressorInformation":           "Compression",
    "ResetDecompressor":                  "Compression",
    "CreateDecompressor":                 "Compression",
    "CloseDecompressor":                  "Compression",
    "Decompress":                         "Compression",
    "QueryDecompressorInformation":       "Compression",
    "SetDecompressorInformation":         "Compression",
    "RtlDecompressBuffer":                "Compression",
}

# ── CNG (Cryptography Next Generation) ───────────────────
CNG_APIS = {
    "BCryptOpenAlgorithmProvider":        "CNG",
    "BCryptCloseAlgorithmProvider":       "BCryptCloseAlgorithmProvider",
    "BCryptCreateHash":                   "CNG",
    "BCryptDestroyHash":                  "CNG",
    "BCryptHashData":                     "CNG",
    "BCryptFinishHash":                   "CNG",
    "BCryptDuplicateHash":                "CNG",
    "BCryptGenerateKeyPair":              "CNG",
    "BCryptGenerateSymmetricKey":         "CNG",
    "BCryptImportKey":                    "CNG",
    "BCryptImportKeyPair":                "CNG",
    "BCryptExportKey":                    "CNG",
    "BCryptDestroyKey":                   "CNG",
    "BCryptDuplicateKey":                 "CNG",
    "BCryptFinalizeKeyPair":              "CNG",
    "BCryptEncrypt":                      "CNG",
    "BCryptDecrypt":                      "CNG",
    "BCryptSignHash":                     "CNG",
    "BCryptVerifySignature":              "CNG",
    "BCryptSecretAgreement":              "CNG",
    "BCryptDeriveKey":                    "CNG",
    "BCryptDeriveKeyCapi":                "CNG",
    "BCryptDeriveKeyPBKDF2":              "CNG",
    "BCryptGenRandom":                    "CNG",
    "BCryptGetProperty":                  "CNG",
    "BCryptSetProperty":                  "CNG",
    "BCryptEnumAlgorithms":               "CNG",
    "BCryptEnumProviders":                "CNG",
    "BCryptResolveProviders":             "CNG",
    "BCryptFreeBuffer":                   "CNG",
    "NCryptOpenStorageProvider":          "CNG",
    "NCryptOpenKey":                      "CNG",
    "NCryptCreatePersistedKey":           "CNG",
    "NCryptImportKey":                    "CNG",
    "NCryptExportKey":                    "CNG",
    "NCryptEncrypt":                      "CNG",
    "NCryptDecrypt":                      "CNG",
    "NCryptSignHash":                     "CNG",
    "NCryptVerifySignature":              "CNG",
    "NCryptSecretAgreement":              "CNG",
    "NCryptDeriveKey":                    "CNG",
    "NCryptDeleteKey":                    "CNG",
    "NCryptFinalizeKey":                  "CNG",
    "NCryptGetProperty":                  "CNG",
    "NCryptSetProperty":                  "CNG",
    "NCryptFreeObject":                   "CNG",
    "NCryptFreeBuffer":                   "CNG",
    "NCryptEnumStorageProviders":         "CNG",
    "NCryptEnumKeys":                     "CNG",
    "NCryptEnumAlgorithms":               "CNG",
    "NCryptProtectSecret":                "CNG",
    "NCryptUnprotectSecret":              "CNG",
    "NCryptIsAlgSupported":               "CNG",
    "NCryptIsKeyHandle":                  "CNG",
    "NCryptTranslateHandle":              "CNG",
    "NCryptNotifyChangeKey":              "CNG",
}

# ── Network DDE ───────────────────────────────────────────
NET_DDE_APIS = {
    "NDdeShareAdd":                       "NetworkDDE",
    "NDdeShareDel":                       "NetworkDDE",
    "NDdeShareEnum":                      "NetworkDDE",
    "NDdeShareGetInfo":                   "NetworkDDE",
    "NDdeShareSetInfo":                   "NetworkDDE",
    "NDdeGetShareSecurity":               "NetworkDDE",
    "NDdeSetShareSecurity":               "NetworkDDE",
    "NDdeTrustedShareEnum":               "NetworkDDE",
    "NDdeGetTrustedShare":                "NetworkDDE",
    "NDdeSetTrustedShare":                "NetworkDDE",
    "NDdeIsValidAppTopicList":            "NetworkDDE",
    "NDdeIsValidShareName":               "NetworkDDE",
    "NDdeGetErrorString":                 "NetworkDDE",
}

# ── Windows Error Reporting ───────────────────────────────
WER_APIS = {
    "WerRegisterFile":                    "WER",
    "WerRegisterMemoryBlock":             "WER",
    "WerRegisterExcludedMemoryBlock":     "WER",
    "WerRegisterCustomMetadata":          "WER",
    "WerRegisterAdditionalProcess":       "WER",
    "WerRegisterRuntimeExceptionModule":  "WER",
    "WerUnregisterFile":                  "WER",
    "WerUnregisterMemoryBlock":           "WER",
    "WerUnregisterExcludedMemoryBlock":   "WER",
    "WerUnregisterCustomMetadata":        "WER",
    "WerUnregisterAdditionalProcess":     "WER",
    "WerUnregisterRuntimeExceptionModule": "WER",
    "WerReportCreate":                    "WER",
    "WerReportAddFile":                   "WER",
    "WerReportAddDump":                   "WER",
    "WerReportSubmit":                    "WER",
    "WerReportCloseHandle":               "WER",
    "WerReportSetParameter":              "WER",
    "WerReportSetUIOption":               "WER",
    "WerGetFlags":                        "WER",
    "WerSetFlags":                        "WER",
    "WerReportHang":                      "WER",
    "WerAddExcludedApplication":          "WER",
    "WerRemoveExcludedApplication":       "WER",
    "WerStoreOpen":                       "WER",
    "WerStoreClose":                      "WER",
    "WerStoreGetFirstReportKey":          "WER",
    "WerStoreGetNextReportKey":           "WER",
    "WerStoreQueryReportMetadataV2":      "WER",
    "WerFreeString":                      "WER",
}

# ── Device Management ─────────────────────────────────────
DEVICE_APIS = {
    "DeviceIoControl":                    "DeviceMgmt",
    "SetupDiGetClassDevs":                "DeviceMgmt",
    "SetupDiEnumDeviceInfo":              "DeviceMgmt",
    "SetupDiGetDeviceRegistryProperty":   "DeviceMgmt",
    "SetupDiGetDeviceInstanceId":         "DeviceMgmt",
    "SetupDiCreateDevRegKey":             "DeviceMgmt",
    "SetupDiOpenDevRegKey":               "DeviceMgmt",
    "SetupDiDestroyDeviceInfoList":       "DeviceMgmt",
    "SetupDiBuildDriverInfoList":         "DeviceMgmt",
    "SetupDiEnumDriverInfo":              "DeviceMgmt",
    "SetupDiGetSelectedDriver":           "DeviceMgmt",
    "SetupDiCallClassInstaller":          "DeviceMgmt",
    "SetupDiInstallDevice":               "DeviceMgmt",
    "SetupDiRemoveDevice":                "DeviceMgmt",
    "RegisterDeviceNotification":         "DeviceMgmt",
    "UnregisterDeviceNotification":       "DeviceMgmt",
    "CM_Get_Device_ID":                   "DeviceMgmt",
    "CM_Get_DevNode_Status":              "DeviceMgmt",
    "CM_Get_Child":                       "DeviceMgmt",
    "CM_Get_Sibling":                     "DeviceMgmt",
    "CM_Get_Parent":                      "DeviceMgmt",
    "CM_Locate_DevNode":                  "DeviceMgmt",
    "CM_Reenumerate_DevNode":             "DeviceMgmt",
    "NtDeviceIoControlFile":              "DeviceMgmt",
    "NtLoadDriver":                       "DeviceMgmt",
    "NtUnloadDriver":                     "DeviceMgmt",
}

# ── Structured Exception Handling ────────────────────────
SEH_APIS = {
    "RaiseException":                     "SEH",
    "SetUnhandledExceptionFilter":        "SEH",
    "UnhandledExceptionFilter":           "SEH",
    "AddVectoredExceptionHandler":        "SEH",
    "RemoveVectoredExceptionHandler":     "SEH",
    "AddVectoredContinueHandler":         "SEH",
    "RemoveVectoredContinueHandler":      "SEH",
    "RtlAddVectoredExceptionHandler":     "SEH",
    "RtlRemoveVectoredExceptionHandler":  "SEH",
    "RtlAddFunctionTable":                "SEH",
    "RtlDeleteFunctionTable":             "SEH",
    "RtlInstallFunctionTableCallback":    "SEH",
    "RtlAddGrowableFunctionTable":        "SEH",
    "RtlDeleteGrowableFunctionTable":     "SEH",
    "RtlLookupFunctionEntry":             "SEH",
    "RtlVirtualUnwind":                   "SEH",
    "RtlUnwind":                          "SEH",
    "RtlUnwindEx":                        "SEH",
    "RtlCaptureContext":                  "SEH",
    "RtlRestoreContext":                  "SEH",
    "NtRaiseHardError":                   "SEH",
    "KeBugCheckEx":                       "SEH",
}

# ── Application Recovery and Restart ─────────────────────
RECOVERY_APIS = {
    "RegisterApplicationRecoveryCallback": "AppRecovery",
    "UnregisterApplicationRecoveryCallback": "AppRecovery",
    "RegisterApplicationRestart":         "AppRecovery",
    "UnregisterApplicationRestart":       "AppRecovery",
    "ApplicationRecoveryFinished":        "AppRecovery",
    "ApplicationRecoveryInProgress":      "AppRecovery",
    "GetApplicationRecoveryCallback":     "AppRecovery",
    "GetApplicationRestartSettings":      "AppRecovery",
}

# ── Transactional NTFS (TxF) ──────────────────────────────
TXF_APIS = {
    "CreateTransaction":                  "TxF",
    "CommitTransaction":                  "TxF",
    "RollbackTransaction":                "TxF",
    "OpenTransaction":                    "TxF",
    "GetTransactionId":                   "TxF",
    "GetTransactionInformation":          "TxF",
    "SetTransactionInformation":          "TxF",
    "CreateEnlistment":                   "TxF",
    "CommitEnlistment":                   "TxF",
    "RollbackEnlistment":                 "TxF",
    "OpenEnlistment":                     "TxF",
    "PrepareEnlistment":                  "TxF",
    "PrePrepareEnlistment":               "TxF",
    "RecoverEnlistment":                  "TxF",
    "CreateResourceManager":              "TxF",
    "OpenResourceManager":                "TxF",
    "RecoverResourceManager":             "TxF",
    "GetNotificationResourceManager":     "TxF",
    "CreateTransactionManager":           "TxF",
    "OpenTransactionManager":             "TxF",
    "RecoverTransactionManager":          "TxF",
    "RollforwardTransactionManager":      "TxF",
    "RtlSetCurrentTransaction":           "TxF",
    "TxfLogCreateFileReadContext":        "TxF",
    "TxfLogDestroyReadContext":           "TxF",
    "TxfLogReadRecords":                  "TxF",
}

# ── Browser / Script engine (for macro/doc malware) ───────
BROWSER_APIS = {
    "CoCreateInstance":                   "Browser",
    "JsEval":                             "Browser",
    "JsParseScript":                      "Browser",
    "JsRunScript":                        "Browser",
    "CDocument_write":                    "Browser",
    "COleScript_ParseScriptText":         "Browser",
}

# ── Misc C runtime and utility ────────────────────────────
MISC_APIS = {
    "srand":                              "CRuntime",
    "rand":                               "CRuntime",
    "malloc":                             "CRuntime",
    "calloc":                             "CRuntime",
    "realloc":                            "CRuntime",
    "free":                               "CRuntime",
    "memmove":                            "CRuntime",
    "strcpy":                             "CRuntime",
    "strcat":                             "CRuntime",
    "sprintf":                            "CRuntime",
    "vsprintf":                           "CRuntime",
    "system":                             "CRuntime",
    "_popen":                             "CRuntime",
    "_wpopen":                            "CRuntime",
    "WinExec":                            "CRuntime",
    "ExitProcess":                        "CRuntime",
}

# ── Merge all databases into one unified lookup ──────────
ALL_APIS = {}
ALL_APIS.update(MAL_APIS)
ALL_APIS.update(NATIVE_APIS)
ALL_APIS.update(DLL_APIS)
# Extended APIs (new additions — do not alter the three above)
ALL_APIS.update(DEBUGGING_APIS)
ALL_APIS.update(SNAPSHOT_APIS)
ALL_APIS.update(VSS_APIS)
ALL_APIS.update(WININET_APIS)
ALL_APIS.update(WINHTTP_APIS)
ALL_APIS.update(NETMGMT_APIS)
ALL_APIS.update(IPHELPER_APIS)
ALL_APIS.update(AUTHZ_APIS)
ALL_APIS.update(ETW_APIS)
ALL_APIS.update(REGISTRY_APIS)
ALL_APIS.update(SERVICES_APIS)
ALL_APIS.update(FILEIO_APIS)
ALL_APIS.update(MEMORY_APIS)
ALL_APIS.update(PROCTHREAD_APIS)
ALL_APIS.update(DLL_LOAD_APIS)
ALL_APIS.update(HOOKS_APIS)
ALL_APIS.update(INPUT_APIS)
ALL_APIS.update(CLIPBOARD_APIS)
ALL_APIS.update(WINSTATION_APIS)
ALL_APIS.update(COM_APIS)
ALL_APIS.update(SHELL_APIS)
ALL_APIS.update(SYSINFO_APIS)
ALL_APIS.update(SYNC_APIS)
ALL_APIS.update(HANDLE_APIS)
ALL_APIS.update(POWER_APIS)
ALL_APIS.update(PIPES_APIS)
ALL_APIS.update(COMPRESSION_APIS)
ALL_APIS.update(CNG_APIS)
ALL_APIS.update(NET_DDE_APIS)
ALL_APIS.update(WER_APIS)
ALL_APIS.update(DEVICE_APIS)
ALL_APIS.update(SEH_APIS)
ALL_APIS.update(RECOVERY_APIS)
ALL_APIS.update(TXF_APIS)
ALL_APIS.update(BROWSER_APIS)
ALL_APIS.update(MISC_APIS)

# ── Colour palette per category ───────────────────────────
CATEGORY_COLORS = {
    # original categories
    "Enumeration":    ("#1a3a5c", "#7ec8e3"),
    "Injection":      ("#5c1a1a", "#f4a4a4"),
    "Evasion":        ("#3a1a5c", "#c9b3f5"),
    "Spying":         ("#5c3a1a", "#f5c97a"),
    "Internet":       ("#1a4a4a", "#7ee8e8"),
    "Anti-Debugging": ("#4a4a1a", "#e8e87e"),
    "Ransomware":     ("#5c1a3a", "#f5a4c9"),
    "Helper":         ("#1a4a2a", "#7ef5a4"),
    # native NT categories
    "Native-Memory":  ("#2a1a4a", "#b09af5"),
    "Native-File":    ("#1a3a2a", "#8af5c0"),
    "Native-Process": ("#4a2a1a", "#f5b07a"),
    "Native-Thread":  ("#1a2a4a", "#7ab0f5"),
    "Native-Handle":  ("#3a3a1a", "#f5f07a"),
    "Native-System":  ("#1a4a4a", "#7af5f0"),
    "Native-Registry":("#4a1a4a", "#f57af5"),
    "Native-Security":("#4a1a1a", "#f57a7a"),
    "Native-Driver":  ("#1a1a1a", "#c0c0c0"),
    "Native-Device":  ("#2a3a1a", "#b0f57a"),
    "Native-Sync":    ("#1a3a4a", "#7acff5"),
    "Native-Timer":   ("#3a2a1a", "#f5c07a"),
    # DLL categories
    "ADVAPI32":       ("#1e2a3a", "#7ab8f5"),
    "AMSI":           ("#3a1e1e", "#f59090"),
    "DBGHELP":        ("#2a2a1e", "#f5e87a"),
    "DNSAPI":         ("#1e3a3a", "#7af5f5"),
    "FWPUCLNT":       ("#2a1e3a", "#c07af5"),
    "KERNEL32":       ("#3a1e2a", "#f57ab8"),
    "MPR":            ("#1e3a2a", "#7af5b0"),
    "NETAPI32":       ("#3a2a1e", "#f5b87a"),
    "NTDLL":          ("#1e1e3a", "#7a7af5"),
    "OLE32":          ("#3a3a1e", "#f5f07a"),
    "PSAPI":          ("#1e3a1e", "#7af57a"),
    "RASAPI32":       ("#3a1e3a", "#f57af5"),
    "SETUPAPI":       ("#2a3a1e", "#b0f57a"),
    "SHELL32":        ("#1e2a3a", "#7ab0f5"),
    "UIAUTOMATION":   ("#2a1e1e", "#f5907a"),
    "URLMON":         ("#1e3a2a", "#7af5b8"),
    "USER32":         ("#3a2a2a", "#f5b0a0"),
    "WINHTTP":        ("#1e2a2a", "#7adada"),
    "WINSTA":         ("#2a2a3a", "#a0a0f5"),
    # Extended new categories
    "Debugging":      ("#2a1a2a", "#e090e0"),
    "ProcessSnapshot":("#1a2a3a", "#80c0f0"),
    "VolumeShadow":   ("#3a2a3a", "#d090d0"),
    "WinINet":        ("#1a3a4a", "#70d0e0"),
    "WinHTTP":        ("#1a2a4a", "#60b0f0"),
    "NetManagement":  ("#3a3a2a", "#e0e060"),
    "IPHelper":       ("#2a3a3a", "#70e0d0"),
    "Authorization":  ("#4a1a2a", "#f060a0"),
    "EventLog":       ("#3a1a3a", "#d060d0"),
    "EventTrace":     ("#2a1a3a", "#b060f0"),
    "Registry":       ("#2a3a2a", "#90e090"),
    "Services":       ("#3a2a2a", "#f0a070"),
    "FileIO":         ("#1a3a3a", "#70e0e0"),
    "MemoryMgmt":     ("#2a2a3a", "#a0a0f0"),
    "ProcThread":     ("#4a2a2a", "#f09080"),
    "DllLoad":        ("#3a1a4a", "#c080f0"),
    "Hooks":          ("#4a3a1a", "#f0d060"),
    "Input":          ("#3a4a1a", "#c0f060"),
    "Clipboard":      ("#1a4a3a", "#60f0c0"),
    "WinStation":     ("#2a4a2a", "#80f080"),
    "COM":            ("#4a4a2a", "#e0e080"),
    "Shell":          ("#2a4a4a", "#80e0e0"),
    "SystemInfo":     ("#4a2a4a", "#e080e0"),
    "Synchronization":("#3a4a3a", "#a0f0a0"),
    "HandleObjects":  ("#4a4a4a", "#c0c0c0"),
    "PowerMgmt":      ("#4a3a2a", "#f0b080"),
    "Pipes":          ("#2a4a1a", "#90f070"),
    "Compression":    ("#1a4a2a", "#70f090"),
    "CNG":            ("#3a2a4a", "#c0a0f0"),
    "NetworkDDE":     ("#4a2a3a", "#f0a0c0"),
    "WER":            ("#3a3a4a", "#b0b0f0"),
    "DeviceMgmt":     ("#2a3a4a", "#90b0f0"),
    "SEH":            ("#4a1a3a", "#f060c0"),
    "AppRecovery":    ("#1a4a4a", "#60f0e0"),
    "TxF":            ("#3a4a4a", "#a0f0f0"),
    "Browser":        ("#4a4a1a", "#f0f060"),
    "CRuntime":       ("#3a3a3a", "#c0c0a0"),
}

# ── group labels shown in the DB tab ─────────────────────
DB_GROUPS = {
    "Win32 APIs":           MAL_APIS,
    "Native NT APIs":       NATIVE_APIS,
    "DLL-Classified APIs":  DLL_APIS,
    # Extended groups
    "Debugging":            DEBUGGING_APIS,
    "Process Snapshotting": SNAPSHOT_APIS,
    "Volume Shadow Copy":   VSS_APIS,
    "WinINet":              WININET_APIS,
    "WinHTTP":              WINHTTP_APIS,
    "Net Management":       NETMGMT_APIS,
    "IP Helper":            IPHELPER_APIS,
    "Authorization":        AUTHZ_APIS,
    "Event Logging":        ETW_APIS,
    "Registry":             REGISTRY_APIS,
    "Services":             SERVICES_APIS,
    "File I/O":             FILEIO_APIS,
    "Memory Management":    MEMORY_APIS,
    "Process & Thread":     PROCTHREAD_APIS,
    "DLL Loading":          DLL_LOAD_APIS,
    "Hooks":                HOOKS_APIS,
    "Input Devices":        INPUT_APIS,
    "Clipboard":            CLIPBOARD_APIS,
    "Window Station":       WINSTATION_APIS,
    "COM / OLE":            COM_APIS,
    "Windows Shell":        SHELL_APIS,
    "System Information":   SYSINFO_APIS,
    "Synchronization":      SYNC_APIS,
    "Handles & Objects":    HANDLE_APIS,
    "Power Management":     POWER_APIS,
    "Pipes":                PIPES_APIS,
    "Compression API":      COMPRESSION_APIS,
    "CNG":                  CNG_APIS,
    "Network DDE":          NET_DDE_APIS,
    "WER":                  WER_APIS,
    "Device Management":    DEVICE_APIS,
    "SEH":                  SEH_APIS,
    "App Recovery":         RECOVERY_APIS,
    "TxF":                  TXF_APIS,
    "Browser / Script":     BROWSER_APIS,
    "C Runtime":            MISC_APIS,
}


# ══════════════════════════════════════════════════════════
#  SCANNER
# ══════════════════════════════════════════════════════════
def scan_binary():
    results = {}

    import_map = {}
    for i in range(idaapi.get_import_module_qty()):
        mod = idaapi.get_import_module_name(i)
        if not mod:
            continue
        def imp_cb(ea, name, ord_):
            if name:
                import_map[name.lower().lstrip("_")] = (ea, name)
            return True
        idaapi.enum_import_names(i, imp_cb)

    ea_to_api = {}
    for api, cat in ALL_APIS.items():
        low = api.lower().lstrip("_")
        if low in import_map:
            imp_ea, _ = import_map[low]
            ea_to_api[imp_ea] = (api, cat)

    for api, cat in ALL_APIS.items():
        ea = idc.get_name_ea_simple(api)
        if ea != idaapi.BADADDR and ea not in ea_to_api:
            ea_to_api[ea] = (api, cat)

    for imp_ea, (api, cat) in ea_to_api.items():
        for xref in idautils.XrefsTo(imp_ea, 0):
            call_ea = xref.frm
            func = ida_funcs.get_func(call_ea)
            if not func:
                continue
            func_ea = func.start_ea
            results.setdefault(func_ea, [])
            results[func_ea].append({"api": api, "category": cat, "call_ea": call_ea})

    return results


def highlight_instruction(ea, color=IDA_HIGHLIGHT_COLOR):
    idc.set_color(ea, idc.CIC_ITEM, color)


def clear_highlights(ea_list):
    for ea in ea_list:
        idc.set_color(ea, idc.CIC_ITEM, 0xFFFFFFFF)


# ══════════════════════════════════════════════════════════
#  STYLES
# ══════════════════════════════════════════════════════════
DARK_BG    = "#1c1c1c"
PANEL_BG   = "#242424"
BORDER     = "#333333"
TEXT_MAIN  = "#d4d4d4"
TEXT_DIM   = "#707070"
ACCENT     = "#4a90d9"
BTN_SCAN   = "#c0392b"
BTN_CLEAR  = "#34495e"
ALT_ROW    = "#202020"

BASE_STYLE = f"""
QWidget               {{ background:{DARK_BG}; color:{TEXT_MAIN}; font-family:'Consolas','Courier New',monospace; font-size:12px; }}
QFrame                {{ background:{PANEL_BG}; border:1px solid {BORDER}; border-radius:4px; }}
QLineEdit             {{ background:#2a2a2a; border:1px solid {BORDER}; border-radius:3px; padding:3px 6px; color:{TEXT_MAIN}; }}
QLineEdit:focus       {{ border:1px solid {ACCENT}; }}
QComboBox             {{ background:#2a2a2a; border:1px solid {BORDER}; border-radius:3px; padding:2px 6px; color:{TEXT_MAIN}; }}
QComboBox QAbstractItemView {{ background:#2a2a2a; selection-background-color:{ACCENT}; }}
QTabWidget::pane      {{ border:1px solid {BORDER}; background:{PANEL_BG}; }}
QTabBar::tab          {{ background:#2a2a2a; color:{TEXT_DIM}; padding:5px 14px; border:1px solid {BORDER}; border-bottom:none; border-radius:3px 3px 0 0; margin-right:2px; }}
QTabBar::tab:selected {{ background:{PANEL_BG}; color:{TEXT_MAIN}; border-bottom:2px solid {ACCENT}; }}
QTableWidget          {{ background:{DARK_BG}; gridline-color:{BORDER}; color:{TEXT_MAIN}; selection-background-color:#2d4a6a; border:none; }}
QTableWidget::item:alternate {{ background:{ALT_ROW}; }}
QHeaderView::section  {{ background:#2a2a2a; color:{ACCENT}; padding:4px; border:none; border-right:1px solid {BORDER}; font-weight:bold; }}
QTreeWidget           {{ background:{DARK_BG}; color:{TEXT_MAIN}; border:none; }}
QTreeWidget::item:hover       {{ background:#2d3d4d; }}
QTreeWidget::item:selected    {{ background:#2d4a6a; }}
QScrollBar:vertical   {{ background:#1c1c1c; width:8px; border-radius:4px; }}
QScrollBar::handle:vertical {{ background:#444; border-radius:4px; min-height:20px; }}
QSplitter::handle     {{ background:{BORDER}; }}
QPushButton           {{ border-radius:3px; padding:4px 12px; font-weight:bold; border:none; }}
QPushButton:hover     {{ opacity:0.85; }}
"""

def make_btn(label, bg, fg="#ffffff"):
    b = QtWidgets.QPushButton(label)
    b.setStyleSheet(f"QPushButton{{background:{bg};color:{fg};border-radius:3px;padding:4px 12px;font-weight:bold;border:none;}}"
                    f"QPushButton:hover{{background:{bg}cc;}}")
    b.setFixedHeight(28)
    return b

def cat_badge(cat):
    bg, fg = CATEGORY_COLORS.get(cat, ("#333", "#ccc"))
    lbl = QtWidgets.QLabel(f" {cat} ")
    lbl.setStyleSheet(f"background:{bg};color:{fg};border-radius:3px;font-size:10px;padding:1px 5px;")
    lbl.setFixedHeight(18)
    return lbl


# ══════════════════════════════════════════════════════════
#  MAIN WIDGET
# ══════════════════════════════════════════════════════════
class MalAPIWidget(ida_kernwin.PluginForm):

    COLS = ["Function", "Call Address", "API Name", "Category", "Hits"]

    def __init__(self):
        super().__init__()
        self._results        = {}
        self._highlight_eas  = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.parent.setStyleSheet(BASE_STYLE)
        self._build_ui()

    def OnClose(self, form):
        pass

    # ── layout ────────────────────────────────────────────
    def _build_ui(self):
        root = QtWidgets.QVBoxLayout()
        root.setSpacing(6)
        root.setContentsMargins(8, 8, 8, 8)

        # header bar
        header = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel("MalAPI Hunter")
        title.setStyleSheet(f"font-size:15px;font-weight:bold;color:{ACCENT};")
        ver   = QtWidgets.QLabel(f"v{PLUGIN_VERSION}")
        ver.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        header.addWidget(title)
        header.addWidget(ver)
        header.addStretch()

        self.status_lbl = QtWidgets.QLabel("Ready — press Scan to begin.")
        self.status_lbl.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        header.addWidget(self.status_lbl)

        # control bar
        ctrl = QtWidgets.QHBoxLayout()
        self.scan_btn  = make_btn("▶  Scan", BTN_SCAN)
        self.clear_btn = make_btn("✕  Clear", BTN_CLEAR)
        self.scan_btn.clicked.connect(self._on_scan)
        self.clear_btn.clicked.connect(self._on_clear)

        self.search_box = QtWidgets.QLineEdit()
        self.search_box.setPlaceholderText("Search function / API / category…")
        self.search_box.setFixedHeight(28)
        self.search_box.textChanged.connect(self._apply_filter)

        self.cat_combo = QtWidgets.QComboBox()
        self.cat_combo.setFixedHeight(28)
        self.cat_combo.setFixedWidth(180)
        self.cat_combo.addItem("All Categories")
        for cat in sorted(CATEGORY_COLORS.keys()):
            self.cat_combo.addItem(cat)
        self.cat_combo.currentTextChanged.connect(self._apply_filter)

        ctrl.addWidget(self.scan_btn)
        ctrl.addWidget(self.clear_btn)
        ctrl.addSpacing(8)
        ctrl.addWidget(self.search_box)
        ctrl.addWidget(self.cat_combo)

        # tabs
        self.tabs = QtWidgets.QTabWidget()
        self.tabs.addTab(self._build_results_tab(), "Results")
        self.tabs.addTab(self._build_db_tab(),      "API Database")

        root.addLayout(header)
        root.addLayout(ctrl)
        root.addWidget(self.tabs)
        self.parent.setLayout(root)

    # ── Results tab ───────────────────────────────────────
    def _build_results_tab(self):
        w = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout(w)
        v.setContentsMargins(0, 6, 0, 0)
        v.setSpacing(4)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        # left: table
        self.table = QtWidgets.QTableWidget(0, len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        hh.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
        hh.setDefaultSectionSize(110)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setDefaultSectionSize(20)
        self.table.verticalHeader().setVisible(False)
        self.table.clicked.connect(self._on_row_click)
        self.table.doubleClicked.connect(self._on_row_dbl)
        splitter.addWidget(self.table)

        # right: detail
        detail = QtWidgets.QWidget()
        detail.setMinimumWidth(280)
        dv = QtWidgets.QVBoxLayout(detail)
        dv.setContentsMargins(6, 0, 0, 0)
        dv.setSpacing(4)

        self.d_title = QtWidgets.QLabel("Select a row")
        self.d_title.setStyleSheet(f"color:{ACCENT};font-weight:bold;font-size:12px;")
        self.d_title.setWordWrap(True)

        self.d_tree = QtWidgets.QTreeWidget()
        self.d_tree.setHeaderLabels(["Category / API", "Address"])
        self.d_tree.setColumnWidth(0, 190)
        self.d_tree.itemDoubleClicked.connect(self._on_tree_dbl)

        self.d_stats = QtWidgets.QLabel("")
        self.d_stats.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        self.d_stats.setWordWrap(True)

        dv.addWidget(self.d_title)
        dv.addWidget(self.d_tree)
        dv.addWidget(self.d_stats)
        splitter.addWidget(detail)
        splitter.setSizes([680, 300])

        v.addWidget(splitter)
        return w

    # ── DB browser tab ────────────────────────────────────
    def _build_db_tab(self):
        w = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout(w)
        v.setContentsMargins(0, 6, 0, 0)

        db_filter = QtWidgets.QLineEdit()
        db_filter.setPlaceholderText("Filter API database…")
        db_filter.setFixedHeight(26)

        self.db_tree = QtWidgets.QTreeWidget()
        self.db_tree.setHeaderLabels(["API Name", "Category / DLL", "Source"])
        self.db_tree.setColumnWidth(0, 260)
        self.db_tree.setColumnWidth(1, 160)
        self.db_tree.setAlternatingRowColors(True)

        for group_label, db in DB_GROUPS.items():
            root_item = QtWidgets.QTreeWidgetItem([group_label, "", f"{len(db)} entries"])
            root_item.setForeground(0, QtGui.QColor(ACCENT))
            root_item.setFont(0, QtGui.QFont("Consolas", 11, QtGui.QFont.Bold))
            self.db_tree.addTopLevelItem(root_item)
            for api, cat in sorted(db.items()):
                bg, fg = CATEGORY_COLORS.get(cat, ("#333", "#ccc"))
                child = QtWidgets.QTreeWidgetItem([api, cat, group_label])
                child.setForeground(0, QtGui.QColor(TEXT_MAIN))
                child.setBackground(1, QtGui.QColor(bg))
                child.setForeground(1, QtGui.QColor(fg))
                root_item.addChild(child)

        def db_search(text):
            t = text.lower()
            for i in range(self.db_tree.topLevelItemCount()):
                grp = self.db_tree.topLevelItem(i)
                for j in range(grp.childCount()):
                    ch = grp.child(j)
                    match = t in ch.text(0).lower() or t in ch.text(1).lower()
                    ch.setHidden(not match if t else False)

        db_filter.textChanged.connect(db_search)

        lbl = QtWidgets.QLabel(f"  Total: {len(ALL_APIS)} APIs across {len(DB_GROUPS)} groups")
        lbl.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")

        v.addWidget(db_filter)
        v.addWidget(self.db_tree)
        v.addWidget(lbl)
        return w

    # ── scan ──────────────────────────────────────────────
    def _on_scan(self):
        self.status_lbl.setText("Scanning binary…")
        QtWidgets.QApplication.processEvents()
        self._on_clear()
        self._results = scan_binary()
        for hits in self._results.values():
            for h in hits:
                highlight_instruction(h["call_ea"])
                self._highlight_eas.append(h["call_ea"])
        self._populate_table()
        nf = len(self._results)
        nh = sum(len(v) for v in self._results.values())
        self.status_lbl.setText(f"{nh} hit(s) in {nf} function(s)")

    def _on_clear(self):
        clear_highlights(self._highlight_eas)
        self._highlight_eas = []

    # ── table ─────────────────────────────────────────────
    def _populate_table(self, ft="", fc="All Categories"):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for func_ea, hits in self._results.items():
            fname = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
            for h in hits:
                api, cat, call_ea = h["api"], h["category"], h["call_ea"]
                if ft and ft not in fname.lower() and ft not in api.lower() and ft not in cat.lower():
                    continue
                if fc != "All Categories" and cat != fc:
                    continue
                row = self.table.rowCount()
                self.table.insertRow(row)
                items = [
                    QtWidgets.QTableWidgetItem(fname),
                    QtWidgets.QTableWidgetItem(f"0x{call_ea:X}"),
                    QtWidgets.QTableWidgetItem(api),
                    QtWidgets.QTableWidgetItem(cat),
                    QtWidgets.QTableWidgetItem(str(len(hits))),
                ]
                items[0].setData(QtCore.Qt.UserRole, func_ea)
                items[1].setData(QtCore.Qt.UserRole, call_ea)
                bg, fg = CATEGORY_COLORS.get(cat, ("#333", "#ccc"))
                items[3].setBackground(QtGui.QColor(bg))
                items[3].setForeground(QtGui.QColor(fg))
                items[3].setFont(QtGui.QFont("Consolas", 10, QtGui.QFont.Bold))
                items[4].setForeground(QtGui.QColor(TEXT_DIM))
                for col, item in enumerate(items):
                    self.table.setItem(row, col, item)
        self.table.setSortingEnabled(True)

    def _apply_filter(self):
        self._populate_table(self.search_box.text(), self.cat_combo.currentText())

    # ── row events ────────────────────────────────────────
    def _on_row_click(self, idx):
        item = self.table.item(idx.row(), 0)
        if item:
            self._show_detail(item.data(QtCore.Qt.UserRole))

    def _on_row_dbl(self, idx):
        col  = idx.column()
        item = self.table.item(idx.row(), 1 if col != 2 else 2)
        if item:
            ea = item.data(QtCore.Qt.UserRole)
            if ea:
                ida_kernwin.jumpto(ea)

    # ── detail panel ──────────────────────────────────────
    def _show_detail(self, func_ea):
        hits = self._results.get(func_ea, [])
        if not hits:
            return
        fname = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
        self.d_title.setText(f"{fname}  @  0x{func_ea:X}")
        self.d_tree.clear()
        by_cat = {}
        for h in hits:
            by_cat.setdefault(h["category"], []).append(h)
        for cat, cat_hits in sorted(by_cat.items()):
            bg, fg = CATEGORY_COLORS.get(cat, ("#333", "#ccc"))
            p = QtWidgets.QTreeWidgetItem([f"{cat}  ({len(cat_hits)})", ""])
            p.setBackground(0, QtGui.QColor(bg))
            p.setForeground(0, QtGui.QColor(fg))
            p.setFont(0, QtGui.QFont("Consolas", 10, QtGui.QFont.Bold))
            self.d_tree.addTopLevelItem(p)
            for h in cat_hits:
                c = QtWidgets.QTreeWidgetItem([h["api"], f"0x{h['call_ea']:X}"])
                c.setData(0, QtCore.Qt.UserRole, h["call_ea"])
                c.setForeground(0, QtGui.QColor(TEXT_MAIN))
                c.setForeground(1, QtGui.QColor("#f5c542"))
                p.addChild(c)
            p.setExpanded(True)
        cats_summary = "  ".join(f"{c}:{len(v)}" for c, v in sorted(by_cat.items()))
        self.d_stats.setText(f"Total {len(hits)} calls  |  {cats_summary}")

    def _on_tree_dbl(self, item, _col):
        ea = item.data(0, QtCore.Qt.UserRole)
        if ea:
            ida_kernwin.jumpto(ea)


# ══════════════════════════════════════════════════════════
#  PLUGIN ENTRY
# ══════════════════════════════════════════════════════════
class MalAPIHunterPlugin(idaapi.plugin_t):
    flags         = idaapi.PLUGIN_KEEP
    comment       = "Detect & highlight malicious/suspicious API usage"
    help          = f"Press {PLUGIN_HOTKEY} to open MalAPI Hunter"
    wanted_name   = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        print(f"[{PLUGIN_NAME}] v{PLUGIN_VERSION} loaded — {PLUGIN_HOTKEY} to open")
        self._widget = None
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        if self._widget is None:
            self._widget = MalAPIWidget()
        self._widget.Show(
            PLUGIN_NAME,
            options=(ida_kernwin.PluginForm.WOPN_TAB |
                     ida_kernwin.PluginForm.WOPN_PERSIST))

    def term(self):
        pass


def PLUGIN_ENTRY():
    return MalAPIHunterPlugin()
