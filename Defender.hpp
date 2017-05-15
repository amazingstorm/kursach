#include <iostream>
#include <string>
#include "windows.h"
#include "conio.h"
#include <tchar.h>
#include <tlhelp32.h>
#include <time.h>
#include <WinUser.h>
#include <stdio.h>
#include <stdlib.h>
#include <Psapi.h>

// RtlQueryProcessDebugInformation
#define WIN32_LEAN_AND_MEAN

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"psapi.lib")
#pragma comment(lib,"user32.lib")

//CsrGetProcessId
typedef DWORD_PTR ( NTAPI *CGPID )( );
typedef DWORD_PTR ( NTAPI *DBGBREAKPOINT ) ();

//work anti debuggers
void dbg()
{
	if(IsDebuggerPresent())
	{
		MessageBox(NULL, TEXT("Please close your debugging application and restart the program"), 
				   TEXT("Debugger Found!"), 0);
		ExitProcess(0);
	}
}

void dbg1()
{
	char IsDbgPresent = 0;
	__asm {
		 mov eax, fs:[30h]
		 mov al, [eax + 2h]
		 mov IsDbgPresent, al
}
	if(IsDbgPresent)
	{
		MessageBox(NULL, TEXT("Please close your debugging pplication and restart the program"), 
				   TEXT("Debugger Found!"), 0);
		ExitProcess(0);
	}
}

void dbg3()
{
	// Function Pointer Typedef for NtQueryInformationProcess
typedef unsigned long (__stdcall *pfnNtQueryInformationProcess)(IN  HANDLE, 
        IN  unsigned int, OUT PVOID, IN ULONG, OUT PULONG);

 
// ProcessDebugPort
const int ProcessDbgPort = 7;
 
// We have to import the function
pfnNtQueryInformationProcess NtQueryInfoProcess = NULL;
 
// Other Vars
unsigned long Ret;
unsigned long IsRemotePresent = 0;
 
HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
if(hNtDll == NULL)
{
    // Handle however.. chances of this failing
    // is essentially 0 however since
    // ntdll.dll is a vital system resource
}
 
NtQueryInfoProcess = (pfnNtQueryInformationProcess)
   GetProcAddress(hNtDll, "NtQueryInformationProcess");
if(NtQueryInfoProcess == NULL)
{
    // Handle however it fits your needs but as before,
    // if this is missing there are some SERIOUS issues with the OS
}
 
// Time to finally make the call
Ret = NtQueryInfoProcess(GetCurrentProcess(), ProcessDbgPort, 
      &IsRemotePresent, sizeof(unsigned long), NULL);
if(Ret == 0x00000000 && IsRemotePresent != 0)
{
    // Debugger is present
    MessageBox(NULL, TEXT("Please close your debugging pplication and restart the program"), 
               TEXT("Debugger Found!"), 0);
    ExitProcess(0);
}
}

void dbg4()
{
	unsigned long NtGlobalFlags = 0;

__asm {

    mov eax, fs:[30h]
    mov eax, [eax + 68h]
    mov NtGlobalFlags, eax
}

if(NtGlobalFlags & 0x70)
// 0x70 =  FLG_HEAP_ENABLE_TAIL_CHECK |
//         FLG_HEAP_ENABLE_FREE_CHECK | 
//         FLG_HEAP_VALIDATE_PARAMETERS
{
    // Debugger is present
    MessageBox(NULL, TEXT("Please close your debugging pplication and restart the program"), 
               TEXT("Debugger Found!"), 0);
    ExitProcess(0);
}
// Normal execution
}

void dbg5()
{
	BOOL IsDbgPresent = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &IsDbgPresent);
if(IsDbgPresent)
{
        MessageBox(NULL, TEXT("Please close your debugging application and restart the program"), 
                   TEXT("Debugger Found!"), 0);
        ExitProcess(0);
}
// Normal Execution
}
//work anti debagguers

//for ollydebug
void pOutputDebugString() {
	OutputDebugString(_T("%s%s%s%s%s%s%s%s%s")); // crashed OllyDBG 1.10
}
//for ollydebug

//disasm
inline bool Int2DCheck()
{
    __try
    {
        __asm
        {
            int 0x2d
            xor eax, eax
            add eax, 2
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
    
    return true;
}

//disasm

