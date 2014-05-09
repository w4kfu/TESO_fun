#include <stdio.h>
#include <Windows.h>


void create_warpatch_process(char *name, char *dll_name)
{
	STARTUPINFOA		si;
	PROCESS_INFORMATION pi;
	DWORD				Addr;
	HANDLE				hThread;
	HMODULE				hKernel32;

	hKernel32 = GetModuleHandleA("kernel32.dll");
	memset(&si, 0, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));
	if (!CreateProcessA(name, 0, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi))
	{
		printf("[-] CreateProcessA() failed : %s is correct ? LastError : %x\n", name, GetLastError());
		exit(EXIT_FAILURE);
	}
	Addr = (DWORD)VirtualAllocEx(pi.hProcess, 0, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (Addr == NULL)
	{
		printf("[-] VirtualAllocEx failed(), LastError : %x\n", GetLastError());
		TerminateProcess(pi.hProcess, 42);
		exit(EXIT_FAILURE);
	}

	WriteProcessMemory(pi.hProcess, (LPVOID)Addr, (void*)dll_name, strlen(dll_name), NULL);
	hThread = CreateRemoteThread(pi.hProcess, NULL, 0,
				(LPTHREAD_START_ROUTINE)::GetProcAddress(hKernel32,"LoadLibraryA"), 
				(LPVOID)Addr, 0, NULL);
	//WaitForSingleObject(hThread, INFINITE);
	ResumeThread(pi.hThread);
	CloseHandle(hThread);
}

int main(int argc, char **argv)
{
	PVOID OldValue = NULL;

	if (argc != 3)
	{
		printf("Usage : %s <target.exe> <dll_name.dll>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	//Wow64DisableWow64FsRedirection(&OldValue);
	create_warpatch_process(argv[1], argv[2]);
	return (0);
}