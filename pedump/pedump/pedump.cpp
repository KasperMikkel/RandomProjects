#include "funcs.h"

int main(int argc, char* argv[]) {

	NEWL;

	/* --- Check user arguments ---*/
	if (argc < 2) {
		std::cout << "Error. Please input a file!" << std::endl;
		return 1;
	}
	if (!fileExist(argv[1])) {
		std::cout << "Error. " << argv[1] << " not found!" << std::endl;
		return 1;
	}


	/* --- Variables --- */
	DWORD fileType;
	FILE *file;
	LPVOID lpFile;
	IMAGE_DOS_HEADER dosHdr;
    PIMAGE_FILE_HEADER pfh;
    PIMAGE_OPTIONAL_HEADER poh;
    PIMAGE_SECTION_HEADER psh;
    IMAGE_SECTION_HEADER shdr[MAXSECTIONNUMBER];
	
	int i, j, n;
	int fsize;

	int nSections;
	int nResources;
	int nMenus;
	int nDialogs;
	int nImportModules;
	int nFunctions;
	int nExportFuntions;
	
	int imageBase;
	int entryPoint;

	char *pnstr;
	char *pst;
	char *piNameBuff;
	char *pfNameBuff;
	char *peNameBuff;
	char *pmNameBuff;
	char *pdNameBuff;
	/* --- End Variables --- */

	/* --- Open file --- */
	#pragma region Open file
	file = fopen(argv[1], "rb");
	fseek(file, 0L, SEEK_END);
	fsize = ftell(file);
	rewind(file);

	lpFile = (void *)calloc(fsize, 1);
	if (lpFile == NULL) {
		std::cout << "Error. Cannot allocate memory!" << std::endl;
		fclose(file);
		return 1;
	}
#pragma endregion

	/* --- Start report --- */
	
	std::cout << "***********************************************************************************************" << std::endl;
	std::cout << "******************************************* FILE DUMP *****************************************" << std::endl;
	std::cout << "***********************************************************************************************" << std::endl << std::endl;
	
	std::cout << "Dump of file: " << argv[1] << std::endl;
	std::cout << "Size of " << argv[1] << ": " << fsize << " bytes" << std::endl << std::endl;

	/* --- Read from file*/
	n = fread(lpFile, fsize, 1, file);
	fclose(file);
	if (n == -1) {
		std::cout << "Failed to read from " << argv[1] << std::endl;
		free(lpFile);
		system("PAUSE");
		return 1;
	}

	GetDosHeader(lpFile, &dosHdr);
	
	/* --- Identify if PE file --- */
	if ((WORD)IMAGE_DOS_SIGNATURE == dosHdr.e_magic) {
		if ((dosHdr.e_lfanew > 4096) || (dosHdr.e_lfanew < 64)) {
			std::cout << "Error file is not in PE format. Maybe Dos?" << std::endl;
			free(lpFile);
			return 1;
		}
	}
	else {
		std::cout << "Error. The file doesn't look like an executable. (magic = " << std::hex << "0x" << dosHdr.e_magic << std::endl;
		free(lpFile);
		return 1;
	}
	
	/* --- Identify file type*/
	fileType = ImageFileType(lpFile);
	if (fileType != IMAGE_NT_SIGNATURE) {
		std::cout << "Error. " << argv[1] << " Is not in PE format (magic = 0x" << std::hex << fileType << ")" << std::endl;
		free(lpFile);
		return 0;
	}
	
	/* ----------------------- */
	/* --- Real processing --- */
	/* ----------------------- */

	pfh = (PIMAGE_FILE_HEADER)		PEFHDROFFSET(lpFile);
	poh = (PIMAGE_OPTIONAL_HEADER)	OPTHDROFFSET(lpFile);
	psh = (PIMAGE_SECTION_HEADER)	SECHDROFFSET(lpFile);

	nSections = pfh->NumberOfSections;
	imageBase = poh->ImageBase;
	entryPoint = poh->AddressOfEntryPoint;

	if (psh == NULL) {
		std::cout << "Error. An unknown error happened during the processing of " << argv[1] << "!!!" << std::endl;
		free(lpFile);
		return 1;
	}

	/* --- Store section headers --- */

	for (i = 0; i < nSections; i++)
		shdr[i] = *psh++;

	/* --- Get Code & Data, offset & size --- */

	for (i = 0; i < nSections; i++) {
		if (poh->BaseOfCode == shdr->VirtualAddress) 
			printf( "Code Offset = %08lX, Code Size = %08lX \n",
				        shdr[i].PointerToRawData, shdr[i].SizeOfRawData );
		if (((shdr[i].Characteristics) & 0xC0000040) == 0xC0000040) {
			printf( "Data Offset = %08lX, Data Size = %08lX \n",
				        shdr[i].PointerToRawData, shdr[i].SizeOfRawData );
			break;
		}	
	}
	NEWL;

	printf( "Number of Objects = %04d (dec), Imagebase = %08Xh \n",
		    nSections, imageBase );

	/* --- Object name alignment --- */
	for (i = 0; i < nSections; i++) {
		for (j = 0; j  < 7; j ++) {
			if (shdr[i].Name[j] == 0)
				shdr[i].Name[j] = 32;
		}
		shdr[i].Name[7] = 0;
	}
	
	for (i = 0; i < nSections; i++)
			printf("   Object%02d: %8s RVA: %08lX Offset: %08lX Size: %08lX Flags: %08lX \n",
			i + 1, shdr[i].Name, shdr[i].VirtualAddress, shdr[i].PointerToRawData,
			shdr[i].SizeOfRawData, shdr[i].Characteristics);

	/* --- Get List of Resources ---*/

	nResources = GetListOfResourceTypes(lpFile, &pnstr);
	pst = pnstr;
	NEWL;
	std::cout << "************************************** RESOURCE INFORMATION ***********************************" << std::endl;
	NEWL;

	if (nResources == 0)
		std::cout << "        There are no Resources in This Application." << std::endl;
	else {
		std::cout << "Number of Resource Types = " << nResources << std::endl;
		for (i = 0; i < nResources; i++) {
			printf("\n   Resource Type %03d: %s", i + 1, pst);
			pst += strlen((char *)(pst)) + 1;
		}

		free((void*)pnstr);
		/* --- Menu info ---*/
		NEWL;
		NEWL;
		std::cout << "**************************************** MENU INFORMATION *************************************" << std::endl;
		NEWL;

		nMenus = GetContentsOfMenu(lpFile, &pmNameBuff);
		if (nMenus == 0)
			std::cout << "There are no menus in this application!" << std::endl;
		else {
			pst = pmNameBuff;
			std::cout << "Number of menus = " << nMenus << std::endl;

			for (i = 0; i < nMenus; i++){

				// menu ID print
				NEWL;
				std::cout << pst << std::endl;
				pst += strlen(pst) + 1;
				std::cout << "--------------" << std::endl;
				if (strncmp(pst, ":::::::::::", 11) == 0) {

				}

			}
		}
	}
	

	/* --- Done! ---*/
	std::cout << "Done!" << std::endl;
	system("PAUSE");
	free(lpFile);
	return 0;
}



