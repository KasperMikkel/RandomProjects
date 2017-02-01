#include "funcs.h"

BOOL	WINAPI GetDosHeader(LPVOID lpFile, PIMAGE_DOS_HEADER pHeader) {
	if ((WORD)IMAGE_DOS_SIGNATURE == *(WORD *)lpFile)
	{
		bcopy(lpFile, (LPVOID)pHeader, sizeof(IMAGE_DOS_HEADER));
		return TRUE;
	}
	return FALSE;

}
DWORD	WINAPI ImageFileType(LPVOID lpFile) {
	/* dos file signature comes first */
	if (*(USHORT *)lpFile == IMAGE_DOS_SIGNATURE)
	{
		/* determine location of PE File header from dos header */
		if (LOWORD(*(DWORD *)NTSIGNATURE(lpFile)) == IMAGE_OS2_SIGNATURE ||
			LOWORD(*(DWORD *)NTSIGNATURE(lpFile)) == IMAGE_OS2_SIGNATURE_LE)
			return (DWORD)LOWORD(*(DWORD *)NTSIGNATURE(lpFile));

		else if (*(DWORD *)NTSIGNATURE(lpFile) == IMAGE_NT_SIGNATURE)
			return IMAGE_NT_SIGNATURE;

		else
			return IMAGE_DOS_SIGNATURE;
	}

	else
		/* unknown file type */
		return 0;
}
INT		WINAPI GetListOfResourceTypes(LPVOID lpFile, char **pszResTypes) {
	PIMAGE_RESOURCE_DIRECTORY		prdRoot;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY prde;
	char *pMem;
	char  buff[32];
	int   nCnt, i;
	DWORD prdeName;

	/* --- Get root directory of resource tree --- */
	if ((prdRoot = (PIMAGE_RESOURCE_DIRECTORY)ImageDirectoryOffset(lpFile, IMAGE_DIRECTORY_ENTRY_RESOURCE)) == NULL)
		return 0;

	nCnt = prdRoot->NumberOfIdEntries * (MAXRESOURCENAME + 1);
	*pszResTypes = (char *)calloc(nCnt, 1);
	if ((pMem = *pszResTypes) == NULL)
		return 0;

	/* --- Set pointer to first resource type entry --- */
	prde = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)prdRoot + sizeof(IMAGE_RESOURCE_DIRECTORY));

	/* --- Loop through all resource directory entry types ---*/
	for (i = 0; i < prdRoot->NumberOfIdEntries; i++) {
		prdeName = prde->Name;

		if (prdeName == 1) {
			strcpy(pMem, "RT_CURSOR");
			pMem += 10;
		}
		else if (prdeName == 2) {
			strcpy(pMem, "RT_BITMAP");
			pMem += 10;
		}
		else if (prdeName == 3) {
			strcpy(pMem, "RT_ICON  ");
			pMem += 10;
		}
		else if (prdeName == 4) {
			strcpy(pMem, "RT_MENU  ");
			pMem += 10;
		}
		else if (prdeName == 5) {
			strcpy(pMem, "RT_DIALOG");
			pMem += 10;
		}
		else if (prdeName == 6) {
			strcpy(pMem, "RT_STRING");
			pMem += 10;
		}
		else if (prdeName == 7) {
			strcpy(pMem, "RT_FONTDIR");
			pMem += 11;
		}
		else if (prdeName == 8) {
			strcpy(pMem, "RT_FONT");
			pMem += 10;
		}
		else if (prdeName == 9) {
			strcpy(pMem, "RT_ACCELERATORS");
			pMem += 16;
		}
		else if (prdeName == 10) {
			strcpy(pMem, "RT_RCDATA");
			pMem += 10;
		}
		else if (prdeName == 11) {
			strcpy(pMem, "RT_MESSAGETABLE");
			pMem += 16;
		}
		else if (prdeName == 12) {
			strcpy(pMem, "RT_GROUP_CURSOR");
			pMem += 16;
		}
		else if (prdeName == 14) {
			strcpy(pMem, "RT_GROUP_ICON  ");
			pMem += 16;
		}
		else if (prdeName == 16) {
			strcpy(pMem, "RT_VERSION");
			pMem += 11;
		}
		else if (prdeName == 17) {
			strcpy(pMem, "RT_DLGINCLUDE  ");
			pMem += 16;
		}
		else if (prdeName == 19) {
			strcpy(pMem, "RT_PLUGPLAY    ");
			pMem += 16;
		}
		else if (prdeName == 20) {
			strcpy(pMem, "RT_VXD   ");
			pMem += 10;
		}
		else if (prdeName == 21) {
			strcpy(pMem, "RT_ANICURSOR   ");
			pMem += 16;
		}
		else if (prdeName == 22) {
			strcpy(pMem, "RT_ANIICON");
			pMem += 11;
		}
		else if (prdeName == 23) {
			strcpy(pMem, "RT_HMTL");
			pMem += 11;
		}
		else if (prdeName == 24) {
			strcpy(pMem, "RT_MANIFEST");
			pMem += 11;
		}
		else if (prdeName == 0x2002) {
			strcpy(pMem, "RT_NEWBITMAP");
			pMem += 13;
		}
		else if (prdeName == 0x2004) {
			strcpy(pMem, "RT_NEWMENU");
			pMem += 11;
		}
		else if (prdeName == 0x2005) {
			strcpy(pMem, "RT_NEWDIALOG");
			pMem += 13;
		}
		else if (prdeName == 0x7FFF) {
			strcpy(pMem, "RT_ERROR ");
			pMem += 10;
		}
		else {
			printf(buff, "RT_UNKNOWN:%08lX", prdeName);
			strcpy(pMem, buff);
			pMem += 20;
		}
		prde++;
	}
	return prdRoot->NumberOfIdEntries;


}
LPVOID	WINAPI ImageDirectoryOffset(LPVOID lpFile, DWORD dwIMAGE_DIRECTORY) {
	PIMAGE_OPTIONAL_HEADER poh = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET(lpFile);
	PIMAGE_SECTION_HEADER  psh = (PIMAGE_SECTION_HEADER)SECHDROFFSET(lpFile);
	int nSection = NumOfSections(lpFile);
	int i = 0;
	LPVOID VAImageDir;

	if (dwIMAGE_DIRECTORY >= poh->NumberOfRvaAndSizes)
		return NULL;

	VAImageDir = (LPVOID)poh->DataDirectory[dwIMAGE_DIRECTORY].VirtualAddress;

	if (VAImageDir == NULL)
		return NULL;
	while (i++ < nSection) {
		if (psh->VirtualAddress <= (DWORD)VAImageDir &&
			psh->VirtualAddress + psh->SizeOfRawData > (DWORD)VAImageDir)
			break;
		psh++;
	}
	if (i > nSection)
		return NULL;
	return (LPVOID)(((int)lpFile + (int)VAImageDir - psh->VirtualAddress) +
		(int)psh->PointerToRawData);

}
INT		WINAPI NumOfSections(LPVOID lpFile) {
	return ((int)((PIMAGE_FILE_HEADER)PEFHDROFFSET(lpFile))->NumberOfSections);
}
INT		WINAPI GetContentsOfMenu(LPVOID lpFile, char ** pszResTypes) {
	PIMAGE_RESOURCE_DIRECTORY prdType, prdName, prdLanguage;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY prde, prde1;
	PIMAGE_RESOURCE_DIR_STRING_U pMenuName;
	PIMAGE_RESOURCE_DATA_ENTRY prData;

	PIMAGE_MENU_HEADER pMenuHeader;
	WORD* pPopup;

	char buff[32];
	int i, j;
	int size;
	int sLength, nMenus;

	WORD flag;
	WORD *pwd;

	char *pMem;

	if ((prdType = (PIMAGE_RESOURCE_DIRECTORY)ImageDirectoryOffset
	(lpFile, IMAGE_DIRECTORY_ENTRY_RESOURCE)) == NULL)
		return 0;

	prde = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)
		((DWORD)prdType + sizeof(IMAGE_RESOURCE_DIRECTORY));

	for (i = 0; i < prdType->NumberOfIdEntries; i++) {
		if (prde->Name == (DWORD)RT_MENU)
			break;
		prde++;
	}
	if (prde->Name != (DWORD)RT_MENU)
		return 0;
	prdName = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)prdType + (prde->OffsetToData ^ 0x80000000));
	if (prdName == NULL)
		return 0;

	prde = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)prdName + sizeof(IMAGE_RESOURCE_DIRECTORY));
	nMenus = prdName->NumberOfNamedEntries + prdName->NumberOfIdEntries;
	sLength = 0;

	for (i = 0; i < prdName->NumberOfNamedEntries; i++) {
		pMenuName = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)prdType + (prde->Name ^ 0x80000000));
		sLength += pMenuName->Length + 1;

		prdLanguage = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)prdType + (prde->OffsetToData ^ 0x80000000));

		if (prdLanguage == NULL)
			continue;

		prde1 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)prdLanguage + sizeof(IMAGE_RESOURCE_DIRECTORY));
		prData = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)prdType + prde1->OffsetToData);

		if (prData == NULL)
			continue;

		pMenuHeader = (PIMAGE_MENU_HEADER)GetActualAddress(lpFile, prData->OffsetToData);



		if (pMenuHeader->wVersion | pMenuHeader->cbHeaderSize) {
			pwd = (WORD *)((DWORD)pMenuHeader + 16);
			size = prData->Size;
			sLength += 16 + size;
		}
		else {
			pPopup = (WORD *)((DWORD)pMenuHeader + sizeof(IMAGE_MENU_HEADER));
			while (1) {
				flag = (WORD)MenuScan(&sLength, (WORD **)(&pPopup));
				if (flag & 0x0080)
					break;
			}
		}
		prde++;
	}

	for (i = 0; i < prdName->NumberOfIdEntries; i++)
	{
		sLength += 12;
		prdLanguage = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)prdType + (prde->OffsetToData ^ 0x80000000));

		if (prdLanguage == NULL)
			continue;

		prde1 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)prdLanguage + sizeof(PIMAGE_RESOURCE_DIRECTORY));
		prData = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)prdType + prde1->OffsetToData);
		if (prData == NULL)
			continue;
		pMenuHeader = (PIMAGE_MENU_HEADER)GetActualAddress(lpFile, prData->OffsetToData);
		if (pMenuHeader->wVersion | pMenuHeader->cbHeaderSize) {
			pwd = (WORD *)((DWORD)pMenuHeader + 16);
			size = prData->Size;
			sLength += 16 + size;
		}
		else {
			pPopup = (WORD *)((DWORD)pMenuHeader + sizeof(IMAGE_MENU_HEADER));
			while (1) {
				flag = (WORD)MenuScan(&sLength, (WORD **)(&pPopup));
				if (flag & 0x0080)
					break;
			}
		}
		prde++;
	}

	*pszResTypes = (char *)calloc(sLength, 1);

	pMem = *pszResTypes;

	prde = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)prdName + sizeof(IMAGE_RESOURCE_DIRECTORY));
		   for (i = 0; i < prdName->NumberOfNamedEntries; i++)
		     {
				pMenuName = (PIMAGE_RESOURCE_DIR_STRING_U)
				((DWORD)prdType + (prde->Name ^ 0x80000000));
		

				for (j = 0; j < pMenuName->Length; j++)
				*pMem++ = (char)(pMenuName->NameString[j]);
				*pMem = 0;
				pMem++;
		
		
				prdLanguage = (PIMAGE_RESOURCE_DIRECTORY)
				((DWORD)prdType + (prde->OffsetToData ^ 0x80000000));
				if (prdLanguage == NULL)
					continue;
		
				prde1 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)prdLanguage + sizeof(IMAGE_RESOURCE_DIRECTORY));
		
				prData = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)prdType + prde1->OffsetToData);
				if (prData == NULL)
				 continue;
		
				pMenuHeader = (PIMAGE_MENU_HEADER)
				GetActualAddress(lpFile, prData->OffsetToData);
				// strange case
				if (pMenuHeader->wVersion | pMenuHeader->cbHeaderSize)
				{
				   pwd = (WORD *)((DWORD)pMenuHeader);
				   size = prData->Size;
				   strcpy(pMem, ":::::::::::");
				   pMem += 12;
				   *(int *)pMem = size;
				   pMem += 4;
				   StrangeMenuFill(&pMem, &pwd, size);
				 }
				else
				{
					pPopup = (WORD*)((DWORD)pMenuHeader + sizeof(IMAGE_MENU_HEADER));
				while (1)
				{
					flag = (WORD)MenuFill(&pMem, (WORD **)(&pPopup));
					if (flag & 0x0080)
						break;
				}
		     }
		   prde++;
		 }
		 for (i = 0; i < prdName->NumberOfIdEntries; i++)
		 {

			sprintf(buff, "MenuId_%04lX", (prde->Name));
			strcpy(pMem, buff);
			pMem += strlen(buff) + 1;

			prdLanguage = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)prdType + (prde->OffsetToData ^ 0x80000000));
			if (prdLanguage == NULL)
				continue;

			prde1 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)prdLanguage + sizeof(IMAGE_RESOURCE_DIRECTORY));

			prData = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)prdType + prde1->OffsetToData);
			if (prData == NULL)
				continue;

			pMenuHeader = (PIMAGE_MENU_HEADER)GetActualAddress(lpFile, prData->OffsetToData);
       // strange case
			if (pMenuHeader->wVersion | pMenuHeader->cbHeaderSize)
			{
			   pwd = (WORD *)((DWORD)pMenuHeader);
			   size = prData->Size;
			   strcpy(pMem, ":::::::::::");
			   pMem += 12;
				* (int *)pMem = size;
			   pMem += 4;
			   StrangeMenuFill(&pMem, &pwd, size);
			}
			else
			{
			   pPopup = (WORD*)((DWORD)pMenuHeader + sizeof(IMAGE_MENU_HEADER));
			   while (1)
				 {
				   flag = (WORD)MenuFill(&pMem, (WORD **)(&pPopup));
				   if (flag & 0x0080)
				 break;
			}
     }
       prde++;
     }
   return nMenus;
}
LPVOID	WINAPI GetActualAddress(LPVOID lpFile, DWORD dwRVA) {
	PIMAGE_SECTION_HEADER psh = (PIMAGE_SECTION_HEADER)SECHDROFFSET(lpFile);
	int nSections = NumOfSections(lpFile);
	int i = 0;

	if (dwRVA == 0)
		return NULL;
	if (dwRVA & 0x80000000)
	{
		std::cout << "Error. There is an unknown error!!" << std::endl;
		exit(1);
	}

	while (i++ < nSections) {
		if (psh->VirtualAddress <= (DWORD)dwRVA && psh->VirtualAddress + psh->SizeOfRawData > (DWORD)dwRVA)
			break;
		psh++;
	}
	if (i > nSections)
		return NULL;
	return (LPVOID)(((int)lpFile + (int)dwRVA - psh->VirtualAddress) + (int)psh->PointerToRawData);
}
INT		WINAPI MenuScan(int *len, WORD **pMenu) {
	WORD *pwd;
	WORD flag, flag1;
	WORD id, ispopup;

	pwd = *pMenu;

	flag = *pwd;

	pwd++;
	(*len) += 2;

	if ((flag & 0x0010) == 0) {
		ispopup = flag;
		id = *pwd;
		pwd++;
		(*len) += 2;
	}
	else {
		ispopup = flag;
	}
	while (*pwd) {
		(*len)++;
		pwd++;
	}
	(*len)++;

	pwd++;

	if ((flag & 0x0010) == 0) {
		*pMenu = pwd;
		return (INT)flag;
	}
	while (1) {
		*pMenu = pwd;
		flag1 = (WORD)MenuScan(len, pMenu);
		pwd = *pMenu;
		if (flag1 & 0x0080)
			break;
	}

	*pMenu = pwd;
	return flag;
}
INT		WINAPI MenuFill(char** psz, WORD** pMenu) {
	char *ptr/*, *pTemp*/;
	WORD *pwd;
	WORD flag, flag1;
	WORD id/*, ispopup*/;

	ptr = *psz;
	pwd = *pMenu;
	flag = *pwd;          // so difficult to correctly code this so let's try this

	pwd++;
	if ((flag & 0x0010) == 0)
	{
		*(WORD *)ptr = flag; // flag store
		ptr += 2;
		*(WORD *)ptr = id = *pwd;    // id store

		ptr += 2;
		pwd++;
		}
	else
     {
		*(WORD *)ptr = flag; // flag store
	
	    ptr += 2;
	 }
	
	while (*pwd)          // name extract
	{
		*ptr = *(char *)pwd;
	    ptr++;
	    pwd++;
	}               //name and null character
	
	 *ptr = 0;
	  ptr++;
	  pwd++;            // skip double null

    if ((flag & 0x0010) == 0) // normal node: done
	{
		* pMenu = pwd;
		* psz = ptr;
          return (int)flag;
    }
    while (1)
      {
        //num++;
    	 * pMenu = pwd;
		 * psz = ptr;
         flag1 = (WORD)MenuFill(psz, pMenu);
         pwd = *pMenu;
         ptr = *psz;
         if (flag1 & 0x0080)
			break;
      }
	*pMenu = pwd;
	*psz = ptr;
	return flag;
 }
VOID	WINAPI StrangeMenuFill(char** psz, WORD** pMenu, int size) {
	WORD *pwd;
	WORD *ptr, *pmax;

	pwd = *pMenu;
	pmax = (WORD *)((DWORD)pwd + size);
	ptr = (WORD *)(*psz);

	while (pwd < pmax) {
		*ptr++ = *pwd++;
	}
	*psz = (char *)ptr;
	*pMenu = pwd;
}
bool fileExist(const std::string filepath) {
	struct stat buffer;
	return (stat(filepath.c_str(), &buffer) == 0);
}