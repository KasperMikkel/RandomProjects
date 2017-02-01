#pragma once
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string>
#include <setjmp.h>
#include <malloc.h>
#include <ctype.h>
#include <sys/stat.h>
#include <iomanip>

#ifndef bcopy
#define		bcopy(s,d,z)					memcpy((d),(s),(z))
#endif
#define		NTSIGNATURE(a)					((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew))
#define		MAXSECTIONNUMBER				16
#define		MAXNAMESTRNUMBER				40
#define		SIZE_OF_NT_SIGNATURE			sizeof (DWORD)
#define		MAXRESOURCENAME					13

#define		NEWL							std::cout << std::endl

#pragma region GlobalMacros
/* global macros to define header offsets into file offset to PE file signature                                 */
#define NTSIGNATURE(a) ((LPVOID)((BYTE *)a + \
            ((PIMAGE_DOS_HEADER)a)->e_lfanew))
/* DOS header identifies the NT PEFile signature dword 809    the PEFILE header exists just after that dword              */
#define PEFHDROFFSET(a) ((LPVOID)((BYTE *)a + \
             ((PIMAGE_DOS_HEADER)a)->e_lfanew    +  \
             SIZE_OF_NT_SIGNATURE))
/* PE optional header is immediately after PEFile header       */
#define OPTHDROFFSET(a) ((LPVOID)((BYTE *)a + \
              ((PIMAGE_DOS_HEADER)a)->e_lfanew    +  \
             SIZE_OF_NT_SIGNATURE            +  \
              sizeof (IMAGE_FILE_HEADER)))

/* section headers are immediately after PE optional header    */
#define SECHDROFFSET(a) ((LPVOID)((BYTE *)a + \
              ((PIMAGE_DOS_HEADER)a)->e_lfanew    +  \
              SIZE_OF_NT_SIGNATURE            +  \
              sizeof (IMAGE_FILE_HEADER)      +  \
              sizeof (IMAGE_OPTIONAL_HEADER)))
#pragma endregion

typedef struct _IMAGE_MENU_HEADER
{
	WORD wVersion;      // Currently zero
    WORD cbHeaderSize;      // Also zero
}
IMAGE_MENU_HEADER, *PIMAGE_MENU_HEADER;


BOOL		WINAPI GetDosHeader				(LPVOID, PIMAGE_DOS_HEADER pHeader);
DWORD		WINAPI ImageFileType			(LPVOID);
INT			WINAPI GetListOfResourceTypes	(LPVOID lpFile, char **pszResTypes);
LPVOID		WINAPI ImageDirectoryOffset		(LPVOID lpFile, DWORD dwIMAGE_DIRECTORY);
INT			WINAPI NumOfSections			(LPVOID lpFile);
INT			WINAPI GetContentsOfMenu		(LPVOID lpFile, char ** pszResTypes);
LPVOID		WINAPI GetActualAddress			(LPVOID lpFile, DWORD dwRVA);
INT			WINAPI MenuScan					(int *len, WORD **pMenu);
INT			WINAPI MenuFill					(char** psz, WORD** pMenu);
VOID		WINAPI StrangeMenuFill			(char** psz, WORD** pMenu, int size);

bool			   fileExist				(const std::string filepath);