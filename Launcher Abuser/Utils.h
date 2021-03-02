#pragma once

#include <iostream>

#include <string>

#include <windows.h>
#include <Psapi.h>
#define WIN32_LEAN_AND_MEAN

#include <tlhelp32.h>

#define ThreadQuerySetWin32StartAddress 9

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
}
UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
  BYTE Reserved1[8];
  PVOID Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
}
PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE Reserved1[16];
  PVOID Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
}
RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
  BYTE Reserved1[2];
  BYTE BeingDebugged;
  BYTE Reserved2[1];
  PVOID Reserved3[2];
  PPEB_LDR_DATA Ldr;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  PVOID Reserved4[3];
  PVOID AtlThunkSListPtr;
  PVOID Reserved5;
  ULONG Reserved6;
  PVOID Reserved7;
  ULONG Reserved8;
  ULONG AtlThunkSListPtr32;
  PVOID Reserved9[45];
  BYTE Reserved10[96];
  PVOID PostProcessInitRoutine;
  BYTE Reserved11[128];
  PVOID Reserved12[1];
  ULONG SessionId;
}
PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks; /* 0x00 */
  LIST_ENTRY InMemoryOrderLinks; /* 0x08 */
  LIST_ENTRY InInitializationOrderLinks; /* 0x10 */
  PVOID DllBase; /* 0x18 */
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName; /* 0x24 */
  UNICODE_STRING BaseDllName; /* 0x28 */
  ULONG Flags;
  WORD LoadCount;
  WORD TlsIndex;
  union {
    LIST_ENTRY HashLinks;
    struct {
      PVOID SectionPointer;
      ULONG CheckSum;
    };
  };
  union {
    ULONG TimeDateStamp;
    PVOID LoadedImports;
  };
  _ACTIVATION_CONTEXT * EntryPointActivationContext;
  PVOID PatchInformation;
  LIST_ENTRY ForwarderLinks;
  LIST_ENTRY ServiceTagLinks;
  LIST_ENTRY StaticLinks;
}
LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef BOOL(WINAPI * tNtQueryInformationThread)(
  HANDLE ThreadHandle,
  ULONG ThreadInformationClass,
  PVOID ThreadInformation,
  ULONG ThreadInformationLength,
  PULONG ReturnLength
);



#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef struct _UNICODE_ANOTHER_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
}
UNICODE_ANOTHER_STRING, * PUNICODE_ANOTHER_STRING;

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
  ULONG SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  PULONG ReturnLength
  );
typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
  HANDLE SourceProcessHandle,
  HANDLE SourceHandle,
  HANDLE TargetProcessHandle,
  PHANDLE TargetHandle,
  ACCESS_MASK DesiredAccess,
  ULONG Attributes,
  ULONG Options
  );
typedef NTSTATUS(NTAPI *_NtQueryObject)(
  HANDLE ObjectHandle,
  ULONG ObjectInformationClass,
  PVOID ObjectInformation,
  ULONG ObjectInformationLength,
  PULONG ReturnLength
  );

typedef struct _SYSTEM_HANDLE
{
  ULONG ProcessId;
  BYTE ObjectTypeNumber;
  BYTE Flags;
  USHORT Handle;
  PVOID Object;
  ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
  ULONG HandleCount;
  SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
  NonPagedPool,
  PagedPool,
  NonPagedPoolMustSucceed,
  DontUseThisType,
  NonPagedPoolCacheAligned,
  PagedPoolCacheAligned,
  NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
  UNICODE_ANOTHER_STRING Name;
  ULONG TotalNumberOfObjects;
  ULONG TotalNumberOfHandles;
  ULONG TotalPagedPoolUsage;
  ULONG TotalNonPagedPoolUsage;
  ULONG TotalNamePoolUsage;
  ULONG TotalHandleTableUsage;
  ULONG HighWaterNumberOfObjects;
  ULONG HighWaterNumberOfHandles;
  ULONG HighWaterPagedPoolUsage;
  ULONG HighWaterNonPagedPoolUsage;
  ULONG HighWaterNamePoolUsage;
  ULONG HighWaterHandleTableUsage;
  ULONG InvalidAttributes;
  GENERIC_MAPPING GenericMapping;
  ULONG ValidAccess;
  BOOLEAN SecurityRequired;
  BOOLEAN MaintainHandleCount;
  USHORT MaintainTypeList;
  POOL_TYPE PoolType;
  ULONG PagedPoolUsage;
  ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;


std::string GetLastErrorAsString();
void LogThis(const char * text);
char * TO_CHAR(wchar_t * string);
PEB * GetPEB();
LDR_DATA_TABLE_ENTRY * GetLDREntry(std::string name);
void notifyErrorAndExit(const char * text);
HANDLE getThreadHandleBasedOnStartAddress(HANDLE processHandle, uintptr_t startOfSectionAddr, uintptr_t endOfSectionAddr);
void ExecWithThreadHiJacking(HANDLE hThread, DWORD shellcodePtr, SIZE_T shellcodeSize, bool thenRestore);
void printInHex(BYTE* address, unsigned int length);