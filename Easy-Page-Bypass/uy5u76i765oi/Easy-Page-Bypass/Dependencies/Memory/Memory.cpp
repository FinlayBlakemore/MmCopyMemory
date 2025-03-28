#include "Memory.hpp"

typedef union _VIRTUAL_MEMORY_ADDRESS { struct { UINT64 PageIndex : 12, PtIndex : 9, PdIndex : 9, PdptIndex : 9, Pml4Index : 9, Unused : 16; } Bits; UINT64 All; } VIRTUAL_ADDRESS, * PVIRTUAL_ADDRESS;
typedef union _DIRECTORY_TABLE_BASE { struct { UINT64 Ignored0 : 3, PageWriteThrough : 1, PageCacheDisable : 1, _Ignored1 : 7, PhysicalAddress : 36, _Reserved0 : 16; } Bits; UINT64 All; } CR3, DIR_TABLE_BASE;
typedef union _PML4_ENTRY { struct { UINT64 Present : 1, ReadWrite : 1, UserSupervisor : 1, PageWriteThrough : 1, PageCacheDisable : 1, Accessed : 1, _Ignored0 : 1, _Reserved0 : 1, _Ignored1 : 4, PhysicalAddress : 40, _Ignored2 : 11, ExecuteDisable : 1; } Bits; UINT64 All; } PML4E;
typedef union _PDPT_ENTRY_LARGE { struct { UINT64 Present : 1, ReadWrite : 1, UserSupervisor : 1, PageWriteThrough : 1, PageCacheDisable : 1, Accessed : 1, Dirty : 1, PageSize : 1, Global : 1, _Ignored0 : 3, PageAttributeTable : 1, _Reserved0 : 17, PhysicalAddress : 22, _Ignored1 : 7, ProtectionKey : 4, ExecuteDisable : 1; } Bits; UINT64 All; } PDPTE_LARGE;
typedef union _PDPT_ENTRY { struct { UINT64 Present : 1, ReadWrite : 1, UserSupervisor : 1, PageWriteThrough : 1, PageCacheDisable : 1, Accessed : 1, _Ignored0 : 1, PageSize : 1, _Ignored1 : 4, PhysicalAddress : 40, _Ignored2 : 11, ExecuteDisable : 1; } Bits; UINT64 All; } PDPTE;
typedef union _PD_ENTRY_LARGE { struct { UINT64 Present : 1, ReadWrite : 1, UserSupervisor : 1, PageWriteThrough : 1, PageCacheDisable : 1, Accessed : 1, Dirty : 1, PageSize : 1, Global : 1, _Ignored0 : 3, PageAttributeTalbe : 1, _Reserved0 : 8, PhysicalAddress : 29, _Reserved1 : 2, _Ignored1 : 7, ProtectionKey : 4, ExecuteDisable : 1; } Bits; UINT64 All; } PDE_LARGE;
typedef union _PD_ENTRY { struct { UINT64 Present : 1, ReadWrite : 1, UserSupervisor : 1, PageWriteThrough : 1, PageCacheDisable : 1, Accessed : 1, _Ignored0 : 1, PageSize : 1, _Ignored1 : 4, PhysicalAddress : 38, _Reserved0 : 2, _Ignored2 : 11, ExecuteDisable : 1; } Bits; UINT64 All; } PDE;
typedef union _PT_ENTRY { struct { UINT64 Present : 1, ReadWrite : 1, UserSupervisor : 1, PageWriteThrough : 1, PageCacheDisable : 1, Accessed : 1, Dirty : 1, PageAttributeTable : 1, Global : 1, _Ignored0 : 3, PhysicalAddress : 38, _Reserved0 : 2, _Ignored1 : 7, ProtectionKey : 4, ExecuteDisable : 1; } Bits; UINT64 All; } PTE;
typedef union _MMPTE_HARDWARE { struct { UINT64 Valid : 1, Dirty1 : 1, Owner : 1, WriteThrough : 1, CacheDisable : 1, Accessed : 1, Dirty : 1, LargePage : 1, Global : 1, CopyOnWrite : 1, Unused : 1, Write : 1, PageFrameNumber : 36, ReservedForHardware : 4, ReservedForSoftware : 4, WsleAge : 4, WsleProtection : 3, NoExecute : 1; } Bits; UINT64 All; } MMPTE_HARDWARE;
typedef struct _SYSTEM_HANDLE { PVOID Object; HANDLE UniqueProcessId; HANDLE HandleValue; ULONG GrantedAccess; USHORT CreatorBackTraceIndex; USHORT ObjectTypeIndex; ULONG HandleAttributes; ULONG Reserved; } SYSTEM_HANDLE, * PSYSTEM_HANDLE;
typedef struct _SYSTEM_HANDLE_INFORMATION_EX { ULONG_PTR HandleCount; ULONG_PTR Reserved; SYSTEM_HANDLE Handles[1]; } SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;
struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX { PVOID Object; ULONG UniqueProcessId; ULONG HandleValue; ULONG GrantedAccess; USHORT CreatorBackTraceIndex; USHORT ObjectTypeIndex; ULONG HandleAttributes; ULONG Reserved; };
struct SYSTEM_HANDLE_INFORMATION_EX_PROCESS { ULONG NumberOfHandles; ULONG Reserved; SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1]; };
typedef struct _RTL_PROCESS_MODULE_INFORMATION { HANDLE Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize; ULONG Flags; USHORT LoadOrderIndex; USHORT InitOrderIndex; USHORT LoadCount; USHORT OffsetToFileName; UCHAR FullPathName[256]; } RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES { ULONG NumberOfModules; RTL_PROCESS_MODULE_INFORMATION Modules[1]; } RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

#include <LazyImporter/LazyImporter.hpp>
#include <HashString/HashString.hpp>

KMemory::KMemory()
{
	this->Handle = NULL;
	this->Offset = { };
}

bool KMemory::CreateHandle(OffsetPacket* Offset, const std::string DeviceName)
{
	// Converting the device string to wide
	std::wstring DeviceNameW = std::wstring(DeviceName.begin(), DeviceName.end());

	// Creating unicode string to open a device to our driver
	UNICODE_STRING UnicodeString;
	RtlInitUnicodeString(&UnicodeString, DeviceNameW.c_str());

	// Initilizing Classes To Pass To "NtCreateFile"
	OBJECT_ATTRIBUTES Attributes = OBJECT_ATTRIBUTES();
	IO_STATUS_BLOCK StatusBlock = IO_STATUS_BLOCK();

	// Creating Handle To The File
	Attributes.Length = sizeof(OBJECT_ATTRIBUTES);
	Attributes.ObjectName = &UnicodeString;

	bool Status = NT_SUCCESS(NtCreateFile(
		&this->Handle,
		GENERIC_READ | GENERIC_WRITE | WRITE_DAC | SYNCHRONIZE,
		&Attributes,
		&StatusBlock,
		nullptr,
		NULL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		nullptr,
		NULL
	));

	if (!Status) {
		return NULL;
	}

	// Setting our offset packet
	this->Offset = Offset;

	return true;
}

bool KMemory::Setup()
{
	this->SystemCr3 = this->GetSystemCr3();

	if (!this->SystemCr3) {
		return false;
	}

	this->SystemProcess = this->GetSystemProcess();

	if (!this->SystemProcess) {
		return false;
	}

	return true;
}

bool KMemory::WriteVirtualMemory(const std::uint64_t Address, void* Buffer, std::size_t Length)
{
	if (!Address || !Buffer || !Length) {
		return false;
	}

	std::size_t Offset = 0x00;
	std::size_t Value = Length;

	while (Value)
	{
		const std::uint64_t PhysicalAddress = this->GetPhysical(Address + Offset);

		if (!PhysicalAddress) {
			return false;
		}

		const std::uint64_t MemoryLength = min(PAGE_SIZE - (PhysicalAddress & 0xFFF), Value);

		this->WritePhysicalMemory(PhysicalAddress, (void*)((std::uint64_t)Buffer + Offset), MemoryLength);

		Offset += MemoryLength;
		Value -= MemoryLength;
	}

	return true;
}

bool KMemory::ReadVirtualMemory(const std::uint64_t Address, void* Buffer, std::size_t Length)
{
	if (!Address || !Buffer || !Length) {
		return false;
	}

	std::size_t Offset = 0x00;
	std::size_t Value = Length;

	while (Value)
	{
		const std::uint64_t PhysicalAddress = this->GetPhysical(Address + Offset);

		if (!PhysicalAddress) {
			return false;
		}

		const std::uint64_t MemoryLength = min(PAGE_SIZE - (PhysicalAddress & 0xFFF), Value);

		this->ReadPhysicalMemory(PhysicalAddress, (void*)((std::uint64_t)Buffer + Offset), MemoryLength);

		Offset += MemoryLength;
		Value -= MemoryLength;
	}

	return true;
}

std::uint64_t KMemory::GetPhysical(const std::uint64_t VirtualAddress)
{
	VIRTUAL_ADDRESS virtAddr = { 0 };

	DIR_TABLE_BASE  dirTableBase = { 0 };
	PML4E           pml4e = { 0 };
	PDPTE           pdpte = { 0 };
	PDPTE_LARGE     pdpteLarge = { 0 };
	PDE             pde = { 0 };
	PDE_LARGE       pdeLarge = { 0 };
	PTE             pte = { 0 };


	virtAddr.All = VirtualAddress;


	dirTableBase.All = this->SystemCr3;

	if (this->ReadPhysicalMemory(
		/* This calculation results in the PML4E address */
		(dirTableBase.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + (virtAddr.Bits.Pml4Index * 8),
		&pml4e,
		sizeof(PML4E)) == FALSE)
	{
		return 0;
	}

	/*
	 * Always ensure we can proceed with our translation process. It may
	 *  also be wise to check the read result of our MmCopyMemory wrapper.
	 */

	if (pml4e.Bits.Present == 0)
	{
		return 0;
	}


	if (this->ReadPhysicalMemory(
		/* This calculation results in the PDPTE address */
		(pml4e.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + (virtAddr.Bits.PdptIndex * 8),
		&pdpte,
		sizeof(PDPTE)) == FALSE)
	{
		return 0;
	}

	if (pdpte.Bits.Present == 0)
	{
		return 0;
	}


	if (IS_LARGE_PAGE(pdpte.All) == TRUE)
	{
		pdpteLarge.All = pdpte.All;

		return (pdpteLarge.Bits.PhysicalAddress << PAGE_1GB_SHIFT)
			+ PAGE_1GB_OFFSET(VirtualAddress);
	}

	if (this->ReadPhysicalMemory(
		/* This calculation results in the PDE address */
		(pdpte.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + (virtAddr.Bits.PdIndex * 8),
		&pde,
		sizeof(PDE)) == FALSE)
	{
		return 0;
	}

	if (pde.Bits.Present == 0)
	{
		return 0;
	}


	if (IS_LARGE_PAGE(pde.All) == TRUE)
	{
		pdeLarge.All = pde.All;

		return (pdeLarge.Bits.PhysicalAddress << PAGE_2MB_SHIFT)
			+ PAGE_2MB_OFFSET(VirtualAddress);
	}

	if (this->ReadPhysicalMemory(
		/* This calculation results in the PTE address */
		(pde.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + (virtAddr.Bits.PtIndex * 8),
		&pte,
		sizeof(PTE)) == FALSE)
	{
		return 0;
	}

	if (pte.Bits.Present == 0)
	{
		return 0;
	}

	return (pte.Bits.PhysicalAddress << PAGE_4KB_SHIFT)
		+ virtAddr.Bits.PageIndex;
}

std::uint64_t KMemory::GetSystemImage(const std::uint32_t Hash)
{
	// Intilizing Variables
	void* Buffer = nullptr;
	DWORD Length = NULL;

	// Getting Size Of List
	NTSTATUS status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)(11),
		Buffer,
		Length,
		&Length
	);

	// Attempting To Fix List
	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		// Freeing Old Buffer And Allocating New Buffer
		LI_FN(VirtualFree)(Buffer, NULL, MEM_RELEASE);
		Buffer = LI_FN(VirtualAlloc)(nullptr, Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		// Setting List Into New Buffer
		status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)(11),
			Buffer,
			Length,
			&Length
		);
	}

	// Checking If It Failed To Assign List
	if (!NT_SUCCESS(status))
	{
		LI_FN(VirtualFree)(Buffer, NULL, MEM_RELEASE);
		return NULL;
	}

	// Reinterpreting The Buffer Into The List Struct
	const RTL_PROCESS_MODULES* ImageList = (RTL_PROCESS_MODULES*)(Buffer);

	// Walking Module List
	for (unsigned long Index = 0; Index < ImageList->NumberOfModules; ++Index)
	{
		// Getting The Current Module Name
		const char* ImageName = (char*)(ImageList->Modules[Index].FullPathName) + ImageList->Modules[Index].OffsetToFileName;

		// Checking If Current Module Is Target Module
		if (Hash::String(ImageName) == Hash)
		{
			// Getting Current Image Base
			const RTL_PROCESS_MODULE_INFORMATION ImageInfo = ImageList->Modules[Index];

			// Freeing List
			LI_FN(VirtualFree)(Buffer, NULL, MEM_RELEASE);
			return (std::uint64_t)ImageInfo.ImageBase;
		}
	}

	return NULL;
}

bool KMemory::WritePhysicalMemory(const std::uint64_t Address, void* Buffer, std::size_t Length)
{
	DriverPacket Packet;
	Packet.PhysicalAddress = Address;
	Packet.Size = Length;

	if (!this->MapPhysicalMemory(&Packet)) {
		return false;
	}

	// Writing the data from the virtual address
	__movsb((BYTE*)Packet.BaseAddress, (BYTE*)Buffer, Length);

	if (!this->UnmapPhysicalMemory(&Packet)) {
		return false;
	}

	return true;
}

bool KMemory::ReadPhysicalMemory(const std::uint64_t Address, void* Buffer, std::size_t Length)
{
	DriverPacket Packet;
	Packet.PhysicalAddress = Address;
	Packet.Size = Length;

	if (!this->MapPhysicalMemory(&Packet)) {
		return false;
	}

	// Reading the data from the virtual address
	__movsb((BYTE*)Buffer, (BYTE*)Packet.BaseAddress, Length);

	if (!this->UnmapPhysicalMemory(&Packet)) {
		return false;
	}

	return true;
}

bool KMemory::UnmapPhysicalMemory(DriverPacket* Packet)
{
	IO_STATUS_BLOCK StatusBlock = IO_STATUS_BLOCK();
	return NT_SUCCESS(NtDeviceIoControlFile(
		this->Handle,
		(HANDLE)NULL,
		(PIO_APC_ROUTINE)nullptr,
		(PVOID)nullptr,
		(PIO_STATUS_BLOCK)&StatusBlock,
		(ULONG)0x80102044,
		(PVOID)Packet,
		(ULONG)sizeof(DriverPacket),
		(PVOID)Packet,
		(ULONG)sizeof(DriverPacket)
	));
}

bool KMemory::MapPhysicalMemory(DriverPacket* Packet)
{
	IO_STATUS_BLOCK StatusBlock = IO_STATUS_BLOCK();
	return NT_SUCCESS(NtDeviceIoControlFile(
		this->Handle,
		(HANDLE)NULL,
		(PIO_APC_ROUTINE)nullptr,
		(PVOID)nullptr,
		(PIO_STATUS_BLOCK)&StatusBlock,
		(ULONG)0x80102040,
		(PVOID)Packet,
		(ULONG)sizeof(DriverPacket),
		(PVOID)Packet,
		(ULONG)sizeof(DriverPacket)
	));
}

std::uint64_t KMemory::GetSystemProcess()
{
	// Getting the size of the buffer
	std::uint32_t _Length = 0;
	std::uint8_t _Buffer[1024] = { 0 };
	NTSTATUS Status = NtQuerySystemInformation(
		static_cast<SYSTEM_INFORMATION_CLASS>(0x40), // SystemExtendedHandleInformation
		&_Buffer,
		sizeof(_Buffer),
		reinterpret_cast<ULONG*>(&_Length)
	);

	// Increasing the size of the buffer
	_Length += 50 * (sizeof(SYSTEM_HANDLE_INFORMATION_EX_PROCESS) + sizeof(SYSTEM_HANDLE));

	// Allocating a buffer with the new length and zeroing it
	void* Buffer = LI_FN(VirtualAlloc)(nullptr, _Length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	RtlSecureZeroMemory(Buffer, _Length);

	// Getting the correct length of the buffer
	std::uint32_t Length = 0;
	Status = NtQuerySystemInformation(
		static_cast<SYSTEM_INFORMATION_CLASS>(0x40), // SystemExtendedHandleInformation
		Buffer,
		_Length,
		reinterpret_cast<ULONG*>(&Length)
	);

	// Reinterpreting our buffer into the HandleInformation structure
	SYSTEM_HANDLE_INFORMATION_EX_PROCESS* HandleInformation = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX_PROCESS*>(Buffer);

	// Walking our handle table to find the handle of the system process
	for (std::uint32_t Index = 0; Index < HandleInformation->NumberOfHandles; Index++)
	{
		// Validating the handle attributes
		if (HandleInformation->Handles[Index].HandleAttributes != 0x102A) {
			continue;
		}

		// Validating the unique process id
		if (HandleInformation->Handles[Index].UniqueProcessId != 4) {
			continue;
		}

		// Getting the result
		std::uint64_t Result = (std::uint64_t)(HandleInformation->Handles[Index].Object);

		// Freeing the list
		LI_FN(VirtualFree)(Buffer, NULL, MEM_RELEASE);

		return Result;
	}

	// Freeing the list
	LI_FN(VirtualFree)(Buffer, NULL, MEM_RELEASE);

	return NULL;
}

std::uint64_t KMemory::GetSystemCr3()
{
	for (int Index = 0; Index < 10; Index++)
	{
		// Mapping a buffer of kernel pages to our process
		DriverPacket Packet;
		Packet.PhysicalAddress = Index * 0x10000;
		Packet.Size = 0x10000;
		if (!this->MapPhysicalMemory(&Packet)) {
			continue;
		}

		// Validating the buffer address
		if (!Packet.BaseAddress) {
			continue;
		}

		// Storing our buffer
		std::uint64_t Buffer = (std::uint64_t)Packet.BaseAddress;

		// Looping the buffer for the system cr3
		for (int Offset = 0; Offset < 0x10000; Offset += 0x1000)
		{
			if (0x00000001000600E9 ^ (0xffffffffffff00ff & *reinterpret_cast<uintptr_t*>(Buffer + Offset)))
				continue;
			if (0xfffff80000000000 ^ (0xfffff80000000000 & *reinterpret_cast<uintptr_t*>(Buffer + Offset + 0x70)))
				continue;
			if (0xffffff0000000fff & *reinterpret_cast<uintptr_t*>(Buffer + Offset + 0xa0))
				continue;

			return *reinterpret_cast<uintptr_t*>(Buffer + Offset + 0xa0);
		}

		// Unmapping buffer
		this->UnmapPhysicalMemory(&Packet);
	}
}
