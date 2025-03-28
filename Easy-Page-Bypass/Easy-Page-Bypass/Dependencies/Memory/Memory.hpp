#pragma once

#pragma comment(lib, "ntdll.lib")

#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <vector>
#include <string>

#define PAGE_SHIFT      12
#ifdef __ASSEMBLY__
#define PAGE_SIZE       (1 << PAGE_SHIFT)
#else
#define PAGE_SIZE       (1UL << PAGE_SHIFT)
#endif
#define PAGE_MASK       (~(PAGE_SIZE-1))

#define PAGE_OFFSET_SIZE 12

#define PAGE_1GB_SHIFT      30
#define PAGE_1GB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_1GB_SHIFT)) )

#define PAGE_2MB_SHIFT      21
#define PAGE_2MB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_2MB_SHIFT)) )

#define PAGE_4KB_SHIFT      12
#define PAGE_4KB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_4KB_SHIFT)) )

#define IS_LARGE_PAGE(x)    ( (BOOLEAN)((x >> 7) & 1) )
#define IS_PAGE_PRESENT(x)  ( (BOOLEAN)(x & 1) )

#pragma pack(push, 1)
typedef struct DriverPacket
{
	DWORD_PTR Size;
	DWORD_PTR PhysicalAddress;
	HANDLE SectionHandle;
	LPVOID BaseAddress;
	LPVOID ReferenceObject;
};
#pragma pack(pop)

struct OffsetPacket
{
	std::uint64_t ActiveProcessLinks;
	std::uint64_t ImageFileName;
	std::uint64_t VirtualSize;
};

class KMemory {
public:
	KMemory();

	bool CreateHandle(OffsetPacket* Offset, const std::string DeviceName);
	bool Setup();

	template<typename Type>
	bool WriteVirtualMemory(const std::uint64_t Address, Type Buffer)
	{
		return this->WriteVirtualMemory(Address, &Buffer, sizeof(Type));
	}

	template<typename Type>
	Type ReadVirtualMemory(const std::uint64_t Address)
	{
		// clearing buffer
		Type Buffer;
		memset(&Buffer, NULL, sizeof(Type));

		// reading virtual memory
		this->ReadVirtualMemory(Address, &Buffer, sizeof(Type));

		return Buffer;
	}

	bool WriteVirtualMemory(const std::uint64_t Address, void* Buffer, std::size_t Length);
	bool ReadVirtualMemory(const std::uint64_t Address, void* Buffer, std::size_t Length);
	std::uint64_t GetPhysical(const std::uint64_t VirtualAddress);
	std::uint64_t GetSystemImage(const std::uint32_t Hash);
private:
	bool WritePhysicalMemory(const std::uint64_t Address, void* Buffer, std::size_t Length);
	bool ReadPhysicalMemory(const std::uint64_t Address, void* Buffer, std::size_t Length);
	bool UnmapPhysicalMemory(DriverPacket* Packet);
	bool MapPhysicalMemory(DriverPacket* Packet);
	std::uint64_t GetSystemProcess();
	std::uint64_t GetSystemCr3();

	std::uint64_t SystemProcess;
	std::uint64_t SystemCr3;
	OffsetPacket* Offset;
	HANDLE Handle;
};

inline KMemory* Memory = new KMemory();