#pragma once

#include <cstdint>

namespace Import
{
	inline std::uint64_t ntoskrnl;

	// https://github.com/reactos/reactos/blob/master/ntoskrnl/mm/arm/page.c#L22
	const std::uint64_t MmProtectToPteMask[32] = {
		0x8000000000000000, 0x8000000000000000, 0x0000000000000000,
		0x0000000000000000, 0x8000000000000800, 0x8000000000000200,
		0x0000000000000800, 0x0000000000000200, 0x8000000000000000,
		0x8000000000000018, 0x0000000000000018, 0x0000000000000018,
		0x8000000000000818, 0x8000000000000218, 0x0000000000000818,
		0x0000000000000218, 0x8000000000000000, 0x8000000000000000,
		0x0000000000000000, 0x0000000000000000, 0x8000000000000800,
		0x8000000000000200, 0x0000000000000800, 0x0000000000000200,
		0x8000000000000000, 0x8000000000000008, 0x0000000000000008,
		0x0000000000000008, 0x8000000000000808, 0x8000000000000208,
		0x0000000000000808, 0x0000000000000208
	};

	std::uint64_t GetCurrentPcrb(const std::int32_t Index);
	std::uint64_t GetSystemPteInfo(const std::uint32_t Offset);
	std::uint64_t GetSystemPte();
	std::uint64_t MakePfnCompatible(const char Flag, const std::uint64_t MMPfn);
	std::uint32_t MiUserPdeOrAbove(std::uint64_t SystemPte);
	std::uint64_t MiGetLeafVa(std::uint64_t Address);
	std::uint64_t MakeValidPte(const std::uint64_t SystemPte, const std::uint64_t Pfn, const std::uint64_t ProtectionFlag);
	std::uint32_t MiPteInShadowRange(const std::uint64_t Pte);
	std::uint64_t RelativeOffset(const std::uint64_t Address, const std::uint32_t Offset);
	std::uint64_t GetPfnDb();
	std::uint64_t MapPhysicalMemory(const std::uint64_t PhysicalAddress);

	std::uint32_t ReadPhysicalMemory(std::uint64_t Address, void* Buffer, std::uint64_t Size);
	std::uint32_t WritePhysicalMemory(std::uint64_t Address, void* Buffer, std::uint64_t Size);
}