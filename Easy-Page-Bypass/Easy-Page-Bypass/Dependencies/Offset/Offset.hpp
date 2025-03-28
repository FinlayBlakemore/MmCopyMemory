#pragma once

#include <cstdint>

// Line : Function : Type
namespace Offset
{
	inline int PageOffset = 0x3F;

	inline std::uint64_t KiProcessorBlock = 0xCFDCC0; // 6 : KeGetPrcb : _KPRCB
	inline std::uint64_t MiSystemPTEInfo = 0xC4EE00; // 322 : MiCheckProcessorPteCache : _MI_SYSTEM_PTE_TYPE
	inline std::uint64_t PageBitMaskList = 0x1DC80; // 188 : MiCheckProcessorPteCache : List of masks i think
	inline std::uint64_t ByteFlag = 0xC4DEC8; // 49 : MiMakeValidPte : Byte
	inline std::uint64_t MmPfnDatabase = 0xCFC510; // MmPfnDatabase   dq ?
	inline std::uint64_t DynamicPfnValue = 0x262D91; // mov rax, uint64 : MiGetPteAddress : UINT64
	inline std::uint64_t PteControlFlag = 0xCFB17C; // 418 : MiReservePtes : UINT32
	inline std::uint64_t PteClearMask = 0xC4DE00; // 447 : MiReservePtes : UINT64
	inline std::uint64_t PteFlagList = 0xC4F888; // 43 : MiMakeValidPte : BYTE

	namespace LeafVa
	{
		inline std::uint64_t Min = 0xC4F9F8; // 48 : MiMakeValidPte : UINT64
		inline std::uint64_t Max = 0xC4E228; // 48 : MiMakeValidPte : UINT64
	}

	namespace KPRCB
	{
		inline std::uint64_t PteBitCache = 0x85B0; // 75 : MiCheckProcessorPteCache : 
		inline std::uint64_t PteBitOffset = 0x85B8; // 196 : MiCheckProcessorPteCache : 
	}

	namespace MiSystemPteType // _MI_SYSTEM_PTE_TYPE
	{
		inline std::uint64_t BasePte = 0x10; //  : : _MMPTE*
		inline std::uint64_t Flags = 0x18; //  : : ULONG
	}
}