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

//0x8 bytes (sizeof)
struct _MMPTE_HARDWARE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Dirty1 : 1;                                                     //0x0
	ULONGLONG Owner : 1;                                                      //0x0
	ULONGLONG WriteThrough : 1;                                               //0x0
	ULONGLONG CacheDisable : 1;                                               //0x0
	ULONGLONG Accessed : 1;                                                   //0x0
	ULONGLONG Dirty : 1;                                                      //0x0
	ULONGLONG LargePage : 1;                                                  //0x0
	ULONGLONG Global : 1;                                                     //0x0
	ULONGLONG CopyOnWrite : 1;                                                //0x0
	ULONGLONG Unused : 1;                                                     //0x0
	ULONGLONG Write : 1;                                                      //0x0
	ULONGLONG PageFrameNumber : 36;                                           //0x0
	ULONGLONG ReservedForHardware : 4;                                        //0x0
	ULONGLONG ReservedForSoftware : 4;                                        //0x0
	ULONGLONG WsleAge : 4;                                                    //0x0
	ULONGLONG WsleProtection : 3;                                             //0x0
	ULONGLONG NoExecute : 1;                                                  //0x0
};

//0x8 bytes (sizeof)
struct _MMPTE_PROTOTYPE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG DemandFillProto : 1;                                            //0x0
	ULONGLONG HiberVerifyConverted : 1;                                       //0x0
	ULONGLONG ReadOnly : 1;                                                   //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Combined : 1;                                                   //0x0
	ULONGLONG Unused1 : 4;                                                    //0x0
	LONGLONG ProtoAddress : 48;                                               //0x0
};

//0x8 bytes (sizeof)
struct _MMPTE_SOFTWARE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG PageFileReserved : 1;                                           //0x0
	ULONGLONG PageFileAllocated : 1;                                          //0x0
	ULONGLONG ColdPage : 1;                                                   //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG PageFileLow : 4;                                                //0x0
	ULONGLONG UsedPageTableEntries : 10;                                      //0x0
	ULONGLONG ShadowStack : 1;                                                //0x0
	ULONGLONG Unused : 5;                                                     //0x0
	ULONGLONG PageFileHigh : 32;                                              //0x0
};

//0x8 bytes (sizeof)
struct _MMPTE_TIMESTAMP
{
	ULONGLONG MustBeZero : 1;                                                 //0x0
	ULONGLONG Unused : 3;                                                     //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG PageFileLow : 4;                                                //0x0
	ULONGLONG Reserved : 16;                                                  //0x0
	ULONGLONG GlobalTimeStamp : 32;                                           //0x0
};

//0x8 bytes (sizeof)
struct _MMPTE_TRANSITION
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Write : 1;                                                      //0x0
	ULONGLONG Spare : 1;                                                      //0x0
	ULONGLONG IoTracker : 1;                                                  //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG PageFrameNumber : 36;                                           //0x0
	ULONGLONG Unused : 16;                                                    //0x0
};

//0x8 bytes (sizeof)
struct _MMPTE_SUBSECTION
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Unused0 : 3;                                                    //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG ColdPage : 1;                                                   //0x0
	ULONGLONG Unused1 : 3;                                                    //0x0
	ULONGLONG ExecutePrivilege : 1;                                           //0x0
	LONGLONG SubsectionAddress : 48;                                          //0x0
};

//0x8 bytes (sizeof)
struct _MMPTE_LIST
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG OneEntry : 1;                                                   //0x0
	ULONGLONG filler0 : 2;                                                    //0x0
	ULONGLONG SwizzleBit : 1;                                                 //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG filler1 : 16;                                                   //0x0
	ULONGLONG NextEntry : 36;                                                 //0x0
};

//0x8 bytes (sizeof)
struct _MMPTE
{
	union
	{
		ULONGLONG Long;                                                     //0x0
		volatile ULONGLONG VolatileLong;                                    //0x0
		struct _MMPTE_HARDWARE Hard;                                        //0x0
		struct _MMPTE_PROTOTYPE Proto;                                      //0x0
		struct _MMPTE_SOFTWARE Soft;                                        //0x0
		struct _MMPTE_TIMESTAMP TimeStamp;                                  //0x0
		struct _MMPTE_TRANSITION Trans;                                     //0x0
		struct _MMPTE_SUBSECTION Subsect;                                   //0x0
		struct _MMPTE_LIST List;                                            //0x0
	} u;                                                                    //0x0
};
