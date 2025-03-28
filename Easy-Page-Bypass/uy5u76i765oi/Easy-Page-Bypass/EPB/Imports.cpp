#include "Imports.hpp"

#include <Offset/Offset.hpp>
#include <Memory/Memory.hpp>

std::uint64_t Import::GetCurrentPcrb(const std::int32_t Index)
{
	return Memory->ReadVirtualMemory<std::uint64_t>(ntoskrnl + Offset::KiProcessorBlock + (Index * sizeof(std::uint64_t)));
}

std::uint64_t Import::GetSystemPteInfo(const std::uint32_t Offset)
{
    return Memory->ReadVirtualMemory<std::uint64_t>(ntoskrnl + Offset::MiSystemPTEInfo + Offset);
}

std::uint64_t Import::GetSystemPte()
{
	const std::uint64_t PRCB = Import::GetCurrentPcrb(0);

	if (!PRCB) {
		return NULL;
	}

    std::uint64_t PteBitCache = Memory->ReadVirtualMemory<std::uint64_t>(PRCB + Offset::KPRCB::PteBitCache);
    const std::uint64_t PteBitOffset = Memory->ReadVirtualMemory<std::uint64_t>(PRCB + Offset::KPRCB::PteBitOffset);
    const std::uint64_t PteBitCacheEntry = Memory->ReadVirtualMemory<std::uint64_t>(PteBitCache + (Offset::PageOffset >> 6 * sizeof(std::uint64_t)));

    std::uint64_t Result = NULL;

    if (PteBitCache != -1) 
    {
        unsigned long MostSignificantBit = 0;
        _BitScanForward64(&MostSignificantBit, ~PteBitCache);

        if (MostSignificantBit > Offset::PageOffset || MostSignificantBit == -1) {
            return NULL;
        }

        const std::uint32_t MostSignificantBitMask = MostSignificantBit & 7;
        char UnknownName = Memory->ReadVirtualMemory<char>(PteBitCache + (MostSignificantBit >> 3));
        const char UnknownFlag = Memory->ReadVirtualMemory<char>(ntoskrnl + Offset::PageBitMaskList + 1) << MostSignificantBitMask;
        UnknownName |= UnknownFlag;

        Memory->WriteVirtualMemory<char>((std::uint64_t)(PteBitCache + (MostSignificantBit >> 3)), UnknownName);
        Result = Import::GetSystemPteInfo(Offset::MiSystemPteType::BasePte) + 0x8 * (MostSignificantBit + PteBitOffset);
    }
    else
    {
        std::uint64_t PteBitCachePtr = (std::uint64_t)(PRCB + Offset::KPRCB::PteBitCache);
        while (PteBitCache == -1)
        {
            PteBitCachePtr += 0x8;
            if (PteBitCachePtr > PteBitCacheEntry) {
                return NULL;
            }

            PteBitCache = Memory->ReadVirtualMemory<std::uint64_t>(PteBitCachePtr);
        }

        unsigned long MostSignificantBit = 0;
        _BitScanForward64(&MostSignificantBit, ~PteBitCache);
        std::uint64_t MSBFlag = (unsigned int)MostSignificantBit + ((PteBitCachePtr - PteBitCacheEntry) << 6);

        if (MSBFlag > Offset::PageOffset || MSBFlag == -1) {
            return NULL;
        }
        
        const std::uint32_t MostSignificantBitMask = MSBFlag & 7;
        char UnknownName = Memory->ReadVirtualMemory<char>(PteBitCache + (MSBFlag >> 3));
        const char UnknownFlag = Memory->ReadVirtualMemory<char>(ntoskrnl + Offset::PageBitMaskList + 1) << MostSignificantBitMask;
        UnknownName |= UnknownFlag;

        Memory->WriteVirtualMemory<char>((std::uint64_t)(PteBitCache + (MostSignificantBit >> 3)), UnknownName);
        Result = Import::GetSystemPteInfo(Offset::MiSystemPteType::BasePte) + 0x8 * (MSBFlag + PteBitOffset);
    }

    if (Result)
    {
        if ((Import::GetSystemPteInfo(Offset::MiSystemPteType::Flags) & 2) == 0) {
            return Result;
        }

        if ((Memory->ReadVirtualMemory<std::uint32_t>(ntoskrnl + Offset::PteControlFlag) & 2) != 0) {
            return Result;
        }

        std::uint64_t Index = 0;
        do
        {
            std::uint64_t CurrIndexPtr = Result + (Index * sizeof(std::uint64_t));

            // Get the current flag
            std::uint64_t PteFlag = Memory->ReadVirtualMemory<std::uint64_t>(CurrIndexPtr);

            // Get the clear mask
            std::uint64_t PteClearMask = Memory->ReadVirtualMemory<std::uint64_t>(ntoskrnl + Offset::PteClearMask);

            if (PteClearMask && (PteFlag & 0x10) == 0) {
                PteFlag &= ~PteClearMask;
            }

            // Write the new flag
            Memory->WriteVirtualMemory<std::uint64_t>(CurrIndexPtr, PteFlag);

            if ((PteFlag & 0xFFFFFFFF00000000ui64) != 0) {
                break;
            }

            ++Index;
        } while (Index < (unsigned int)1);

        if (Index != 1)
        {
            // Flush needed
        }
    }

	return Result;
}

std::uint64_t Import::MakePfnCompatible(const char Flag, const std::uint64_t MMPfn)
{
    // Get the mask
    unsigned int ProtectionFlagMask = Flag & 7;

    // Get the page state
    char PageState = Memory->ReadVirtualMemory<BYTE>(MMPfn + 0x22) >> 6 & 0x3;

    // Change the mask based on the page state
    (PageState == 2) ? (ProtectionFlagMask |= 0x18u) : (ProtectionFlagMask |= 8u);

    return ProtectionFlagMask;
}

std::uint32_t Import::MiUserPdeOrAbove(std::uint64_t SystemPte)
{
    std::uint64_t Max = 0xFFFFF6FB40000000ui64;
    std::uint64_t Min = 0xFFFFF6FB5FFFFFF8ui64;

    for (unsigned int Index = 1; Index < 4; ++Index)
    {
        if (SystemPte <= Min && SystemPte >= Max) {
            return 1;
        }

        Max = ((Max >> 9) & 0x7FFFFFFFF8i64) - 0x98000000000i64;
        Min = ((Min >> 9) & 0x7FFFFFFFF8i64) - 0x98000000000i64;
    }

    return 0;
}

std::uint64_t Import::MiGetLeafVa(std::uint64_t Address)
{
    for (; Address >= 0xFFFFF68000000000ui64; Address = (std::uint64_t)(Address << 25) >> 16)
    {
        if (Address > 0xFFFFF6FFFFFFFFFFui64)
            break;
    }

    return Address;
}

std::uint64_t Import::MakeValidPte(const std::uint64_t SystemPte, const std::uint64_t Pfn, const std::uint64_t ProtectionFlag) 
{
    // Get the protection flag mask
    int ProtectionFlagMask = ProtectionFlag;
    std::int64_t ProtectionMaskIndex = ProtectionFlag & 0x1F;
    ProtectionMaskIndex += 1;

    // Calculate the Pfn value shifted by 12
    std::uint64_t ShiftedPfn = (Pfn & 0xFFFFFFFFFi64) << 12;

    // Calculate the Pte with the masks
    std::uint64_t Pte = ShiftedPfn | (MmProtectToPteMask[ProtectionMaskIndex] & 0xFFFF000000000E7Fui64) | 0x21;

    if (SystemPte >= 0xFFFFF68000000000ui64 && SystemPte <= 0xFFFFF6FFFFFFFFFFui64) 
    {
        std::uint64_t LeafVa = (std::int64_t)(SystemPte << 25) >> 16;

        if (SystemPte >= 0xFFFFF6FB40000000ui64 && SystemPte <= 0xFFFFF6FB7FFFFFFFui64) 
        {
            if (SystemPte == 0xFFFFF6FB7DBEDF68ui64) {
                Pte = ShiftedPfn | (MmProtectToPteMask[ProtectionMaskIndex] & 0xFFFF000000000E7Fui64) | 0x8000000000000021ui64;
            }
            else if ((ProtectionFlag & 0x4000000) == 0) {
                Pte = (ShiftedPfn & 0x7FFFFFFFFFFFFFFFi64) | (MmProtectToPteMask[ProtectionMaskIndex] & 0x7FFF000000000E7Fi64) | 0x21;
            }

            if (MiUserPdeOrAbove(SystemPte)) {
                Pte |= 4ui64;
            }
        }

        std::uint64_t TempPte = Pte;
        Pte |= 4ui64;
        if (SystemPte > 0xFFFFF6BFFFFFFF78ui64) {
            Pte = TempPte;
        }

        if ((ProtectionFlag & 0x4000000) != 0) {
            LeafVa = MiGetLeafVa((std::int64_t)(SystemPte << 25) >> 16);
        }

        if (LeafVa < 0xFFFF800000000000ui64) 
        {
            int ByteFlag = HIBYTE(Memory->ReadVirtualMemory<WORD>(ntoskrnl + Offset::ByteFlag));

            if (!ByteFlag) {
                Pte |= 0x100ui64;
            }
        }

        if (Memory->ReadVirtualMemory<BYTE>(ntoskrnl + Offset::PteFlagList + (((LeafVa >> 39) & 0x1FF) - 256)) != 1 && (LeafVa < 0xFFFFF68000000000ui64 || LeafVa > 0xFFFFF6FFFFFFFFFFui64))
        {
            if (LeafVa < Memory->ReadVirtualMemory<std::uint64_t>(ntoskrnl + Offset::LeafVa::Min) 
                || LeafVa > Memory->ReadVirtualMemory<std::uint64_t>(ntoskrnl + Offset::LeafVa::Max)) {
                int ByteFlag = (unsigned __int8)Memory->ReadVirtualMemory<WORD>(ntoskrnl + Offset::ByteFlag);
            }
            else {
                int ByteFlag = HIBYTE(Memory->ReadVirtualMemory<WORD>(ntoskrnl + Offset::ByteFlag));
                if (!ByteFlag) {
                    Pte |= 0x100ui64;
                }
            }
        }
    }

    // Add flags to the Pte based on protection flag
    std::uint64_t ResultPte = Pte | 0x42;
    if (ProtectionFlag >= 0 || (ProtectionMaskIndex & 5) != 4) {
        ResultPte = Pte;
    }

    if ((ProtectionFlag & 0x40000000) != 0) {
        ResultPte &= ~4ui64;
    }

    if ((ProtectionFlag & 0x20000000) != 0) {
        ResultPte = ((unsigned __int16)ResultPte 
            ^ (unsigned __int16)((unsigned __int8)Memory->ReadVirtualMemory<WORD>(ntoskrnl + Offset::ByteFlag) << 8)) & 0x100 ^ (std::uint64_t)ResultPte;
    }

    std::uint64_t FinalPte = ResultPte & 0xFFFFFFFFFFFFFEFFui64;
    if ((ProtectionFlag & 0x8000000) == 0) {
        FinalPte = ResultPte;
    }

    std::uint64_t ReturnPte = FinalPte | 0x80;
    if ((ProtectionFlag & 0x4000000) == 0) {
        ReturnPte = FinalPte;
    }

    return ReturnPte & 0xF0FFFFFFFFFFFFFFui64 | 0xA00000000000000i64;
}

std::uint32_t Import::MiPteInShadowRange(const std::uint64_t Pte)
{
    return Pte >= 0xFFFFF6FB7DBED000ui64 && Pte <= 0xFFFFF6FB7DBED7F8ui64;
}

std::uint64_t Import::RelativeOffset(const std::uint64_t Address, const std::uint32_t Offset)
{  
    std::uint64_t RelativeAddress = Address + Offset + sizeof(std::uint32_t);

    return  RelativeAddress + Memory->ReadVirtualMemory<std::uint32_t>(Address + Offset);
}

std::uint64_t Import::GetPfnDb()
{
    const std::uint64_t MmPfnDatabase = Memory->ReadVirtualMemory<std::uint64_t>(ntoskrnl + Offset::MmPfnDatabase);

    if (!MmPfnDatabase) {
        return NULL;
    }

    std::printf("MmPfnDatabase: %llx\n", MmPfnDatabase);

    const std::uint64_t RelativeOffset = Memory->ReadVirtualMemory<std::uint64_t>(ntoskrnl + Offset::DynamicPfnValue + 2);

    if (!RelativeOffset) {
        return NULL;
    }

    std::printf("RelativeOffset: %llx\n", RelativeOffset);

    const std::uint64_t RelativePfnDatabase = MmPfnDatabase - RelativeOffset;

    if (!RelativePfnDatabase) {
        return NULL;
    }

    std::printf("RelativePfnDatabase: %llx\n", RelativePfnDatabase);

    return RelativePfnDatabase;
}

std::uint64_t Import::MapPhysicalMemory(const std::uint64_t PhysicalAddress)
{
    const std::uint64_t SystemPte = Import::GetSystemPte();

    if (!SystemPte) {
        return NULL;
    }

    const std::uint64_t MMPfnBase = Import::GetPfnDb();

    if (!MMPfnBase) {
        return NULL;
    }

    const std::uint64_t Pfn = PhysicalAddress >> 12;
    const std::uint32_t PageOffset = PhysicalAddress & 0xFFF;
    const std::uint64_t MMPfn = MMPfnBase + (Pfn * 0x30);

    if (!MMPfn) {
        return NULL;
    }

    std::printf("Pfn: %llx\n", Pfn);

    const int PageAttributes = Memory->ReadVirtualMemory<std::uint8_t>(MMPfn + 0x22) >> 6;

    if (PageAttributes == 3) {
        return NULL;
    }

    std::printf("PageAttributes: %llx\n", PageAttributes);

    const char CurrentState = Memory->ReadVirtualMemory<char>(MMPfn + 0x23) < 0;

    if (CurrentState < 0) {
        return NULL;
    }

    std::printf("CurrentState: %llx\n", CurrentState);

    const std::uint64_t ProtectionFlag = Import::MakePfnCompatible(1, MMPfn);
    const std::uint64_t CustomPte = Import::MakeValidPte(SystemPte, Pfn, ProtectionFlag | 0x20000000u);

    std::printf("ProtectionFlag: %llx\n", ProtectionFlag);
    std::printf("CustomPte: %llx\n", CustomPte);

    // Verifying the range of the new pte
    if (Import::MiPteInShadowRange(CustomPte)) {
        return NULL;
    }

    // Setting the new pte
    Memory->WriteVirtualMemory<std::uint64_t>(SystemPte, CustomPte);

    // Calculating the mapped address
    std::int64_t MappedAddress = (std::int64_t)(SystemPte << 25) >> 16;
    MappedAddress += PageOffset;

    return MappedAddress;
}

std::uint32_t Import::ReadPhysicalMemory(std::uint64_t Address, void* Buffer, std::uint64_t Size)
{
    const std::uint64_t MappedMemory = MapPhysicalMemory(Address);

    if (!MappedMemory) {
        return 0;
    }

    return 1;
}

std::uint32_t Import::WritePhysicalMemory(std::uint64_t Address, void* Buffer, std::uint64_t Size)
{
    const std::uint64_t MappedMemory = MapPhysicalMemory(Address);

    if (!MappedMemory) {
        return 0;
    }

    return 1;
}


