#include "EPB/EPB.hpp"
#include "EPB/Imports.hpp"

int main()
{
	if (!EPB::Setup()) {
		return 1;
	}

	Import::ntoskrnl = Memory->GetSystemImage(HASH("ntoskrnl.exe"));
	std::printf("%llx\n", Memory->ReadVirtualMemory<unsigned short>(Import::ntoskrnl));

	if (!Import::ntoskrnl) { 
		return NULL; 
	}

	auto PhysicalAddress = Memory->GetPhysical(Import::ntoskrnl);
	auto MappedAddress = Import::MapPhysicalMemory(PhysicalAddress);

	std::printf("%llx\n", PhysicalAddress);
	std::printf("%llx\n", MappedAddress);

	Sleep(FLT_MAX);

	return 0;
}