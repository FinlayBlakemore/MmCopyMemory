#include "EPB.hpp"

bool EPB::Setup()
{
	// Downloading Offset Data
	if (!Pdb->DownloadOffsetData({_("ntoskrnl.exe"),_("win32k.sys")})) {
		return false;
	}

	// Creating offset packet
	OffsetPacket* Offset = new OffsetPacket();
	{
		// Flushing out our offset packet
		memset(Offset, 0, sizeof(OffsetPacket));

		// Filling in properties
		Offset->ActiveProcessLinks = Pdb->GetProperty(HASH("ntoskrnl.exe"), HASH("_EPROCESS"), HASH("ActiveProcessLinks"));
		Offset->ImageFileName = Pdb->GetProperty(HASH("ntoskrnl.exe"), HASH("_EPROCESS"), HASH("ImageFileName"));
		Offset->VirtualSize = Pdb->GetProperty(HASH("ntoskrnl.exe"), HASH("_EPROCESS"), HASH("VirtualSize"));
	}

	// Creating a handle to the device
	if (!Memory->CreateHandle(Offset, _("\\DosDevices\\WinIo"))) {
		return false;
	}

	// Setting up the memory handler
	if (!Memory->Setup()) {
		return false;
	}

    return true;
}
