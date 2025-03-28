#include "PDB.hpp"

static const char* SystemImageList[4] = { "ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe" };
#define CURRENT_HANDLE (HANDLE)(-1)

struct DebugInfo_t
{
	char magic[4]; // RSDS
	GUID guid;
	int age;
	char pdb_path[];
};

PDB::PDB() { }

std::uint64_t PDB::GetProperty(const std::uint32_t ImageHash, const std::uint32_t StructHash, const std::uint32_t PropertyHash)
{
	auto ImageEntry = this->StructList.find(ImageHash);

	if (ImageEntry == this->StructList.end()) {
		return NULL;
	}

	auto StructEntry = ImageEntry->second.find(StructHash);

	if (StructEntry == ImageEntry->second.end()) {
		return NULL;
	}

	auto PropertyEntry = StructEntry->second.find(PropertyHash);

	if (PropertyEntry == StructEntry->second.end()) {
		return NULL;
	}

	return PropertyEntry->second;
}

std::uint64_t PDB::GetData(const std::uint32_t ImageHash, const std::uint32_t FunctionHash)
{
	auto ImageEntry = this->FunctionList.find(ImageHash);

	if (ImageEntry == this->FunctionList.end()) {
		return NULL;
	}

	auto FunctionEntry = ImageEntry->second.find(FunctionHash);

	if (FunctionEntry == ImageEntry->second.end()) {
		return NULL;
	}

	return FunctionEntry->second;
}

bool PDB::DownloadOffsetData(std::vector<std::string> ImageNameList)
{
	char TempPath[MAX_PATH];
	LI_FN(GetTempPathA)(MAX_PATH, TempPath);
	std::string DownloadPath = std::string(TempPath);

	for (std::string& ImageName : ImageNameList)
	{
		if (!ImageName.compare(_("ntoskrnl.exe")))
		{
			bool HasDownloadedModule = false;
			for (std::size_t Index = 0; Index < 4; Index++)
			{
				if (!this->DownloadToPath(SystemImageList[Index], DownloadPath, this->GetGuid(ImageName))) {
					continue;
				}

				// resolving the pdb path
				std::string PdbPath = this->ResolvePath(SystemImageList[Index], DownloadPath, true);

				// defining our structs to dump data into
				std::map<std::uint32_t, std::map<std::uint32_t, std::uint64_t>> StructData;
				std::map<std::uint32_t, std::uint64_t> FunctionData;

				// dumping the pdb offset data
				if (!this->DumpData(PdbPath, &StructData, &FunctionData)) {
					this->Delete(PdbPath);
					return false;
				}

				// storing our offsets into the function data
				this->FunctionList.insert({ Hash::String(ImageName.c_str()), FunctionData });
				this->StructList.insert({ Hash::String(ImageName.c_str()), StructData });

				// deleting the pdb
				this->Delete(PdbPath);
				HasDownloadedModule = true;
			}

			if (!HasDownloadedModule) {
				return false;
			}
		}
		else
		{
			if (!this->DownloadToPath(ImageName, DownloadPath, this->GetGuid(ImageName))) {
				return false;
			}

			// resolving the pdb path
			std::string PdbPath = this->ResolvePath(ImageName, DownloadPath, true);

			// defining our structs to dump data into
			std::map<std::uint32_t, std::map<std::uint32_t, std::uint64_t>> StructData;
			std::map<std::uint32_t, std::uint64_t> FunctionData;

			// dumping the pdb offset data
			if (!this->DumpData(PdbPath, &StructData, &FunctionData)) {
				this->Delete(PdbPath);
				return false;
			}

			// storing our offsets into the function data
			this->FunctionList.insert({ Hash::String(ImageName.c_str()), FunctionData });
			this->StructList.insert({ Hash::String(ImageName.c_str()), StructData });

			// deleting the pdb
			this->Delete(PdbPath);
		}
	}

	return true;
}

bool PDB::DumpData(std::string PdbPath, std::map<std::uint32_t, std::map<std::uint32_t, std::uint64_t>>* StructData, std::map<std::uint32_t, std::uint64_t>* FunctionData)
{
	WIN32_FILE_ATTRIBUTE_DATA FileAttributeData{ 0 };
	if (!GetFileAttributesExA(PdbPath.c_str(), GetFileExInfoStandard, &FileAttributeData)) {
		return false;
	}

	DWORD PdbLength = FileAttributeData.nFileSizeLow;

	if (!PdbLength) {
		return false;
	}

	bool Result = SymInitialize(
		CURRENT_HANDLE,
		PdbPath.c_str(),
		FALSE
	);

	if (!Result) {
		return false;
	}

	SymSetOptions(
		SYMOPT_UNDNAME |
		SYMOPT_DEFERRED_LOADS |
		SYMOPT_AUTO_PUBLICS |
		SYMOPT_DEBUG |
		SYMOPT_LOAD_ANYTHING
	);

	std::uint64_t ImageBase = SymLoadModuleEx(
		CURRENT_HANDLE,
		nullptr,
		PdbPath.c_str(),
		PdbPath.c_str(),
		0x1000,
		PdbLength,
		NULL,
		NULL
	);

	if (!ImageBase) {
		SymCleanup(CURRENT_HANDLE);
		return false;
	}

	auto Callback = [](SYMBOL_INFO* SymbolInformation, ULONG SymbolSize, void* UserContext)
		{
			std::map<std::uint32_t, std::map<std::uint32_t, std::uint64_t>>* Result = (std::map<std::uint32_t, std::map<std::uint32_t, std::uint64_t>>*)UserContext;
			std::map<std::uint32_t, std::uint64_t> StructData = {};

			TI_FINDCHILDREN_PARAMS TempFp = { 0 };
			if (!SymGetTypeInfo(CURRENT_HANDLE, 0x1000, SymbolInformation->TypeIndex, TI_GET_CHILDRENCOUNT, &TempFp)) {
				return TRUE;
			}

			ULONG ChildParamsSize = sizeof(TI_FINDCHILDREN_PARAMS) + TempFp.Count * sizeof(ULONG);
			TI_FINDCHILDREN_PARAMS* ChildParams = (TI_FINDCHILDREN_PARAMS*)malloc(ChildParamsSize);
			ZeroMemory(ChildParams, ChildParamsSize);

			memcpy(ChildParams, &TempFp, sizeof(TI_FINDCHILDREN_PARAMS));

			if (!SymGetTypeInfo(CURRENT_HANDLE, 0x1000, SymbolInformation->TypeIndex, TI_FINDCHILDREN, ChildParams)) {
				return TRUE;
			}

			for (ULONG i = ChildParams->Start; i < ChildParams->Count; i++) {
				WCHAR* PropertyName = nullptr;
				if (!SymGetTypeInfo(CURRENT_HANDLE, 0x1000, ChildParams->ChildId[i], TI_GET_SYMNAME, &PropertyName)) {
					return TRUE;
				}

				if (!PropertyName) {
					continue;
				}

				std::wstring WideString = std::wstring(PropertyName);
				std::string UnicodeString = std::string(
					WideString.begin(),
					WideString.end()
				);

				ULONG Offset = 0;
				if (!SymGetTypeInfo(CURRENT_HANDLE, 0x1000, ChildParams->ChildId[i], TI_GET_OFFSET, &Offset)) {
					return TRUE;
				}

				StructData.insert({ Hash::String(UnicodeString.c_str()), Offset });
			}

			Result->insert({ Hash::String(SymbolInformation->Name), StructData });

			return TRUE; // Continue enumeration
		};

	SymEnumTypes(CURRENT_HANDLE, ImageBase, Callback, StructData);

	SymEnumSymbols(CURRENT_HANDLE, ImageBase, "*", [](SYMBOL_INFO* SymbolInformation, ULONG SymbolSize, void* Context)
		{
			if (!SymbolInformation->Name || !SymbolInformation->Address) {
				return TRUE;
			}

			// Pushing back name and offset of function
			reinterpret_cast<std::map<std::uint32_t, std::uint64_t>*>(Context)->insert({ Hash::String(SymbolInformation->Name), SymbolInformation->Address - SymbolInformation->ModBase });

			// Continuing execution
			return TRUE;
		}, FunctionData
	);

	SymUnloadModule64(CURRENT_HANDLE, ImageBase);
	return true;
}

bool PDB::DownloadToPath(std::string ImageName, const std::string DownloadPath, const std::string Guid)
{
	// Removing file extention
	ImageName.resize(ImageName.size() - 4);

	// Creating the stream ready to add our url to
	std::stringstream URL;

	// Pushing the base of the url (symbol server and image name .pbd)
	URL << _("http://msdl.microsoft.com/download/symbols/") << ImageName << _(".pdb/");

	URL << Guid;
	URL << _("/") << ImageName << _(".pdb");

	return !URLDownloadToFileA(NULL, URL.str().c_str(), this->ResolvePath(ImageName, DownloadPath, false).c_str(), 0, 0);
}

std::string PDB::ResolvePath(const std::string ImageName, const std::string DownloadPath, bool Extention)
{
	std::string Result = ImageName;

	if (Extention) {
		Result.resize(Result.size() - 4);
	}

	Result += _(".pdb");
	return DownloadPath + Result;
}

std::uint64_t PDB::ResolveRelativeAddress(const std::uint64_t Address, IMAGE_NT_HEADERS* NtHeaders, std::uint8_t* LocalBuffer)
{
	IMAGE_SECTION_HEADER* FirstSection = IMAGE_FIRST_SECTION(NtHeaders);
	for (IMAGE_SECTION_HEADER* Section = FirstSection; Section < FirstSection + NtHeaders->FileHeader.NumberOfSections; Section++) {
		if (Address >= Section->VirtualAddress && Address < Section->VirtualAddress + Section->Misc.VirtualSize) {
			return (std::uint64_t)LocalBuffer + Section->PointerToRawData + (Address - Section->VirtualAddress);
		}
	}
	return NULL;
}

std::vector<std::uint8_t> PDB::ScanFileData(const std::string SystemPath, const std::string ImageName)
{
	const std::string PathList[2] = { SystemPath + ImageName, SystemPath + "drivers\\" + ImageName };

	for (int Index = 0; Index < 2; Index++)
	{
		// Attemptign to find the file
		WIN32_FIND_DATAA FileData;
		HANDLE Handle = FindFirstFileA(PathList[Index].c_str(), &FileData);
		if (Handle == INVALID_HANDLE_VALUE) {
			continue;
		}

		do
		{
			// Is a folder so we skip
			if (FileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				continue;
			}

			// Reading the file data
			return PDB::ReadFileData(PathList[Index]);

		} while (FindNextFileA(Handle, &FileData) != 0);

		FindClose(Handle);
	}

	return { };
}

std::vector<std::uint8_t> PDB::ReadFileData(const std::string ImagePath)
{
	// Open the file in binary mode
	std::ifstream File(ImagePath, std::ios::binary);
	if (!File) {
		return { };
	}

	// Determine the file size
	File.seekg(0, std::ios::end);
	std::streamsize FileLength = File.tellg();
	File.seekg(0, std::ios::beg);

	// Read the file into a vector
	std::vector<std::uint8_t> FileData(FileLength);
	if (!File.read(reinterpret_cast<char*>(FileData.data()), FileLength)) {
		return { };
	}

	return FileData;
}

std::string PDB::GetGuid(const std::string ImageName)
{
	// Getting the system path
	char _SystemPath[MAX_PATH];
	LI_FN(GetSystemDirectoryA)(_SystemPath, MAX_PATH);
	std::string SystemPath = std::string(_SystemPath) + _("\\");

	// Scanning for the file data of that file
	std::vector<std::uint8_t> FileData = PDB::ScanFileData(SystemPath, ImageName);

	if (!FileData.size()) {
		return "";
	}
	IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)FileData.data();

	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return "";
	}

	IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)(FileData.data() + DosHeader->e_lfanew);

	if (NtHeader->Signature != IMAGE_NT_SIGNATURE) {
		return "";
	}

	IMAGE_DATA_DIRECTORY DebugDataDirectory = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

	if (!DebugDataDirectory.VirtualAddress || !DebugDataDirectory.Size) {
		return "";
	}

	IMAGE_DEBUG_DIRECTORY* DebugDirectory = (IMAGE_DEBUG_DIRECTORY*)(std::uint64_t)PDB::ResolveRelativeAddress(DebugDataDirectory.VirtualAddress, NtHeader, FileData.data());

	if (!DebugDirectory->AddressOfRawData) {
		return "";
	}

	DebugInfo_t DebugInfo;
	__movsb(
		(BYTE*)&DebugInfo,
		(BYTE*)(PDB::ResolveRelativeAddress(DebugDirectory->AddressOfRawData, NtHeader, FileData.data())),
		sizeof(DebugInfo_t)
	);

	std::stringstream Guid;

	// Setting all the guid variables into the url
	Guid << std::setfill('0') << std::setw(8) << std::hex << DebugInfo.guid.Data1;
	Guid << std::setw(4) << std::hex << DebugInfo.guid.Data2;
	Guid << std::setw(4) << std::hex << DebugInfo.guid.Data3;

	for (const auto i : DebugInfo.guid.Data4) {
		Guid << std::setw(2) << std::hex << +i;
	}

	// Adding age of file into URL
	Guid << DebugInfo.age;

	return Guid.str();
}

void PDB::Delete(const std::string ImagePath)
{
	remove(ImagePath.c_str());
}
