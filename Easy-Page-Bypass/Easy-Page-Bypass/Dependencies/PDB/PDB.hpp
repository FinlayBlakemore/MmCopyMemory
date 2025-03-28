#pragma once

#pragma comment(lib, "URLMon.lib")
#pragma comment(lib, "dbghelp.lib")

#include <LazyImporter/LazyImporter.hpp>
#include <HashString/HashString.hpp>
#include <XorStr/XorStr.hpp>
#include <Windows.h>
#include <dbghelp.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <string>
#include <vector>
#include <map>

class PDB {
public:
	PDB();

	std::uint64_t GetProperty(const std::uint32_t ImageHash, const std::uint32_t StructHash, const std::uint32_t PropertyHash);
	std::uint64_t GetData(const std::uint32_t ImageHash, const std::uint32_t FunctionHash);

	bool DownloadOffsetData(std::vector<std::string> ImageNameList);
private:
	bool DumpData(std::string PdbPath, std::map<std::uint32_t, std::map<std::uint32_t, std::uint64_t>>* StructData, std::map<std::uint32_t, std::uint64_t>* FunctionData);
	bool DownloadToPath(std::string ImageName, const std::string DownloadPath, const std::string Guid);
	std::string ResolvePath(const std::string ImageName, const std::string DownloadPath, bool Extention);
	std::uint64_t ResolveRelativeAddress(const std::uint64_t Address, IMAGE_NT_HEADERS* NtHeaders, std::uint8_t* LocalBuffer);
	std::vector<std::uint8_t> ScanFileData(const std::string SystemPath, const std::string ImageName);
	std::vector<std::uint8_t> ReadFileData(const std::string ImagePath);
	std::string GetGuid(const std::string ImageName);
	void Delete(const std::string ImagePath);

	std::map<std::uint32_t, std::map<std::uint32_t, std::map<std::uint32_t, std::uint64_t>>> StructList;
	std::map<std::uint32_t, std::map<std::uint32_t, std::uint64_t>> FunctionList;
};