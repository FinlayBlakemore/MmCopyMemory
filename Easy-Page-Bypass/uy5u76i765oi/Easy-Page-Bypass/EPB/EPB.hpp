#pragma once

#include <Memory/Memory.hpp>
#include <PDB/PDB.hpp>

namespace EPB
{
	inline PDB* Pdb = new PDB();

	bool Setup();
}