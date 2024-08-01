#include "BytePatch.hpp"

namespace NewBase
{
	BytePatch::~BytePatch()
	{
		Restore();
	}

	void BytePatch::Apply() const
	{
		DWORD old;

		VirtualProtect(m_Address, m_Size, PAGE_EXECUTE_READWRITE, &old);
		std::copy_n(m_Patch.get(), m_Size, reinterpret_cast<byte*>(m_Address));
		VirtualProtect(m_Address, m_Size, old, nullptr);
	}

	void BytePatch::Restore() const
	{
		DWORD old;

		VirtualProtect(m_Address, m_Size, PAGE_EXECUTE_READWRITE, &old);
		std::copy_n(m_Original.get(), m_Size, reinterpret_cast<byte*>(m_Address));
		VirtualProtect(m_Address, m_Size, old, nullptr);
	}

	void BytePatch::Remove() const
	{
		if (const auto it = std::find(gPatches.begin(), gPatches.end(), this); it != gPatches.end())
		{
			gPatches.erase(it);
		}
	}

	void BytePatch::RestoreAll()
	{
		gPatches.clear();
	}

	bool operator==(const std::unique_ptr<BytePatch>& a, const BytePatch* b)
	{
		return a->m_Address == b->m_Address;
	}
}