#include "Pointers.hpp"

#include "memory/BytePatch.hpp"
#include "memory/ModuleMgr.hpp"
#include "memory/PatternScanner.hpp"
#include "util/Joaat.hpp"

namespace NewBase
{
	bool Pointers::Init()
	{
		auto scanner = PatternScanner(ModuleMgr::Get("GTA5.exe"_J));

		strcpy(ModuleMgr::Get("GTA5.exe"_J)->GetPdbFilePath(), (std::filesystem::current_path() / "GTA5.pdb").string().c_str());

		constexpr auto queueDependency = Pattern<"E8 ? ? ? ? B8 A0 00 00 00">("QueueDependency");
		scanner.Add(queueDependency, [this](PointerCalculator ptr) {
			m_QueueDependency = ptr.Add(1).Rip().As<PVOID>();
		});

		constexpr auto initMemAllocator = Pattern<"83 C8 01 48 8D 0D ? ? ? ? 41 B1 01 45 33 C0">("InitMemAllocator");
		scanner.Add(initMemAllocator, [this](PointerCalculator ptr) {
			*ptr.Add(17).As<uint32_t*>() = 650 * 1024 * 1024;
		});

		constexpr auto SMPACreateStub = Pattern<"49 63 F0 48 8B EA B9 07 00 00 00">("SMPACreateStub");
		scanner.Add(SMPACreateStub, [this](PointerCalculator ptr) {
			m_SMPACreateStub = ptr.Sub(0x29).As<PVOID>();
		});

		constexpr auto readGameConfig = Pattern<"48 89 5C 24 10 55 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC 30 48 8B F9">("ReadGameConfig");
		scanner.Add(readGameConfig, [this](PointerCalculator ptr) {
			m_ReadGameConfig = ptr.As<PVOID>();
		});

		constexpr auto getPoolSize = Pattern<"45 33 DB 44 8B D2 66 44 39 59 10 74 4B">("GetPoolSize");
		scanner.Add(getPoolSize, [this](PointerCalculator ptr) {
			m_GetPoolSize = ptr.As<PVOID>();
		});

		constexpr auto createPool = Pattern<"40 53 48 83 EC 20 8B 44 24 50 48 83">("CreatePool");
		scanner.Add(createPool, [this](PointerCalculator ptr) {
			m_CreatePool = ptr.As<PVOID>();
		});

		constexpr auto getPoolItem = Pattern<"4C 8B D1 48 63 49 18">("GetPoolItem");
		scanner.Add(getPoolItem, [this](PointerCalculator ptr) {
			m_GetPoolItem = ptr.As<PVOID>();
		});

		constexpr auto onProgramLoad = Pattern<"48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 33 FF 48 8B D9 40">("OnProgramLoad");
		scanner.Add(onProgramLoad, [this](PointerCalculator ptr) {
			m_OnProgramLoad = ptr.As<PVOID>();
		});

		constexpr auto resetThread = Pattern<"40 53 48 83 EC 20 48 8B D9 E8 ? ? ? ? 48 8D 93 D4">("ResetThread");
		scanner.Add(resetThread, [this](PointerCalculator ptr) {
			m_ResetThread = ptr.As<PVOID>();
		});

		constexpr auto killThread = Pattern<"48 89 5C 24 08 57 48 83 EC 20 48 83 B9 18 01">("KillThread");
		scanner.Add(killThread, [this](PointerCalculator ptr) {
			m_KillThread = ptr.As<PVOID>();
		});

		constexpr auto scriptVM = Pattern<"48 8B C4 4C 89 40 18 48 89 50 10 48 89 48 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 68 A1 48 81 EC B8">("ScriptVM");
		scanner.Add(scriptVM, [this](PointerCalculator ptr) {
			m_ScriptVM = ptr.As<PVOID>();
		});

		constexpr auto getNativeHandler = Pattern<"48 8D 0D ? ? ? ? 48 8B 14 FA">("GetNativeHandler");
		scanner.Add(getNativeHandler, [this](PointerCalculator ptr) {
			m_NativesTable = ptr.Add(3).Rip().As<void*>();
			m_GetNativeHandler = ptr.Add(11).Rip().As<GetNativeHandler>();
		});

		if (!scanner.Scan())
		{
			LOG(FATAL) << "Some patterns could not be found, unloading.";
			return false;
		}

		return true;
	}

	bool Pointers::InitScriptHook()
	{
		ModuleMgr::Refresh();

		auto scanner = PatternScanner(ModuleMgr::Get("ScriptHookV.dll"_J));

		constexpr auto onlineCheck = Pattern<"74 3A 48 8D 0D">("OnlineCheck");
		scanner.Add(onlineCheck, [this](PointerCalculator ptr) {
			BytePatch::Make(ptr.As<void*>(), std::to_array({0xEB}))->Apply();
		});

		constexpr auto poolStuff = Pattern<"41 81 FA 2C 23 82 11">("PoolStuff");
		scanner.Add(poolStuff, [this](PointerCalculator ptr) {
			BytePatch::Make(ptr.As<void*>(), std::vector<uint8_t>(34, 0x90))->Apply();
			BytePatch::Make(ptr.Add(34).As<void*>(), std::to_array({0xEB}))->Apply();
		});

		constexpr auto poolStuff2 = Pattern<"B8 00 01 00 00 3B C3">("PoolStuff2");
		scanner.Add(poolStuff2, [this](PointerCalculator ptr) {
			BytePatch::Make(ptr.As<void*>(), std::vector<uint8_t>(10, 0x90))->Apply();
		});

		scanner.Scan();

		return true;
	}
}