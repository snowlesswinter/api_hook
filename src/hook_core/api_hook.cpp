#include "api_hook.h"

#include <cassert>
#include <string>

#include <boost/scoped_array.hpp>
#include <boost/algorithm/string.hpp>
#include <windows.h>
#include <imagehlp.h>
#include <tlhelp32.h>

using std::string;
using std::map;
using std::make_pair;
using boost::shared_ptr;
using boost::algorithm::iequals;

namespace {
bool tamperImportTable(const char* moduleName, const void* APIAddress,
                       const void* customFunc, void* targetModule,
                       HANDLE writableProcHandle,
                       IMAGE_IMPORT_DESCRIPTOR* importDesc)
{
    assert(targetModule);
    if (!targetModule)
        return false;

    assert(importDesc);

    // Whether the dll module which our interested API locates in is in this
    // import table?
    char* moduleBaseAddr = reinterpret_cast<char*>(targetModule);
    for (; importDesc->Name; ++importDesc) {
        string dllName = moduleBaseAddr + importDesc->Name;
        if (!iequals(dllName, moduleName))
            continue;

        // Start to search the interested API.
        IMAGE_THUNK_DATA* thunk =
            reinterpret_cast<IMAGE_THUNK_DATA*>(
                moduleBaseAddr + importDesc->FirstThunk);
        for (; thunk->u1.Function; ++thunk) {
            void** importFunc = reinterpret_cast<void**>(&thunk->u1.Function);

            // The search will fail if another hooking with the same technique
            // has taken place.
            if (*importFunc == APIAddress) {
                
                // We found it.
                const void* customFuncAlias = customFunc;
                if (!WriteProcessMemory(writableProcHandle, importFunc,
                                        &customFuncAlias,
                                        sizeof(customFuncAlias), NULL)) {
                    DWORD oldProtect;
                    if (!VirtualProtectEx(writableProcHandle, importFunc,
                                          sizeof(customFuncAlias),
                                          PAGE_READWRITE, &oldProtect)) {
                        // Not all processes can be modified.
                        DWORD err = GetLastError();
                        return false;
                    }

                    if (!WriteProcessMemory(writableProcHandle, importFunc,
                                            &customFuncAlias,
                                            sizeof(customFuncAlias), NULL))
                        return false;
                }

                return true;
            }
        }
    }

    // API not found.
    return false;
}
}

HookTask::HookTask(const char* moduleName, const void* APIAddress,
                   const void* customFunction,
                   const shared_ptr<void>& customFuncModule)
    : moduleName_(moduleName)
    , APIAddress_(APIAddress)
    , customFuncModule_(customFuncModule)
    , customFunction_(customFunction)
{
}

HookTask::HookTask(const HookTask& ref)
    : moduleName_(ref.moduleName_)
    , APIAddress_(ref.APIAddress_)
    , customFuncModule_(ref.customFuncModule_)
    , customFunction_(ref.customFunction_)
{
}

HookTask::~HookTask()
{
}

HookTask& HookTask::operator=(const HookTask& ref)
{
    moduleName_ = ref.moduleName_;
    APIAddress_ = ref.APIAddress_;
    customFuncModule_ = ref.customFuncModule_;
    customFunction_ = ref.customFunction_;
    return *this;
}

//----------------------------------------------------------------------------
APIHookBase::~APIHookBase()
{
    HANDLE h = reinterpret_cast<HANDLE>(writableProcHandle_.get());
    for (map<string, HookTask>::iterator i = hookTasks_.begin(),
        e = hookTasks_.end(); i != e; ++i) {
        for (map<void*, void*>::iterator j = hookedModules_.begin(),
            f = hookedModules_.end(); j != f; ++j) {

            MEMORY_BASIC_INFORMATION info;
            if ((VirtualQuery(j->first, &info, sizeof(info)) == sizeof(info)) &&
                (info.State != MEM_COMMIT))
                continue;

            // Unhook by simply exchange the API address and custom function.
            tamperImportTable(
                i->second.GetModuleName(), i->second.GetCustomFunction(),
                i->second.GetAPIAddress(), j->first, h,
                reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(j->second));
        }
    }
}

bool APIHookBase::Hook(const string& APIName, const HookTask& hookTask)
{
    // We'll hook all modules in a process by default.
    shared_ptr<void> moduleSnapshot(
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId()),
        CloseHandle);
    MODULEENTRY32 moduleInfo = {0};
    moduleInfo.dwSize = sizeof(moduleInfo);
    BOOL status = Module32First(reinterpret_cast<HANDLE>(moduleSnapshot.get()),
                                &moduleInfo);
    while (status) {
        void* moduleBaseAddress = moduleInfo.modBaseAddr;

        bool exclude = (hookCoreBaseAddress_ == moduleBaseAddress);
        if (!exclude)
            exclude = (moduleBaseAddress == hookTask.GetCustomFuncModule());

        if (!exclude) {

            for (map<string, HookTask>::iterator i = hookTasks_.begin(),
                e = hookTasks_.end(); i != e; ++i) {

                // Do not hook the custom function modules.
                if (moduleInfo.modBaseAddr == i->second.GetCustomFuncModule()) {
                    exclude = true;
                    break;
                }
            }
        }

        status = Module32Next(reinterpret_cast<HANDLE>(moduleSnapshot.get()),
                              &moduleInfo);
        if (exclude)
            continue;

        // Find IMAGE_IMPORT_DESCRIPTOR structure in the target PE image.
        DWORD size;
        IMAGE_IMPORT_DESCRIPTOR* importDesc = 
            reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
                ImageDirectoryEntryToDataEx(
                    moduleBaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT,
                    &size, NULL));
        if (!importDesc) {
            // Note that not every module(such as "kernel32.dll") is permitted
            // to access its import table.
            continue;
        }

        tamperImportTable(hookTask.GetModuleName(), hookTask.GetAPIAddress(),
                          hookTask.GetCustomFunction(), moduleBaseAddress,
                          reinterpret_cast<HANDLE>(writableProcHandle_.get()),
                          importDesc);

        hookedModules_.insert(make_pair(moduleBaseAddress, importDesc));
    }

    hookTasks_.insert(make_pair(APIName, hookTask));
    return true;
}

bool APIHookBase::HookModule(const string& APIName, const HookTask& hookTask,
                         void* targetModule)
{
    // Find IMAGE_IMPORT_DESCRIPTOR structure in the target PE image.
    DWORD size;
    IMAGE_IMPORT_DESCRIPTOR* importDesc = 
        reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            ImageDirectoryEntryToDataEx(
                targetModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, NULL));
    if (!importDesc) {
        // Note that not every module(such as "kernel32.dll") is permitted
        // to access its import table.
        return false;
    }

    tamperImportTable(hookTask.GetModuleName(), hookTask.GetAPIAddress(),
                      hookTask.GetCustomFunction(), targetModule,
                      reinterpret_cast<HANDLE>(writableProcHandle_.get()),
                      importDesc);

    hookTasks_.insert(make_pair(APIName, hookTask));
    if (hookedModules_.find(targetModule) == hookedModules_.end())
        hookedModules_.insert(make_pair(targetModule, importDesc));

    return true;
}

bool APIHookBase::duplicateToModule(void* module)
{
    // Find IMAGE_IMPORT_DESCRIPTOR structure in the target PE image.
    DWORD size;
    IMAGE_IMPORT_DESCRIPTOR* importDesc = 
        reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            ImageDirectoryEntryToDataEx(
                module, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, NULL));
    if (!importDesc) {
        // Note that not every module(such as "kernel32.dll") is permitted
        // to access its import table.
        return false;
    }

    if (hookedModules_.find(module) == hookedModules_.end()) {
        for (map<string, HookTask>::iterator i = hookTasks_.begin(),
            e = hookTasks_.end(); i != e; ++i) {
            tamperImportTable(
                i->second.GetModuleName(), i->second.GetAPIAddress(),
                i->second.GetCustomFunction(), module,
                reinterpret_cast<HANDLE>(writableProcHandle_.get()),
                importDesc);
        }

        hookedModules_.insert(make_pair(module, importDesc));
    }

    return true;
}

bool APIHookBase::removeHookFromModule(void* module)
{
    map<void*, void*>::iterator iter = hookedModules_.find(module);
    if (iter == hookedModules_.end())
        return true;

    for (map<string, HookTask>::iterator i = hookTasks_.begin(),
        e = hookTasks_.end(); i != e; ++i) {
        tamperImportTable(
                i->second.GetModuleName(), i->second.GetAPIAddress(),
                i->second.GetCustomFunction(), module,
                reinterpret_cast<HANDLE>(writableProcHandle_.get()),
                reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(iter->second));
    }

    hookedModules_.erase(module);
    return true;
}

void APIHookBase::notifyModuleFreed(void* module)
{
    map<void*, void*>::iterator i = hookedModules_.find(module);
    if (i == hookedModules_.end())
        return;

    MEMORY_BASIC_INFORMATION info;
    if ((VirtualQuery(i->first, &info, sizeof(info)) == sizeof(info)) &&
        (info.State != MEM_COMMIT))
        hookedModules_.erase(i);
}

const void* APIHookBase::retrieveDummy(const char* APIName)
{
    map<string, HookTask>::iterator i = hookTasks_.find(APIName);
    if (i != hookTasks_.end())
        return i->second.GetCustomFunction();

    return NULL;
}

APIHookBase::APIHookBase(const void* hookCoreBaseAddress)
    : hookTasks_()
    , hookedModules_()
    , hookCoreBaseAddress_(hookCoreBaseAddress)
    , writableProcHandle_(
        OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE,
                    GetCurrentProcessId()),
        CloseHandle)
{
    assert(hookCoreBaseAddress_);
}

//------------------------------------------------------------------------------
APIHook* APIHook::hooker = NULL;
APIHook* APIHook::GetHooker()
{
    return hooker;
}

void APIHook::Initialize(const void* hookCoreBaseAddress)
{
    if (!hooker)
        hooker = new APIHook(hookCoreBaseAddress);
}

void APIHook::Finalize()
{
    if (hooker) {
        delete hooker;
        hooker = NULL;
    }
}

APIHook::~APIHook()
{
}

void* __stdcall APIHook::dummyLoadLibraryA(const char* dllName)
{
    void* m = LoadLibraryA(dllName);
    if (m) {
        if (hooker)
            hooker->duplicateToModule(m);
    }

    return m;
}

void* __stdcall APIHook::dummyLoadLibraryW(const wchar_t* dllName)
{
    void* m = LoadLibraryW(dllName);
    if (m) {
        if (hooker)
            hooker->duplicateToModule(m);
    }

    return m;
}

void* __stdcall APIHook::dummyLoadLibraryExA(const char* dllName, void* file,
                                             unsigned int flags)
{
    void* m = LoadLibraryExA(dllName, file, flags);
    if (m && (!(flags & LOAD_LIBRARY_AS_DATAFILE))) {
        if (hooker)
            hooker->duplicateToModule(m);
    }

    return m;
}

void* __stdcall APIHook::dummyLoadLibraryExW(const wchar_t* dllName, void* file,
                                              unsigned int flags)
{
    void* m = LoadLibraryExW(dllName, file, flags);
    if (m && (!(flags & LOAD_LIBRARY_AS_DATAFILE))) {
        if (hooker)
            hooker->duplicateToModule(m);
    }

    return m;
}

const void* __stdcall APIHook::dummyGetProcAddress(void* m, const char* name)
{
    void* p = GetProcAddress(reinterpret_cast<HMODULE>(m), name);
    if (p && (reinterpret_cast<int>(name) & 0xFFFF0000)) {
        if (hooker) {
            const void* d = hooker->retrieveDummy(name);
            if (d)
                return d;
        }
    }

    return p;
}

int __stdcall APIHook::dummyFreeLibrary(void* m)
{
    int rv = FreeLibrary(reinterpret_cast<HMODULE>(m));
    if (m) {
        if (hooker)
            hooker->notifyModuleFreed(m);
    }

    return rv;
}

APIHook::APIHook(const void* hookCoreBaseAddress)
    : APIHookBase(hookCoreBaseAddress)
{
    shared_ptr<void> dontNeedModuleRef;
    Hook(
        string("LoadLibraryA"),
        HookTask("kernel32.dll",
                 GetProcAddress(GetModuleHandle(L"kernel32.dll"),
                                "LoadLibraryA"), dummyLoadLibraryA,
                 dontNeedModuleRef));

    Hook(
        string("LoadLibraryW"),
        HookTask("kernel32.dll",
                 GetProcAddress(GetModuleHandle(L"kernel32.dll"),
                                "LoadLibraryW"), dummyLoadLibraryW,
                 dontNeedModuleRef));

    Hook(
        string("LoadLibraryExA"),
        HookTask("kernel32.dll",
                 GetProcAddress(GetModuleHandle(L"kernel32.dll"),
                                "LoadLibraryExA"), dummyLoadLibraryExA,
                 dontNeedModuleRef));

    Hook(
        string("LoadLibraryExW"),
        HookTask("kernel32.dll",
                 GetProcAddress(GetModuleHandle(L"kernel32.dll"),
                                "LoadLibraryExW"), dummyLoadLibraryExW,
                 dontNeedModuleRef));

    Hook(
        string("GetProcAddress"),
        HookTask("kernel32.dll",
                 GetProcAddress(GetModuleHandle(L"kernel32.dll"),
                                "GetProcAddress"), dummyGetProcAddress,
                 dontNeedModuleRef));

    Hook(
        string("FreeLibrary"),
        HookTask("kernel32.dll",
                 GetProcAddress(GetModuleHandle(L"kernel32.dll"),
                                "FreeLibrary"), dummyFreeLibrary,
                 dontNeedModuleRef));
}