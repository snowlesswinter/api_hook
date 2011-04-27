#ifndef _API_HOOK_H_
#define _API_HOOK_H_

#include <map>
#include <string>

#include <boost/shared_ptr.hpp>

enum HookState
{
    kHookAttempting,
    kHookEnabled,
    kHookDisabled,
    kHookNoResponse,
};

//------------------------------------------------------------------------------
class HookTask
{
public:
    HookTask(const char* moduleName, const void* APIAddress,
             const void* customFunction,
             const boost::shared_ptr<void>& customFuncModule);
    HookTask(const HookTask& ref);
    ~HookTask();

    HookTask& operator=(const HookTask& ref);

    const char* GetModuleName() const { return moduleName_.c_str(); }
    const void* GetAPIAddress() const { return APIAddress_; }
    const void* GetCustomFunction() const { return customFunction_; }
    const void* GetCustomFuncModule() const { return customFuncModule_.get(); }

private:
    std::string moduleName_;
    const void* APIAddress_;
    boost::shared_ptr<void> customFuncModule_;
    const void* customFunction_;
};

//------------------------------------------------------------------------------
// Not thread-safe.
class APIHookBase
{
public:
    ~APIHookBase();

    bool Hook(const std::string& APIName, const HookTask& hookTask);
    bool HookModule(const std::string& APIName, const HookTask& hookTask,
                    void* targetModule);

protected:
    explicit APIHookBase(const void* hookCoreBaseAddress);

    bool duplicateToModule(void* module);
    bool removeHookFromModule(void* module);
    void notifyModuleFreed(void* module);
    const void* retrieveDummy(const char* APIName);

private:
    std::map<std::string, HookTask> hookTasks_;

    // The second element is the start address of the IMAGE_IMPORT_DESCRIPTOR
    // of the module. We store these descriptors because
    // ImageDirectoryEntryToDataEx may not be available since it is possible
    // that we may access import address table when the dbghelp.dll is already
    // unloaded, at which ImageDirectoryEntryToDataEx locates.
    std::map<void*, void*> hookedModules_;
    const void* hookCoreBaseAddress_;
    boost::shared_ptr<void> writableProcHandle_;
};

//------------------------------------------------------------------------------

class APIHook : public APIHookBase
{
public:
    static APIHook* GetHooker();
    static void Initialize(const void* hookCoreBaseAddress);
    static void Finalize();

    ~APIHook();

private:
    static APIHook* hooker;

    static void* __stdcall dummyLoadLibraryA(const char* dllName);
    static void* __stdcall dummyLoadLibraryW(const wchar_t* dllName);
    static void* __stdcall dummyLoadLibraryExA(const char* dllName,
                                               void* file, unsigned int flags);
    static void* __stdcall dummyLoadLibraryExW(const wchar_t* dllName,
                                               void* file, unsigned int flags);
    static const void* __stdcall dummyGetProcAddress(void* m, const char* name);
    static int __stdcall dummyFreeLibrary(void* m);

    explicit APIHook(const void* hookCoreBaseAddress);
};

#endif  // _API_HOOK_H_