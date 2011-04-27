#include <cassert>
#include <string>
#include <list>

#include <boost/scoped_array.hpp>
#include <boost/intrusive_ptr.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <windows.h>
#include <process.h>

#include "api_hook.h"
#include "custom_hook_desc.h"
#include "hook_comm.h"
#include "intrusive_ptr_helper.h"

using std::string;
using std::wstring;
using std::pair;
using std::list;
using std::make_pair;
using boost::scoped_array;
using boost::shared_ptr;
using boost::intrusive_ptr;
using boost::filesystem2::wpath;
using boost::filesystem2::wdirectory_iterator;
using boost::system::system_error;
using boost::algorithm::iequals;

#pragma data_seg("shared")
#pragma comment(linker, "/section:shared,rws")
HWND globalHostWindow = NULL;
#pragma data_seg()

namespace {
HMODULE hookCoreModule = NULL;
HMODULE avoidUnload = NULL;

bool hookVirtualMethodVoid(void* obj, int methodOffset, const void* dummy,
                           void** originalFuncAddr)
{
    if (!originalFuncAddr)
        return false;

    char** vTableAddr = reinterpret_cast<char**>(obj);
    char* vTable = *vTableAddr;
    void* funcAddr = vTable + methodOffset;
    if (!memcmp(&dummy, funcAddr, sizeof(dummy)))
        return true;

    // Store the original function, or it would be lost.
    memcpy(originalFuncAddr, funcAddr, sizeof(*originalFuncAddr));
    if (!WriteProcessMemory(GetCurrentProcess(), funcAddr,
                            &dummy, sizeof(dummy), NULL)) {
        shared_ptr<void> h(
            OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE,
                        GetCurrentProcessId()),
            CloseHandle);
        DWORD oldProtect;
        if (h &&
            VirtualProtectEx(reinterpret_cast<HANDLE>(h.get()), funcAddr,
                             sizeof(dummy), PAGE_READWRITE, &oldProtect)) {
            if (WriteProcessMemory(reinterpret_cast<HANDLE>(h.get()), funcAddr,
                                   &dummy, sizeof(dummy), NULL))
                return true;
        }

        return false;
    }

    return true;
}

union MethodToVoidCast
{
    HRESULT (__stdcall IUnknown::* MethodAddr)();
    const void* VoidMethodAddr;
};

union MethodAddressToVoidCast
{
    HRESULT (__stdcall IUnknown::** MethodAddrPointer)();
    void** VoidMethodAddrPointer;
};

template <typename DummyType, typename OriginalType>
inline bool hookVirtualMethod(void* obj, int methodOffset, DummyType dummy,
                              OriginalType* originalFuncAddr)
{
    MethodToVoidCast c1;
    c1.MethodAddr = reinterpret_cast<HRESULT (__stdcall IUnknown::*)()>(dummy);
    MethodAddressToVoidCast c2;
    c2.MethodAddrPointer =
        reinterpret_cast<HRESULT (__stdcall IUnknown::**)()>(originalFuncAddr);
    return hookVirtualMethodVoid(obj, methodOffset, c1.VoidMethodAddr,
                                 c2.VoidMethodAddrPointer);
}

//------------------------------------------------------------------------------
int __stdcall dummyStdcall0()
{
    return 0;
}

int __stdcall dummyStdcall1(void* p1)
{
    return 0;
}

int __stdcall dummyStdcall2(void* p1, void* p2)
{
    return 0;
}

int __stdcall dummyStdcall3(void* p1, void* p2, void* p3)
{
    return 0;
}

int __stdcall dummyStdcall4(void* p1, void* p2, void* p3, void* p4)
{
    return 0;
}

int __stdcall dummyStdcall5(void* p1, void* p2, void* p3, void* p4, void* p5)
{
    return 0;
}

int __stdcall dummyStdcall6(void* p1, void* p2, void* p3, void* p4, void* p5, void* p6)
{
    return 0;
}

int __stdcall dummyStdcall7(void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7)
{
    return 0;
}

int __stdcall dummyStdcall8(void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8)
{
    return 0;
}

int __stdcall dummyStdcall9(void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9)
{
    return 0;
}

//------------------------------------------------------------------------------
void loadProcHookTask(CustomProcHookDescEnumCreateFunc createEnum,
                      const shared_ptr<void>& customFunModule,
                      list<pair<string, HookTask> >* tasks)
{
    assert(createEnum);
    intrusive_ptr<CustomProcHookDescEnum> descEnum;
    if (createEnum(reinterpret_cast<CustomProcHookDescEnum**>(&descEnum)) < 0)
        return;

    descEnum->Reset();
    for (;;) {
        intrusive_ptr<CustomProcedureDesc> desc;
        if (!descEnum->Next(reinterpret_cast<CustomProcedureDesc**>(&desc)))
            break;

        const int bufSize = 128;
        char APIName[bufSize];
        int actualSize = desc->GetAPIName(APIName, bufSize);
        assert(actualSize < bufSize);

        char moduleName[bufSize];
        actualSize = desc->GetAPIModuleName(moduleName, bufSize);
        assert(actualSize < bufSize);

        shared_ptr<void> m(LoadLibraryA(moduleName), FreeLibrary);
        if (!m)
            return;

        const void* f = GetProcAddress(reinterpret_cast<HMODULE>(m.get()),
                                       APIName);
        HookTask task(moduleName, f, desc->GetCustomFuncAddress(),
                      customFunModule);
        tasks->push_back(make_pair(string(APIName), task));
    }
}

const void* getDummyFuncBySignature(FactoryProcSignature s, int objIndex)
{
    switch (s) {
        case kR_stdcall_0:
            return dummyStdcall0;
        case kR_stdcall_1:
            return dummyStdcall1;
        case kR_stdcall_2:
            break;
        case kR_stdcall_3:
            break;
        case kR_stdcall_4:
            break;
        case kR_stdcall_5:
            break;
        case kR_stdcall_6:
            break;
        case kR_stdcall_7:
            break;
        case kR_stdcall_8:
            break;
        case kR_stdcall_9:
            break;
        default:
            assert(false);
            return NULL;
    }

    return NULL;
}

void loadCOMHookTaskFromFactory(const intrusive_ptr<COMFactoryAPIDesc>& desc,
                                const shared_ptr<void>& customFunModule,
                                const string& APIModuleName,
                                list<pair<string, HookTask> >* tasks)
{
    const int nameLength = desc->GetFactoryProcedureName(NULL, 0);
    if (nameLength) {
        const void* dummyFactoryFunc =
            getDummyFuncBySignature(desc->GetFactoryProcSignature(),
            desc->GetCOMObjSeqNum());
        if (!dummyFactoryFunc)
            return;

        scoped_array<char> buf(new char[nameLength + 1]);
        desc->GetFactoryProcedureName(buf.get(), nameLength + 1);

        shared_ptr<void> m(LoadLibraryA(APIModuleName.c_str()), FreeLibrary);
        if (!m)
            return;

        const void* f = GetProcAddress(reinterpret_cast<HMODULE>(m.get()),
                                       buf.get());
        HookTask task(APIModuleName.c_str(), f, dummyFactoryFunc,
                      customFunModule);
        tasks->push_back(make_pair(string(buf.get()), task));
    }
}

void loadCOMHookTask(const intrusive_ptr<CustomCOMHookDesc>& desc,
                     const shared_ptr<void>& customFunModule,
                     list<pair<string, HookTask> >* tasks)
{
    const int bufSize = 128;
    char moduleName[bufSize];
    int actualSize = desc->GetAPIModuleName(moduleName, bufSize);
    assert(actualSize < bufSize);
}

void loadCOMHookTask(CustomCOMHookDescEnumCreateFunc createEnum,
                     const shared_ptr<void>& customFunModule,
                     list<pair<string, HookTask> >* tasks)
{
//     assert(createEnum);
//     intrusive_ptr<CustomCOMHookDescEnum> descEnum;
//     if (createEnum(reinterpret_cast<CustomCOMHookDescEnum**>(&descEnum)) < 0)
//         return;
// 
//     descEnum->Reset();
//     for (;;) {
//         intrusive_ptr<CustomCOMHookDesc> desc;
//         if (!descEnum->Next(reinterpret_cast<CustomCOMHookDesc**>(&desc)))
//             break;
// 
//         const int bufSize = 128;
//         char APIName[bufSize];
//         int actualSize = desc->GetAPIName(APIName, bufSize);
//         assert(actualSize < bufSize);
// 
//         char moduleName[bufSize];
//         actualSize = desc->GetAPIModuleName(moduleName, bufSize);
//         assert(actualSize < bufSize);
// 
//         shared_ptr<void> m(LoadLibraryA(moduleName), FreeLibrary);
//         if (!m)
//             return;
// 
//         const void* f = GetProcAddress(reinterpret_cast<HMODULE>(m.get()),
//                                        APIName);
//         HookTask task(moduleName, f, desc->GetCustomFuncAddress(),
//                       customFunModule);
//         tasks->push_back(make_pair(string(APIName), task));
//     }
}

void loadHookTask(wstring customHook, list<pair<string, HookTask> >* tasks)
{
    assert(tasks);
    HMODULE m = LoadLibrary(customHook.c_str());
    if (!m)
        return;

    shared_ptr<void> autoRelease(m, FreeLibrary);
    CustomProcHookDescEnumCreateFunc f =
        reinterpret_cast<CustomProcHookDescEnumCreateFunc>(
            GetProcAddress(m, "CreateCustomHookDescEnum"));
    if (f)
        loadProcHookTask(f, autoRelease, tasks);

    CustomCOMHookDescEnumCreateFunc g =
        reinterpret_cast<CustomCOMHookDescEnumCreateFunc>(
            GetProcAddress(m, "CreateCOMHookDescEnum"));
    if (g)
        loadCOMHookTask(g, autoRelease, tasks);
}

void loadHookTasks(void* moduleBase, list<pair<string, HookTask> >* tasks)
{
    assert(tasks);
    boost::scoped_array<wchar_t> buf(new wchar_t[MAX_PATH]);
    GetModuleFileName(reinterpret_cast<HMODULE>(moduleBase), buf.get(),
                      MAX_PATH);
    wpath dllPath(buf.get());
    try {
        for (wdirectory_iterator i(dllPath.remove_filename()),
            e = wdirectory_iterator(); i != e; ++i) {
            if (iequals(i->path().extension(), L".dll") &&
                (i->path() != buf.get()))
                loadHookTask(i->path().string(), tasks);
        }
    } catch (const system_error& ex) {
        (ex);
    }
}

void hook(void* moduleBase)
{
    list<pair<string, HookTask> > tasks;

    // See what user requested.
    loadHookTasks(moduleBase, &tasks);
    for (list<pair<string, HookTask> >::iterator i = tasks.begin(),
        e = tasks.end(); i != e; ++i)
        APIHook::GetHooker()->Hook(i->first, i->second);
}

unsigned int __stdcall threadEntry(void* param)
{
    // Put it here because we don't wanna load libraries in "DllMain".
    hook(param);

    HMODULE hh = LoadLibraryA("C:/WINDOWS/system32/Macromed/Flash/Flash10o.ocx");

    HINSTANCE inst = reinterpret_cast<HINSTANCE>(param);
    WNDCLASS windowClass = {0};
    windowClass.lpszClassName = L"HookCommunicationWindow";
    windowClass.hInstance = inst;
    windowClass.lpfnWndProc = DefWindowProc;
    ATOM classAtom = RegisterClass(&windowClass);
    wchar_t* className = reinterpret_cast<wchar_t*>(classAtom);
    shared_ptr<void> w(CreateWindow(className, L"", WS_OVERLAPPED, 0, 0, 0, 0,
                                    NULL, NULL, inst, NULL),
                       DestroyWindow);
    if (!w)
        return 0;

    HWND winHandle = reinterpret_cast<HWND>(w.get());
    SetTimer(winHandle, 0, 1000, NULL);

    assert(globalHostWindow);
    PostMessage(globalHostWindow, kHookMessageHello,
                reinterpret_cast<WPARAM>(winHandle), kHookEnabled);

    HookState state = kHookEnabled;
    MSG message;
    while (GetMessage(&message, winHandle, 0, 0)) {
        if (WM_TIMER == message.message) {
            PostMessage(globalHostWindow, kHookMessageHello,
                        reinterpret_cast<WPARAM>(winHandle), state);
            continue;
        }

        if (kHookMessageDisable == message.message) { // Disable hooking.
            state = kHookDisabled;
            continue;
        }

        if (kHookMessageEnable == message.message) { // Enable hooking.
            state = kHookEnabled;
            continue;
        }

        TranslateMessage(&message); 
        DispatchMessage(&message); 
    }
    return 0;
}

bool isHookApp(void* moduleBase)
{
    scoped_array<wchar_t> buf(new wchar_t[MAX_PATH]);
    GetModuleFileName(NULL, buf.get(), MAX_PATH);
    wpath exePath(buf.get());

    memset(buf.get(), 0, sizeof(buf[0]) * MAX_PATH);
    GetModuleFileName(reinterpret_cast<HMODULE>(moduleBase), buf.get(),
                      MAX_PATH);
    wpath hookCorePath(buf.get());
    return (exePath.remove_filename() == hookCorePath.remove_filename());
}

inline void startHooking(void* moduleBase)
{
    hookCoreModule = reinterpret_cast<HMODULE>(moduleBase);
    if (isHookApp(moduleBase))
        return;

    // Safe. See comment in DllMain.
    if (APIHook::GetHooker())
        return;

    APIHook::Initialize(moduleBase);
    _beginthreadex(NULL, 0, threadEntry, moduleBase, 0, NULL);
}

inline void stopHooking()
{
    // Safe. See comment in DllMain.
    APIHook::Finalize();
}
}

BOOL __stdcall DllMain(HMODULE module, DWORD reasonForCall, void* reserved)
{
    // A typical process would be like this:
    //
    // 1. Target process load the hook core, and DllMain is called, during which
    //    we create a thread and initialize hooking.
    // 2. At a certain point of time, the process ends, and the thread is
    //    terminated(by exiting the main thread). Then, we'll do the clean-up at
    //    DllMain with the reason "DLL_PROCESS_DETACH".
    //
    // Some matters of fact that we should consider:
    //
    // 1. Once the hook core is loaded, there is no way controlling when to
    //    unload it.
    // 2. As a result of the above fact, DllMain being called for
    //    "DLL_PROCESS_DETACH" is the only and final chance for us to do the
    //    clean-up. It's the operating system that has guaranteed a synchronized
    //    process of initialization and final clean-up stuff, so that we are
    //    saved from figuring out lots of lock-like mechanisms to achieve that.
    // 3. When "DLL_PROCESS_DETACH", the main thread is about to end, which
    //    means no any thread lives at that point. The thread we created when
    //    initializing will be terminated at any point of time! i.e., any kind
    //    of resource acquisition in that thread is dangerous! Even the hooking
    //    initialization.
    //
    //    So why we still creating thread even there is so much danger? Could
    //    We put the hooking initialization in the message handling routine?
    //
    //    First, we could put it into DllMain, but the initialization is
    //    correspondingly complicated, and involves dll loading, which are both
    //    recommended to be avoided in MSDN. Second, we could put it inside the
    //    message handling routine, but neither of these alternatives can
    //    continually communicate with other processes, by which we can enable
    //    or disable hooking at runtime.
    // 4. During DllMain, do not try to wait for anything. It'll probably lead
    //    to dead waiting. Do not wait for a thread handle which is definitely
    //    signaled in the process of exiting.

    switch (reasonForCall) {
        case DLL_PROCESS_ATTACH:
            startHooking(module);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            stopHooking();
            break;
    }

    return TRUE;
}

LRESULT __stdcall ForHookGetMessageInjection(int code, WPARAM w, LPARAM l)
{
    if (!avoidUnload) {

        // We load hook core again so that it won't be unloaded when the hook
        // is unset.
        assert(hookCoreModule);
        scoped_array<wchar_t> buf(new wchar_t[MAX_PATH]);
        GetModuleFileName(hookCoreModule, buf.get(), MAX_PATH);
        avoidUnload = LoadLibrary(buf.get());
    }

    // Just pass through.
    return CallNextHookEx(NULL, code, w, l);
}

void __stdcall InitHostWindowHandle(void* hostWindow)
{
    globalHostWindow = reinterpret_cast<HWND>(hostWindow); // test git 1
}