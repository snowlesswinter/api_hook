#include "injector.h"

#include <windows.h>
#include <tlhelp32.h>

using boost::shared_ptr;

Injector* Injector::CreateHookGetMessageInjector(void* host)
{
    return new HookGetMessageInjector(host);
}

Injector::~Injector()
{
}

Injector::Injector(void* host)
    : hookCore_()
    , hookProc_(NULL)
{
    HMODULE m = LoadLibrary(L"hook_core.dll");
    shared_ptr<void> autoRelease(m, FreeLibrary);

    HOOKPROC hookProc = reinterpret_cast<HOOKPROC>(
        GetProcAddress(m, "ForHookGetMessageInjection"));
    if (!hookProc)
        return;

    void (__stdcall* initHostWindowFunc)(void*);
    initHostWindowFunc = reinterpret_cast<void (__stdcall*)(void*)>(
        GetProcAddress(m, "InitHostWindowHandle"));
    if (!initHostWindowFunc)
        return;

    hookCore_ = autoRelease;
    hookProc_ = hookProc;
    initHostWindowFunc(host);
}

//------------------------------------------------------------------------------
HookGetMessageInjector::~HookGetMessageInjector()
{
}

HookGetMessageInjector::HookGetMessageInjector(void* host)
    : Injector(host)
    , hookHandle_()
{
}

int HookGetMessageInjector::Inject(int processID)
{
    assert(processID && (processID != GetCurrentProcessId()));

    // TODO: Manager all hook handle in a specific module.

    if (!getHookProc() || !getHookCoreModule())
        return -1;

    shared_ptr<void> threadSnapshot(
        CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0), CloseHandle);
    if (!threadSnapshot)
        return -1;

    THREADENTRY32 threadInfo = {0};
    threadInfo.dwSize = sizeof(threadInfo);
    BOOL status = Thread32First(
        reinterpret_cast<HANDLE>(threadSnapshot.get()), &threadInfo);
    while (status) {
        THREADENTRY32 info = threadInfo;
        status = Thread32Next(
            reinterpret_cast<HANDLE>(threadSnapshot.get()), &threadInfo);
        if ((info.th32OwnerProcessID != processID) || !info.th32ThreadID)
            continue;

        hookHandle_.reset(
            SetWindowsHookEx(WH_GETMESSAGE,
                             reinterpret_cast<HOOKPROC>(getHookProc()),
                             reinterpret_cast<HINSTANCE>(getHookCoreModule()),
                             info.th32ThreadID),
            UnhookWindowsHookEx);
        if (hookHandle_) {

            // Enforce hooking.
            PostThreadMessage(info.th32ThreadID, WM_PAINT, 0, 0);
            return 0;
        }
    }

    return -1;
}