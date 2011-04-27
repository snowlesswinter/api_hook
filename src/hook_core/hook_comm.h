#ifndef _HOOK_COMM_H_
#define _HOOK_COMM_H_

enum HookMessage
{
    kHookMessageHello = WM_USER + 501,
    kHookMessageDisable,
    kHookMessageEnable,
};

#endif  // _HOOK_COMM_H_