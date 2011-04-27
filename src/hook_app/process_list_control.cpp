#include "stdafx.h"
#include "process_list_control.h"

#include <boost/format.hpp>
#include <boost/filesystem.hpp>
#include <tlhelp32.h>

#include "injector.h"
#include "../../src/hook_core/hook_comm.h"
#include "resource/resource.h"

using std::map;
using std::make_pair;
using boost::shared_ptr;
using boost::make_tuple;
using boost::wformat;
using boost::filesystem2::wpath;

namespace {
class AutoRecoverRedraw
{
public:
    explicit AutoRecoverRedraw(CWnd* w) : w_(w) { w->SetRedraw(FALSE); }
    ~AutoRecoverRedraw() { w_->SetRedraw(TRUE); }

private:
    CWnd* w_;
};

void initBoldFont(CFont* ref, shared_ptr<void>* font)
{
    LOGFONT fontDesc;
    ref->GetLogFont(&fontDesc);

    fontDesc.lfWeight = FW_BOLD;
    font->reset(CreateFontIndirect(&fontDesc), DeleteObject);
}

const wchar_t* hookStateToString(HookState state)
{
    switch (state) {
        case kHookAttempting:
            return L"Attempting";
        case kHookEnabled:
            return L"Enabled";
        case kHookDisabled:
            return L"Disabled";
        case kHookNoResponse:
            return L"No Response";
    }

    return NULL;
}
}

ProcessListControl::ProcessListControl()
    : CListCtrl()
    , process_(-1)
    , smallIcons_()
    , injector_()
    , hookStates_()
    , boldFont_()
{
    smallIcons_.Create(16, 16, ILC_MASK | ILC_COLORDDB, 1, 100);
}

ProcessListControl::~ProcessListControl()
{
}

void ProcessListControl::Init()
{
    DWORD style = GetStyle();
    SetWindowLong(*this, GWL_STYLE, style | LVS_REPORT | LVS_SINGLESEL);

    DWORD exStyle = GetExtendedStyle();
    SetExtendedStyle(exStyle | LVS_EX_FULLROWSELECT);

    CRect rect;
    GetClientRect(&rect);
    InsertColumn(0, L"Module Name", LVCFMT_LEFT, 160, 0);
    InsertColumn(1, L"Hook Status", LVCFMT_RIGHT, 80, 1);
    InsertColumn(2, L"PID", LVCFMT_CENTER, 75, 2);
    InsertColumn(3, L"Parent PID", LVCFMT_CENTER, 75, 3);
    InsertColumn(4, L"Exe Path", LVCFMT_LEFT, 100, 4);

    injector_.reset(Injector::CreateHookGetMessageInjector(GetSafeHwnd()));
    SetTimer(0, 1000, NULL);
}

void ProcessListControl::Update()
{
    AutoRecoverRedraw(this);
    DeleteAllItems();
    process_ = -1;

    shared_ptr<void> processSnapshot(
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), CloseHandle);
    if (!processSnapshot)
        return;

    PROCESSENTRY32 processInfo = {0};
    processInfo.dwSize = sizeof(processInfo);
    int itemIndex = 0;
    BOOL status = Process32First(
        reinterpret_cast<HANDLE>(processSnapshot.get()), &processInfo);
    while (status) {
        PROCESSENTRY32 info = processInfo;
        status = Process32Next(
            reinterpret_cast<HANDLE>(processSnapshot.get()), &processInfo);

        // Don't involve myself.
        if (!info.th32ProcessID ||
            (info.th32ProcessID == GetCurrentProcessId()))
            continue;

        // Retrieve the icon of the processes.
        shared_ptr<void> moduleSnapshot(
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, info.th32ProcessID),
            CloseHandle);
        if (!moduleSnapshot)
            continue;

        MODULEENTRY32 moduleInfo = {0};
        moduleInfo.dwSize = sizeof(moduleInfo);
        if (Module32First(reinterpret_cast<HANDLE>(moduleSnapshot.get()),
                          &moduleInfo)) {
            SHFILEINFO shellInfo = {0};
            if (SHGetFileInfo(moduleInfo.szExePath, 0, &shellInfo,
                              sizeof(shellInfo),
                              SHGFI_ICON | SHGFI_SMALLICON)) {
                ++process_;
                itemIndex = smallIcons_.Add(shellInfo.hIcon);
                InsertItem(process_, moduleInfo.szModule, itemIndex);

                HookStateMap::iterator i = hookStates_.find(info.th32ProcessID);
                const wchar_t* state = (i != hookStates_.end()) ?
                    hookStateToString(i->second.get<0>()) : L"N/A";

                // Item content.
                SetItemText(process_, 1, state);
                const wformat f(L"%d");
                SetItemText(process_, 2,
                            (wformat(f) % info.th32ProcessID).str().c_str());
                SetItemText(
                    process_, 3,
                    (wformat(f) % info.th32ParentProcessID).str().c_str());

                wpath exePath(moduleInfo.szExePath);
                SetItemText(process_, 4,
                            exePath.remove_filename().string().c_str());
                SetItemData(process_, info.th32ProcessID);
            }
        }

    }

    SetImageList(&smallIcons_, LVSIL_SMALL);
    autoSize();
}

void ProcessListControl::GetIdealSize(int* width, int* height)
{
    if (!width || !height)
        return;

    *width = 0;
    *height = 0;

    CHeaderCtrl* header = GetHeaderCtrl();
    if (!header)
        return;

    RECT headerRect;
    header->GetWindowRect(&headerRect);

    RECT itemRect;
    if (!GetItemRect(0, &itemRect, LVIR_BOUNDS))
        return;

    int count = GetItemCount();
    *height = (itemRect.bottom - itemRect.top) * count + 3 * count / 2 + 
        headerRect.bottom - headerRect.top;

    *width = itemRect.right - itemRect.left + 8;
}

BEGIN_MESSAGE_MAP(ProcessListControl, CListCtrl)
    ON_NOTIFY_REFLECT(NM_RCLICK, &ProcessListControl::OnRClick)
    ON_NOTIFY_REFLECT(NM_DBLCLK, &ProcessListControl::OnDblClick)
    ON_NOTIFY_REFLECT(NM_CUSTOMDRAW,
                      &ProcessListControl::OnCustomDrawListProcess)
    ON_COMMAND(ID_MENU_INJECT, &ProcessListControl::OnInject)
    ON_COMMAND(ID_MENU_DISABLE, &ProcessListControl::OnDisableHook)
    ON_COMMAND(ID_MENU_ENABLE, &ProcessListControl::OnEnableHook)
    ON_MESSAGE(kHookMessageHello, &ProcessListControl::OnHookHello)
    ON_WM_TIMER()
END_MESSAGE_MAP()

void ProcessListControl::OnRClick(NMHDR* desc, LRESULT* r)
{
    LV_DISPINFO* dispInfo = reinterpret_cast<LV_DISPINFO*>(desc);
    int currentSel = dispInfo->item.mask;
    if (currentSel < 0)
        return;

    // Please note that "dispInfo->item.lParam" equals 0 here.
    HookStateMap::iterator i = hookStates_.find(GetItemData(currentSel));
    const int subMenuIndex =
        (i == hookStates_.end()) ? 0 :
            (i->second.get<0>() == kHookDisabled) ? 2 : 1;

    CMenu menu;
    menu.LoadMenu(ID_MENU_FOR_LIST_CONTROL);
    CMenu* pop = menu.GetSubMenu(subMenuIndex);

    POINT cursorPos;
    GetCursorPos(&cursorPos);
    pop->TrackPopupMenu(0, cursorPos.x, cursorPos.y, this);

    *r = 0;
}

void ProcessListControl::OnDblClick(NMHDR *desc, LRESULT* r)
{
    LV_DISPINFO* dispInfo = reinterpret_cast<LV_DISPINFO*>(desc);
    int currentSel = dispInfo->item.mask;

    if ((currentSel >= 0) &&
        MessageBox(L"Terminate selected process?", L"WARNING",
                   MB_OKCANCEL | MB_ICONWARNING) == IDOK) {
        HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE,
                                  GetItemData(currentSel));
        if (proc && TerminateProcess(proc, 0)) {
            hookStates_.erase(GetItemData(currentSel));
            DeleteItem(currentSel);
        }
    }

    *r = 0;
}

void ProcessListControl::OnCustomDrawListProcess(NMHDR* desc, LRESULT* r)
{
    NMLVCUSTOMDRAW* customDrawDesc = reinterpret_cast<NMLVCUSTOMDRAW*>(desc);
    if (CDDS_PREPAINT == customDrawDesc->nmcd.dwDrawStage) {
        *r = CDRF_NOTIFYITEMDRAW; // Please notify me before draw an item.
        return;
    }

    if (CDDS_ITEMPREPAINT == customDrawDesc->nmcd.dwDrawStage) {
        *r = CDRF_NOTIFYSUBITEMDRAW; // Please notify me before draw a subitem.
        return;
    }

    // We'll change the appearance of any hooked item.
    if ((CDDS_ITEMPREPAINT | CDDS_SUBITEM) ==
        customDrawDesc->nmcd.dwDrawStage) {
        const int itemIndex = customDrawDesc->nmcd.dwItemSpec;

        if (itemIndex >= 0) {
            HookStateMap::iterator i =
                hookStates_.find(customDrawDesc->nmcd.lItemlParam);
            if (i != hookStates_.end()) {
                customDrawDesc->clrTextBk = 0xF0F0F0;

                if (!boldFont_)
                    initBoldFont(GetFont(), &boldFont_);

                SelectObject(customDrawDesc->nmcd.hdc,
                             reinterpret_cast<HGDIOBJ>(boldFont_.get()));
            }
        }
    }

    *r = CDRF_DODEFAULT;
}

void ProcessListControl::OnInject()
{
    int currentSel = getCurrentSel();
    if (currentSel < 0)
        return;

    const DWORD processID = GetItemData(currentSel);
    if (hookStates_.find(processID) == hookStates_.end()) {
        injector_->Inject(processID);

        HWND unknownWindow = NULL;
        hookStates_.insert(
            make_pair(processID,
                      make_tuple(kHookAttempting, unknownWindow, 0)));
        updateItem(currentSel, L"Attempting");
    }
}

void ProcessListControl::OnDisableHook()
{
    switchHookState(false);
}

void ProcessListControl::OnEnableHook()
{
    switchHookState(true);
}

LRESULT ProcessListControl::OnHookHello(WPARAM w, LPARAM l)
{
    HookState state = static_cast<HookState>(l);
    HWND winHandle = reinterpret_cast<HWND>(w);
    DWORD processID;
    DWORD threadID = GetWindowThreadProcessId(winHandle, &processID);
    HookStateMap::iterator i = hookStates_.find(processID);
    do {
        if (i == hookStates_.end()) {
            hookStates_.insert(make_pair(processID,
                                         make_tuple(state, winHandle, 0)));
        } else {
            if (i->second.get<0>() == state) {
                int& notRespondCount = i->second.get<2>();
                notRespondCount = 0;
                break; // The record is already up-to-date.
            }

            i->second = make_tuple(state, winHandle, 0);
        }

        int itemIndex = findItemByProcID(processID);
        assert(itemIndex >= 0);
        if (itemIndex >= 0)
            updateItem(itemIndex, hookStateToString(state));
    } while (0);

    return 0;
}

void ProcessListControl::OnTimer(UINT_PTR timerID)
{
    for (HookStateMap::iterator i = hookStates_.begin(), e = hookStates_.end();
        i != e; ++i) {
        int& notResponeCount = i->second.get<2>();
        if (++notResponeCount > 5) {

            // We'll remove the corresponding item if the process has
            // terminated.
            HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE,
                                      i->first);
            DWORD code = 0;
            if (GetExitCodeProcess(proc, &code) && (STILL_ACTIVE != code)) {
                int itemIndex = findItemByProcID(i->first);
                assert(itemIndex >= 0);
                DeleteItem(itemIndex);

                hookStates_.erase(i);
                break;
            }

            i->second.get<0>() = kHookNoResponse;
            int itemIndex = findItemByProcID(i->first);
            assert(itemIndex >= 0);
            updateItem(itemIndex, hookStateToString(kHookNoResponse));
        }
    }
}

inline int ProcessListControl::getCurrentSel()
{
    POSITION pos = GetFirstSelectedItemPosition();
    if (!pos)
        return -1;

    return GetNextSelectedItem(pos);
}

void ProcessListControl::autoSize()
{
    int numOfHeaders = GetHeaderCtrl()->GetItemCount();
    for (int i = 0; i < numOfHeaders; i++)
        SetColumnWidth(i, LVSCW_AUTOSIZE);
}

void ProcessListControl::updateItem(int index, const wchar_t* text)
{
    assert(index >= 0);
    SetItemText(index, 1, text);
    autoSize();

    RECT rect;
    GetItemRect(index, &rect, LVIR_BOUNDS);
    InvalidateRect(&rect, FALSE);
}

void ProcessListControl::switchHookState(bool enable)
{
    int currentSel = getCurrentSel();
    if (currentSel < 0)
        return;

    HookStateMap::iterator i = hookStates_.find(GetItemData(currentSel));
    assert(i != hookStates_.end());
    if (i == hookStates_.end())
        return;

    ::PostMessage(i->second.get<1>(),
                  enable ? kHookMessageEnable : kHookMessageDisable, 0, 0);
}

int ProcessListControl::findItemByProcID(int procID)
{
    LVFINDINFO findInfo = {0};
    findInfo.flags = LVFI_PARAM;
    findInfo.lParam = procID;
    return FindItem(&findInfo);
}