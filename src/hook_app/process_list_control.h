#ifndef _PROCESS_LIST_CONTROL_H_
#define _PROCESS_LIST_CONTROL_H_

#include <map>

#include <boost/scoped_ptr.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/tuple/tuple.hpp>

#include "../../src/hook_core/api_hook.h"
#include "resource/resource.h"

class Injector;
class ProcessListControl : public CListCtrl
{
public:
    ProcessListControl();
    virtual ~ProcessListControl();

    void Init();
    void Update();
    void GetIdealSize(int* width, int* height);

protected:
    void OnRClick(NMHDR* desc, LRESULT* r);
    void OnDblClick(NMHDR* desc, LRESULT* r);
    void OnCustomDrawListProcess(NMHDR* desc, LRESULT* r);
    void OnInject();
    void OnDisableHook();
    void OnEnableHook();
    LRESULT OnHookHello(WPARAM w, LPARAM l);
    void OnTimer(UINT_PTR timerID);

    DECLARE_MESSAGE_MAP()

private:
    typedef std::map<DWORD, boost::tuple<HookState, HWND, int> > HookStateMap;

    int getCurrentSel();
    void autoSize();
    void updateItem(int index, const wchar_t* text);
    void switchHookState(bool enable);
    int findItemByProcID(int procID);

    int process_;
    CImageList smallIcons_;
    boost::scoped_ptr<Injector> injector_;
    HookStateMap hookStates_;
    boost::shared_ptr<void> boldFont_;
};

#endif // _PROCESS_LIST_CONTROL_H_