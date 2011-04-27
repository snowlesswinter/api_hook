#ifndef _HOOK_APP_DLG_H_
#define _HOOK_APP_DLG_H_

#include "process_list_control.h"

class HookAppDlg : public CDialog
{
public:
    enum { IDD = IDD_HOOK_APP_DIALOG };

    HookAppDlg(CWnd* parent = NULL);

protected:
    virtual void DoDataExchange(CDataExchange* dataExchange);
    virtual BOOL OnInitDialog();

    void OnSysCommand(UINT commandID, LPARAM lParam);
    void OnPaint();
    HCURSOR OnQueryDragIcon();
    void OnSize(UINT type, int width, int height);
    void OnButtonRefresh();

    DECLARE_MESSAGE_MAP()

private:
    HICON icon_;
    ProcessListControl listProcesses_;

    // Layout.
    int listWidthDiff_;
    int listHeightDiff_;
    int OKButtonLeft_;
    int OKButtonTop_;
    int refreshButtonLeft_;
    int refreshButtonTop_;
};

#endif  // _HOOK_APP_DLG_H_