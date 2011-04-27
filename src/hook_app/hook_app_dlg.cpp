#include "stdafx.h"
#include "hook_app_dlg.h"

#include "hook_app.h"

class CAboutDlg : public CDialog
{
public:
    enum { IDD = IDD_ABOUTBOX };

    CAboutDlg() : CDialog(CAboutDlg::IDD) {}

protected:
    virtual void DoDataExchange(CDataExchange* dataExchange);

    DECLARE_MESSAGE_MAP()
};

void CAboutDlg::DoDataExchange(CDataExchange* dataExchange)
{
    CDialog::DoDataExchange(dataExchange);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()

//------------------------------------------------------------------------------
HookAppDlg::HookAppDlg(CWnd* parent /*=NULL*/)
    : CDialog(HookAppDlg::IDD, parent)
    , icon_(AfxGetApp()->LoadIcon(IDR_MAINFRAME))
    , listProcesses_()
    , listWidthDiff_(0)
    , listHeightDiff_(0)
    , OKButtonLeft_(0)
    , OKButtonTop_(0)
    , refreshButtonLeft_(0)
    , refreshButtonTop_(0)
{
}

void HookAppDlg::DoDataExchange(CDataExchange* dataExchange)
{
    CDialog::DoDataExchange(dataExchange);
    DDX_Control(dataExchange, IDC_LIST_PROCESS, listProcesses_);
}

BEGIN_MESSAGE_MAP(HookAppDlg, CDialog)
    ON_WM_SYSCOMMAND()
    ON_WM_PAINT()
    ON_WM_QUERYDRAGICON()
    ON_WM_SIZE()
    ON_BN_CLICKED(IDC_BUTTON_REFRESH, &HookAppDlg::OnButtonRefresh)
END_MESSAGE_MAP()

BOOL HookAppDlg::OnInitDialog()
{
    CDialog::OnInitDialog();

    assert((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
    assert(IDM_ABOUTBOX < 0xF000);

    CMenu* sysMenu = GetSystemMenu(FALSE);
    if (sysMenu) {
        BOOL nameValid;
        CString aboutMenu;
        nameValid = aboutMenu.LoadString(IDS_ABOUTBOX);
        assert(nameValid);
        if (!aboutMenu.IsEmpty()) {
            sysMenu->AppendMenu(MF_SEPARATOR);
            sysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, aboutMenu);
        }
    }

    SetIcon(icon_, TRUE);
    SetIcon(icon_, FALSE);

    listProcesses_.Init();
    listProcesses_.Update();

    RECT myRect;
    GetClientRect(&myRect);
    RECT itemRect;
    listProcesses_.GetWindowRect(&itemRect);
    listWidthDiff_ = myRect.right - (itemRect.right - itemRect.left);
    listHeightDiff_ = myRect.bottom - (itemRect.bottom - itemRect.top);

    CWnd* item = GetDlgItem(IDOK);
    assert(item);
    assert(item->GetSafeHwnd());
    POINT leftTop = {0};
    item->MapWindowPoints(this, &leftTop, 1);
    OKButtonLeft_ = myRect.right - leftTop.x;
    OKButtonTop_ = myRect.bottom - leftTop.y;

    item = GetDlgItem(IDC_BUTTON_REFRESH);
    assert(item);
    assert(item->GetSafeHwnd());
    memset(&leftTop, 0, sizeof(leftTop));
    item->MapWindowPoints(this, &leftTop, 1);
    refreshButtonLeft_ = myRect.right - leftTop.x;
    refreshButtonTop_ = myRect.bottom - leftTop.y;

    int idealWidth;
    int idealHeight;
    listProcesses_.GetIdealSize(&idealWidth, &idealHeight);
    idealWidth = min(GetSystemMetrics(SM_CXFULLSCREEN) * 9 / 10, idealWidth);
    idealHeight = min(GetSystemMetrics(SM_CYFULLSCREEN) * 9 / 10, idealHeight);
    SetWindowPos(NULL, 0, 0, idealWidth + listWidthDiff_,
                 idealHeight + listHeightDiff_, SWP_NOMOVE | SWP_NOZORDER);
    return TRUE;
}

void HookAppDlg::OnSysCommand(UINT commandID, LPARAM lParam)
{
    if ((commandID & 0xFFF0) == IDM_ABOUTBOX) {
        CAboutDlg dlgAbout;
        dlgAbout.DoModal();
    } else {
        CDialog::OnSysCommand(commandID, lParam);
    }
}

void HookAppDlg::OnPaint()
{
    if (IsIconic()) {
        CPaintDC dc(this);

        SendMessage(WM_ICONERASEBKGND,
                    reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

        int cxIcon = GetSystemMetrics(SM_CXICON);
        int cyIcon = GetSystemMetrics(SM_CYICON);
        CRect rect;
        GetClientRect(&rect);
        int x = (rect.Width() - cxIcon + 1) / 2;
        int y = (rect.Height() - cyIcon + 1) / 2;

        dc.DrawIcon(x, y, icon_);
    } else {
        CDialog::OnPaint();
    }
}

HCURSOR HookAppDlg::OnQueryDragIcon()
{
    return static_cast<HCURSOR>(icon_);
}

void HookAppDlg::OnSize(UINT type, int width, int height) 
{
    // Maybe called before the list control is created.
    if (listProcesses_.GetSafeHwnd())
	    listProcesses_.SetWindowPos(NULL, 0, 0, width - listWidthDiff_,
                                    height - listHeightDiff_,
                                    SWP_NOMOVE | SWP_NOZORDER);

	CWnd* item = GetDlgItem(IDOK);
    if (item != NULL && item->GetSafeHwnd()) {
		item->SetWindowPos(NULL, width - OKButtonLeft_, height - OKButtonTop_,
                           0, 0, SWP_NOSIZE | SWP_NOZORDER);
    }

	item = GetDlgItem(IDC_BUTTON_REFRESH);
	if (item && item->GetSafeHwnd())
		item->SetWindowPos(NULL, width - refreshButtonLeft_,
                           height - refreshButtonTop_, 0, 0,
                           SWP_NOSIZE | SWP_NOZORDER);

	CDialog::OnSize(type, width, height);
}

void HookAppDlg::OnButtonRefresh()
{
    BeginWaitCursor();
	listProcesses_.Update();
	EndWaitCursor();
}