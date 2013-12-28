#include "main.h"

HINSTANCE	hInst;
int			ScreenWidth;
int			ScreenHeigth;
WNDPROC     g_wndProcOriginalListViewHeader;
HWND 		listView;

LRESULT CALLBACK MainProc(HWND Dlg,UINT message,WPARAM wParam,LPARAM lParam);

BOOL OpenMNFFiles(HWND hwnd)
{
	OPENFILENAME ofn;
	char szFile[MAX_PATH];
	HANDLE hf;
	char *p;

	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hwnd;
	ofn.lpstrFile = szFile;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = "MNF Files (*.mnf)\0*.mnf\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (GetOpenFileNameA(&ofn) == FALSE)
	{
		return FALSE;
	}
	hf = CreateFileA(ofn.lpstrFile, 
					GENERIC_READ,
					FILE_SHARE_READ,
					(LPSECURITY_ATTRIBUTES) NULL,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL,
					(HANDLE) NULL);
	if (hf == INVALID_HANDLE_VALUE)
	{
		printf("[-] CreateFile()\n");
		return FALSE;
	}
	p = strrchr(ofn.lpstrFile, '.');
	if (p)
	{
		*p = 0;
	}
	printf("[+] FileName = %s\n", ofn.lpstrFile);
	return ReadMNF(hf, ofn.lpstrFile);
}

LRESULT WndProcListViewHeader(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
   switch(msg)
   {
      case WM_NOTIFY:
      {
         NMHDR *nmhdr = (NMHDR*)lParam;
         if (HDN_BEGINTRACKW == nmhdr->code || HDN_BEGINTRACKA == nmhdr->code)
         {
            return TRUE;
         }
      }
      /*case WM_SETCURSOR:
      {
         return TRUE;
      }
      case WM_LBUTTONDBLCLK:
      {
         return TRUE;
      }*/
   }
   return CallWindowProc(g_wndProcOriginalListViewHeader, hWnd, msg, wParam, lParam);
}

void ListViewAddItems(struct entry_table3 *Entry, DWORD dwType)
{
	LVITEM lvItem;
	char Buf[0x100]; 
   
   lvItem.mask = LVIF_TEXT;

   lvItem.iItem = 0;
   sprintf(Buf, "%08X", Entry->UncompSize);
   lvItem.pszText = Buf;
   lvItem.iSubItem = 0;
   SendMessage(listView, LVM_INSERTITEM, 0, (LPARAM)&lvItem);
   sprintf(Buf, "%08X", Entry->CompSize);
   lvItem.pszText = Buf;
   lvItem.iSubItem = 1;
   ListView_SetItem(listView, &lvItem);
   sprintf(Buf, "%08X", Entry->unk_0);
   lvItem.pszText = Buf;
   lvItem.iSubItem = 2;
   ListView_SetItem(listView, &lvItem);
   sprintf(Buf, "%08X", Entry->Offset);
   lvItem.pszText = Buf;
   lvItem.iSubItem = 3;
   ListView_SetItem(listView, &lvItem);
   sprintf(Buf, "%08X", Entry->Type);
   lvItem.pszText = Buf;
   lvItem.iSubItem = 4;
   ListView_SetItem(listView, &lvItem);
   sprintf(Buf, "%08X", Entry->ArchiveNum);
   lvItem.pszText = Buf;
   lvItem.iSubItem = 5;
   ListView_SetItem(listView, &lvItem);
   sprintf(Buf, "%08X", Entry->unk_1);
   lvItem.pszText = Buf;
   lvItem.iSubItem = 6;
   ListView_SetItem(listView, &lvItem);
   sprintf(Buf, "%s (%08X)", TypeFile(dwType), dwType);
   lvItem.pszText = Buf;
   lvItem.iSubItem = 7;
   ListView_SetItem(listView, &lvItem);
}

BOOL InitColumn(HWND hWin)
{
    LVCOLUMN lvc;
	HWND hwndListViewHeader;

    listView = GetDlgItem(hWin,IDC_LISTVIEW);
	ListView_SetExtendedListViewStyle(listView, ListView_GetExtendedListViewStyle(listView) | LVS_EX_FULLROWSELECT);
	hwndListViewHeader = ListView_GetHeader(listView);
	g_wndProcOriginalListViewHeader = (WNDPROC)SetWindowLong(listView, GWLP_WNDPROC, (LONG_PTR)WndProcListViewHeader);	
	
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;

    lvc.cx = 130;
    lvc.pszText = "FMT";
    ListView_InsertColumn(listView, 0, &lvc);		
	
    lvc.cx = 70;
    lvc.pszText = "Unk1";
    ListView_InsertColumn(listView, 0, &lvc);	
	
    lvc.cx = 70;
    lvc.pszText = "Archive";
    ListView_InsertColumn(listView, 0, &lvc);	
	
    lvc.cx = 70;
    lvc.pszText = "Type";
    ListView_InsertColumn(listView, 0, &lvc);	
	
    lvc.cx = 70;
    lvc.pszText = "Offset";
    ListView_InsertColumn(listView, 0, &lvc);	
	
    lvc.cx = 70;
    lvc.pszText = "Unk";
    ListView_InsertColumn(listView, 0, &lvc);	
	
    lvc.cx = 70;
    lvc.pszText = "CSize";
    ListView_InsertColumn(listView, 0, &lvc);	
	
    lvc.cx = 90;
    lvc.pszText = "Size";
    ListView_InsertColumn(listView, 0, &lvc);

	printf("[+] InitColumn\n");
	return TRUE;
}

int main(void)
{
	HWND console;
	HMODULE hMod;

	console = GetConsoleWindow();
	
	hMod = GetModuleHandle(NULL);
	hInst = hMod;
	InitCommonControls();
	ScreenWidth = GetSystemMetrics(SM_CXSCREEN);
	ScreenHeigth = GetSystemMetrics(SM_CYSCREEN);
	
	DialogBoxParam(hMod, (LPCTSTR)IDD_DLGMAIN, NULL, (DLGPROC)MainProc, 0);
}

LRESULT CALLBACK MainProc(HWND hWin,UINT message,WPARAM wParam,LPARAM lParam)
{
   int Select;

   switch(message)
   {
   case WM_INITDIALOG:
	   {
			InitColumn(hWin);
			break;
	   }
   case WM_COMMAND:
			Select = LOWORD(wParam);
			switch(Select)
			{
				case IDC_BUTTONOK:
				case IDM_OPEN:
				{
					OpenMNFFiles(hWin);
					break;
				}
				case IDC_BUTTONEXIT:
				case IDM_EXIT:
					{
						SendMessage(hWin, WM_CLOSE, 0, 0);
						break;
					}			
				default:
					break;
			}
			break;
   case WM_CLOSE:
   case WM_DESTROY:
			EndDialog(hWin,0);
			break;
   default:
      return FALSE;
   }
   return TRUE;
}