#include "main.h"

HINSTANCE	hInst;
int			ScreenWidth;
int			ScreenHeigth;

LRESULT CALLBACK MainProc(HWND Dlg,UINT message,WPARAM wParam,LPARAM lParam);

BOOL OpenMNFFiles(HWND hwnd)
{
	OPENFILENAME ofn;
	char szFile[MAX_PATH];
	HANDLE hf;


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
	return ReadMNF(hf);
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