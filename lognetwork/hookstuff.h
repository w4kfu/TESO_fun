#ifndef HOOK_STUFF_H_
#define HOOK_STUFF_H_

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stddef.h>
#include <Winsock2.h>

#include <string>
#include <list>

#pragma comment(lib, "Ws2_32.lib")

#include "dbg.h"

#define LDE_X86 0

#ifdef __cplusplus
extern "C"
#endif
int __stdcall LDE(void* address , DWORD type);

void setup_hook(char *module, char *name_export, void *Hook_func, void *trampo, DWORD addr);
void setup_all_hook(void);

#endif // HOOK_STUFF_H_