del main_teso.exe

@cl.exe main_teso.c /W3 /GF /GS- /GA /MT /nologo /c /TC
@cl.exe aes.c /W3 /GF /GS- /GA /MT /nologo /c /TC
@link main_teso.obj aes.obj /release /subsystem:console /out:main_teso.exe /MACHINE:IX86 /BASE:0x400000 /MANIFEST:NO  /merge:.rdata=.text /DYNAMICBASE:NO

del *.obj
del *.exp
