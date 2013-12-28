@cl.exe main.c /W3 /GF /GS- /GA /MT /nologo /c /TC /D"_CRT_SECURE_NO_WARNINGS"
@cl.exe mnf.c /W3 /GF /GS- /GA /MT /nologo /c /TC /D"_CRT_SECURE_NO_WARNINGS"
@cl.exe buffer.c /W3 /GF /GS- /GA /MT /nologo /c /TC /D"_CRT_SECURE_NO_WARNINGS"

@rc rsrc.rc
@link main.obj mnf.obj buffer.obj /release /subsystem:console  /SUBSYSTEM:CONSOLE,5.01 /out:TESO_mnf.exe /MACHINE:IX86 /BASE:0x400000 /MANIFEST:NO /merge:.rdata=.text /DYNAMICBASE:NO rsrc.res

del *.obj
del *.exp