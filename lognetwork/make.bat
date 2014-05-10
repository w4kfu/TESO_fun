@cl.exe inject.cpp /W3 /GF /GS- /GA /MT /nologo /EHs /TP /c
@link inject.obj /release /subsystem:console /SUBSYSTEM:console,5.01 /OSVERSION:5.1 /out:inject.exe /MACHINE:IX86 /BASE:0x400000 /MANIFEST:NO  /merge:.rdata=.text /DYNAMICBASE:NO

@cl.exe main.cpp /W3 /GF /GS- /GA /MT /nologo /EHs /TP /c
@cl.exe dbg.cpp /W3 /GF /GS- /GA /MT /nologo /EHs /TP /c
@cl.exe hookstuff.cpp /W3 /GF /GS- /GA /MT /nologo /EHs /TP /c
@cl.exe packet.cpp /W3 /GF /GS- /GA /MT /nologo /EHs /TP /c
@cl.exe scanmem.cpp /W3 /GF /GS- /GA /MT /nologo /EHs /TP /c
@link main.obj dbg.obj hookstuff.obj packet.obj scanmem.obj lib/LDE64.lib lib/zlib.lib cryptopp/cryptlib.lib /dll /release /subsystem:console /SUBSYSTEM:console,5.01 /OSVERSION:5.1 /out:lognetwork.dll /MACHINE:IX86 /BASE:0x400000 /MANIFEST:NO  /merge:.rdata=.text /DYNAMICBASE:NO

del *.obj
del *.exp

pause