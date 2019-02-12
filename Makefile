NAME   = xt-gexpo
CFLAGS = /c /Gz /MD /O2 /DUNICODE /nologo
LFLAGS = /DLL /NXCOMPAT /DYNAMICBASE /nologo
LIBS   = Kernel32.lib Ole32.lib Pathcch.lib Shell32.lib User32.lib

L32 = $(LFLAGS) /MACHINE:X86 $(LIBS) /DEF:src\$(NAME)-x86.def
L64 = $(LFLAGS) /MACHINE:X64 $(LIBS) 

.SILENT:

dummy:
    echo "Available targets:"
    echo "  nmake win32"
    echo "  nmake win64"
    echo "  nmake clean"

win32:
    cl $(CFLAGS) src\$(NAME).c /Fo$(NAME).o
    link $(L32) /OUT:build\$(NAME)-x86.dll $(NAME).o
    del $(NAME).o
    del build\$(NAME)-x86.exp
    del build\$(NAME)-x86.lib

win64:
    cl $(CFLAGS) src\$(NAME).c /Fo$(NAME).o
    link $(L64) /OUT:build\$(NAME)-x64.dll $(NAME).o
    del $(NAME).o
    del build\$(NAME)-x64.exp
    del build\$(NAME)-x64.lib

clean:
    del $(NAME)*.o            2>NUL
    del build\$(NAME)-x86.dll 2>NUL
    del build\$(NAME)-x64.dll 2>NUL
    del build\$(NAME)-x86.exp 2>NUL
    del build\$(NAME)-x64.exp 2>NUL
    del build\$(NAME)-x86.lib 2>NUL
    del build\$(NAME)-x64.lib 2>NUL
