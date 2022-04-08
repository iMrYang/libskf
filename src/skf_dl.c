/**
 * @brief Why define function rather than macro?
 *
 * Reason:
 * 1. <Windows.h> have already typedef LONG/ULONG and etc, Compile maybe warning
 * redefinition.
 * 2. <Windows.h> exist macro CreateFile, will replace SKF function ptr macro.
 *
 * So, platform function just exist this file, and not export to all project,
 * avoid typedef or macro conflit.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
/* Windows */
# include <Windows.h>
#else   /* _WIN32 */
/* Linux */
# include <dlfcn.h>
#endif  /* _WIN32 */
#include "skf_dl.h"

void *skf_dlopen(const char *file)
{
#ifdef _WIN32
    return (void *)LoadLibrary(file);
#else
    int flags = RTLD_LAZY|RTLD_LOCAL;
#ifdef RTLD_DEEPBIND
    flags |= RTLD_DEEPBIND;
#endif
    return dlopen(file, flags);
#endif
}

void *skf_dlsym(void *dll, const char *name)
{
#ifdef _WIN32
    return (void *)GetProcAddress((HMODULE)dll, (LPCSTR)name);
#else
    return dlsym(dll, name);
#endif
}

void skf_dlclose(void *dll)
{
    if (dll) {
#ifdef _WIN32
        FreeLibrary((HMODULE)dll);
#else
        dlclose(dll);
#endif
    }
}

