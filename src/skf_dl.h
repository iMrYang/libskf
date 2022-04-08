#ifndef __SKF_DL_H
#define __SKF_DL_H

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/* dll open/load/close function */
void *skf_dlopen(const char *file);
void *skf_dlsym(void *dll, const char *name);
void skf_dlclose(void *dll);

#ifdef __cplusplus
}
#endif  /* __cplusplus */
#endif  /* __SKF_DL_H */

