#ifndef    __UTIL_H__
#define    __UTIL_H__
#include <stdarg.h>
#define dbg(msg) do { }while(0)
#define handle_error(msg) do { perror(msg); exit(EXIT_FAILURE); }while(0)

char * zsys_sprintf (const char *format, ...);
char * zsys_vprintf (const char *format, va_list argptr);
int systemf(const char* format, ...);



#endif
