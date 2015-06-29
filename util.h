#ifndef    __UTIL_H__
#define    __UTIL_H__
#include <stdarg.h>
#define nfc_dbg(fmt, args...) do{ fprintf(stderr, "%s/%s(%d): " fmt, \
     __func__,__FILE__, __LINE__, ##args); }while(0)
#define handle_error(msg) do { perror(msg); exit(EXIT_FAILURE); }while(0)

char * zsys_sprintf (const char *format, ...);
char * zsys_vprintf (const char *format, va_list argptr);
int systemf(const char* format, ...);


/* the following are for testing */
#define MODE_NAT 0
#define MODE_BRIDGE 1
#define MODE_ROUTER 2
#define MODE_L2TPX2 3
#define MODE_L2TPX3 4
#define MODE_GREX2 5
#define MODE_GREX3 6
#define MODE_PPTP 7
#define MODE_PPPOE 8


#endif
