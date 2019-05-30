#ifndef _VBH_STATUS_H_
#define _VBH_STATUS_H_

#include <asm/errno.h>

/*
    Values should be used only as defined constants, do not return hardcoded integer values.
    The status values may change in future.
*/

#define     EVBHBASE                0x10000
#define     EPROCNSTOP              EVBHBASE + 0x1  // Processors not stopped
#define     EPROCNRESUME            EVBHBASE + 0x2  // Processors not started

#endif