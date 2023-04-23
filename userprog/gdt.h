#ifndef USERPROG_GDT_H
#define USERPROG_GDT_H

#include "threads/loader.h"

/* Segment selectors.
   More selectors are defined by the loader in loader.h. */
#define SEL_UCSEG       0x1B    /* User code selector. 011(选择子3) 0 11(特权级3)*/
#define SEL_UDSEG       0x23    /* User data selector. 100(选择子4) 0 11(特权级3)*/
#define SEL_TSS         0x28    /* Task-state segment. 101(选择子5) 0 00(特权级0)*/
#define SEL_CNT         6       /* Number of segments. 5 + 1*/

void gdt_init (void);

#endif /* userprog/gdt.h */
