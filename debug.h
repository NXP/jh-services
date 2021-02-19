/*
 * Copyright 2020-2021 NXP
 *
 * the code contained herein is licensed under the gnu general public
 * license. you may obtain a copy of the gnu general public license
 * version 2 or later at the following locations:
 *
 * http://www.opensource.org/licenses/gpl-license.html
 * http://www.gnu.org/copyleft/gpl.html
 *
 * Brief    Map LK printing system to the Kernel one
 */

#ifndef __DEBUG_H
#define __DEBUG_H

#include <linux/kern_levels.h>
#include <linux/printk.h>

/* Mapping LK debug levels to Kernel levels */
#define LK_EMERG      KERN_EMERG
#define LK_ALERT      KERN_ALERT
#define LK_CRIT       KERN_CRIT
#define LK_ERR        KERN_ERR
#define LK_WARNING    KERN_WARNING
#define LK_NOTICE     KERN_NOTICE
#define LK_INFO       KERN_INFO
#define LK_DEBUG      KERN_DEBUG
/* Mapping LK_VERBOSE as new level */
#define LK_VERBOSE    KERN_SOH "8"

#if defined(VERBOSE_DEBUG) || defined(DEBUG)
#define printlk_dbg(level, prnt...) printk(KERN_DEBUG prnt)
#else
#define printlk_dbg(level, prnt...) no_printk(KERN_DEBUG prnt)
#endif

/*
 * Mapping LK printlk() macro to Kernel printk()
 *
 * All printk() are copied to the Kernel's ring buffer. For this reason,
 * prints which are called over and over again, must have LK_VERBOSE level.
 * printlk() call with this level will be printed out only if DEBUG or
 * VERBOSE_DEBUG are defined, to avoid ring buffer overrun.
 */
#define printlk(level, prnt...) \
    do { \
        if (printk_get_level(level)) \
            printk(level prnt); \
        else \
            printlk_dbg(level, prnt); \
    } while (0)

#endif /* __DEBUG_H */
