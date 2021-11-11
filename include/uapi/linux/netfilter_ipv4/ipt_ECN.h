/* Header file for iptables ipt_ECN target
 *
 * (C) 2002 by Harald Welte <laforge@gnumonks.org>
 *
 * This software is distributed under GNU GPL v2, 1991
 * 
 * ipt_ECN.h,v 1.3 2002/05/29 12:17:40 laforge Exp
*/
#ifndef _IPT_ECN_TARGET_H
#define _IPT_ECN_TARGET_H

#include <linux/types.h>
#include <linux/netfilter/xt_DSCP_2.h>

#define IPT_ECN_IP_MASK	(~XT_DSCP_MAS