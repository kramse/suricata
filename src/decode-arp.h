/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Henrik Kramshoej <hlk@kramse.org>
 */

/*  Address Resolution Protocol.
 *
 * See RFC 826 for protocol description
 */

#ifndef __DECODE_ARP_H__
#define __DECODE_ARP_H__

#include "decode.h"

/* ARP has a fixed-length arphdr followed by variable-sized fields */
#define ARP_HEADER_LEN       8

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER    1       /* ethernet hardware format */
#endif
#ifndef ARPHRD_IEEE802
#define ARPHRD_IEEE802  6       /* IEEE 802 hardware format */
#endif
#ifndef ARPHRD_FRELAY
#define ARPHRD_FRELAY   15      /* frame relay hardware format */
#endif
#ifndef ARPHRD_IEEE1394
#define ARPHRD_IEEE1394 24      /* IEEE 1394 (FireWire) hardware format */
#endif
#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST   1       /* request to resolve address */
#endif
#ifndef ARPOP_REPLY
#define ARPOP_REPLY     2       /* response to previous request */
#endif
#ifndef ARPOP_REVREQUEST
#define ARPOP_REVREQUEST 3      /* request protocol address given hardware */
#endif
#ifndef ARPOP_REVREPLY
#define ARPOP_REVREPLY  4       /* response giving protocol address */
#endif
#ifndef ARPOP_INVREQUEST
#define ARPOP_INVREQUEST 8      /* request to identify peer */
#endif
#ifndef ARPOP_INVREPLY
#define ARPOP_INVREPLY  9       /* response identifying peer */
#endif

/* ARP header structure */
typedef struct  ARPHdr_ {
        u_int16_t ar_hrd;       /* format of hardware address */
        u_int16_t ar_pro;       /* format of protocol address */
        u_int8_t  ar_hln;       /* length of hardware address */
        u_int8_t  ar_pln;       /* length of protocol address */
        u_int16_t ar_op;        /* one of: */
} __attribute__((__packed__)) ARPHdr;
/*
 * The remaining fields are variable in size,
 * according to the sizes above.
 */
/*      u_int8_t  ar_sha[];      sender hardware address
        u_int8_t  ar_spa[];      sender protocol address
        u_int8_t  ar_tha[];      target hardware address
        u_int8_t  ar_tpa[];      target protocol address */


#define ARP_HEADER_PKT_OFFSET 0

/** macro for ARP "operation" access */
#define ARP_GET_OPERATION(p)      (p)->ARPh->ar_op
/** macro for ARP "code" access */

void DecodeARPRegisterTests(void);

#endif /* __DECODE_ARP_H__ */
