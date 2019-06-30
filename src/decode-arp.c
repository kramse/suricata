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
 * \ingroup decode
 *
 * @{
 */


/**
 * \file
 *
 * \author Henrik Kramshoej <hlk@kramse.org>
 *
 * Decode Address Resolution Protocol see RFC 826 for protocol description
 */

#include "suricata-common.h"

#include "decode.h"
#include "decode-events.h"
#include "decode-arp.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"
#include "util-print.h"



/** DecodeARP
 *  \brief Main ARP decoding function
 */
int DecodeARP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint32_t len, PacketQueue *pq)
{
    StatsIncr(tv, dtv->counter_arp);

    if (unlikely(len < ETHERNET_HEADER_LEN + ARP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ARP_PKT_TOO_SMALL);
        return -1;
    }

    p->arph = (ARPHdr *)(pkt + ETHERNET_HEADER_LEN);

    printf("\n");
/*    printf("Packet bytes\n");
    int i = 0;
    for (0; i < len; i++)
    {
      printf("%02x ", pkt[i]);
    }
    printf("\n");

    printf("Struct arph\n");
    printf("%0d \n", p->arph->ar_hrd);
    printf("%0d \n", p->arph->ar_pro);
    printf("%02x \n", p->arph->ar_hln);
    printf("%02x \n", p->arph->ar_pln);
    printf("%0d \n", p->arph->ar_op);*/

    switch (SCNtohs(p->arph->ar_hrd))
    {
        case ARPHRD_ETHER:
            printf("ARP hardware format Ethernet ");
            break;
        case ARPHRD_IEEE802:
            printf("ARP hardware format IEEE802 ");
            break;
        case ARPHRD_FRELAY:
            printf("ARP hardware format Frame Relay ");
            break;
        case ARPHRD_IEEE1394:
            /* request protocol address given hardware */
            printf("ARP hardware format IEEE1394 ");
            break;

        default:
            printf("ARP hardware format unknown\n");
            ENGINE_SET_EVENT(p,ARP_UNKNOWN_HARDWARE_FORMAT);
    }

    switch (SCNtohs(p->arph->ar_pro))
    {
        case ETHERNET_TYPE_IP:
            printf("protocol type IPv4 ");
            int arp_len;
            arp_len = 2 * ( (u_int8_t) p->arph->ar_hln + (u_int8_t) p->arph->ar_pln );
            if (len < ETHERNET_HEADER_LEN + ARP_HEADER_LEN + arp_len) {
                ENGINE_SET_INVALID_EVENT(p, ARP_PKT_TRUNCATED);
                return -1;
            }
            break;
        default:
            printf("ARP protocol type unknown\n");
            ENGINE_SET_EVENT(p,ARP_UNKNOWN_PROTOCOL);
    }

    switch (SCNtohs(p->arph->ar_op))
    {
        case ARPOP_REQUEST:
            /* request to resolve address */
            printf("ARP OPERATION REQUEST\n");
            break;
        case ARPOP_REPLY:
            /* response to previous request */
            printf("ARP operation REPLY\n");
            break;
        case ARPOP_REVREQUEST:
            /* request protocol address given hardware */
            printf("ARP operation REVREQUEST\n");
            break;
        case ARPOP_REVREPLY:
            /* response giving protocol address */
            printf("ARP operation REVREPLY\n");
            break;
        case ARPOP_INVREQUEST:
            /* request to identify peer */
            printf("ARP operation INVREQUEST\n");
            break;
        case ARPOP_INVREPLY:
            /* response identifying peer */
            printf("ARP operation INVREPLY\n");
            break;

        default:
            printf("ARP operation unknown\n");
            ENGINE_SET_EVENT(p,ARP_UNKNOWN_OPERATION);

    }

    return TM_ECODE_OK;
}


#ifdef UNITTESTS

#endif /* UNITTESTS */

/**
 * \brief Registers ICMPV4 unit test
 */
void DecodeARPRegisterTests(void)
{
#ifdef UNITTESTS
/* Make some for each operation - there are six
    UtRegisterTest("DecodeARPtest01", DecodeARPtest01);
    UtRegisterTest("DecodeARPtest02", DecodeARPtest02);
    UtRegisterTest("DecodeARPtest03", DecodeARPtest03);
    UtRegisterTest("DecodeARPtest04", DecodeARPtest04);
    UtRegisterTest("DecodeARPtest05", DecodeARPtest05);
    UtRegisterTest("DecodeARPtest06", DecodeARPtest06);*/
#endif /* UNITTESTS */
}
/**
 * @}
 */
