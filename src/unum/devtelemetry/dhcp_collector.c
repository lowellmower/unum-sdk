// device telemetry DHCP information collector

#include "unum.h"

/* Temporary, log to console or /var/log/dhcp.log from here */
#undef LOG_DST
#undef LOG_DBG_DST
#define LOG_DST LOG_DST_DHCP
// #define LOG_DBG_DST LOG_DST_CONSOLE

// copycat from fp_dhcp.c and TPCAP_TEST_FP_JSON will need to be moved
#ifdef DEBUG
#define DPRINTF(args...) ((tpcap_test_param.int_val == TPCAP_TEST_FP_JSON) ? \
                          (printf(args)) : 0)
#else  // DEBUG
#define DPRINTF(args...) /* Nothing */
#endif // DEBUG

// DHCP packet header (followed by options)
struct dhcp_pkt {
    u_int8_t  type;           // packet type
    u_int8_t  haddrtype;      // type of hardware address (Ethernet, etc)
    u_int8_t  haddrlen;       // length of hardware address
    u_int8_t  hops;           // hops
    u_int32_t sid;            // random transaction id number
    u_int16_t sec;            // seconds used in timing
    u_int16_t flags;          // flags
    struct in_addr caddr;     // IP address of this machine (if available)
    struct in_addr oaddr;     // IP address of this machine (if offered)
    struct in_addr saddr;     // IP address of DHCP server
    struct in_addr raddr;     // IP address of DHCP relay
    unsigned char haddr[16];  // hardware address of this machine
    char sname[64];           // DHCP server name
    char file[128];           // boot file name
    char cookie[4];           // cookie 0x63,0x82,0x53,0x63 for DHCP
    unsigned char options[];  // variable length options (up to 308 bytes)
} __attribute__((packed));

// Forward declarations
static void dhcp_offr_cb(TPCAP_IF_t *tpif,
                           PKT_PROC_ENTRY_t *pe,
                           struct tpacket2_hdr *thdr,
                           struct iphdr *iph);

// DHCP offer packet processing entry
static PKT_PROC_ENTRY_t dt_dhcp_offr_pkt_proc = {
    0,
    {},
    0,
    {},
    PKT_MATCH_TCPUDP_P1_SRC|PKT_MATCH_TCPUDP_P2_DST|PKT_MATCH_TCPUDP_UDP_ONLY,
    { .p1 = 67, .p2 = 68 },
    NULL, dhcp_offr_cb, NULL, NULL,
    "UDP from port 67 to 68, DHCP offer"
};

// INCOMPLETE: (lmower 20190628)
// DHCP offer packet callback added to packet processing entry
// dt_dhcp_offr_pkt_proc for UDP packets originating from port 67 and destined
// for port 68. This callback is currently logging to a file which is a big
// 'no, no' and should be augmented upon the state full implementation of
// collecting and processing DHCP information.
static void dhcp_offr_cb(TPCAP_IF_t *tpif,
                        PKT_PROC_ENTRY_t *pe,
                        struct tpacket2_hdr *thdr,
                        struct iphdr *iph)
{
    // No use for ethhdr at the moment but we will want this when
    // moving information to the DHCP table.
    // struct ethhdr *ehdr = (struct ethhdr *)((void *)thdr + thdr->tp_mac);
    struct udphdr *udph = ((void *)iph) + sizeof(struct iphdr);
    struct dhcp_pkt *dhdr = ((void *)udph) + sizeof(struct udphdr);

    // copycat from fp_dhcp.c - dhcp_rcv_cb
    int remains = thdr->tp_snaplen;
    remains -= (thdr->tp_net - thdr->tp_mac) +
               sizeof(struct iphdr) + sizeof(struct udphdr);
    if(remains < sizeof(struct dhcp_pkt) + 1) {
        log("%s: DEBUG - incomplete DHCP header, %d bytes remains, need %d\n",
                     __func__, remains, sizeof(struct dhcp_pkt) + 1);
        // DPRINTF("%s: incomplete DHCP header, %d bytes remains, need %d\n",
        //           __func__, remains, sizeof(struct dhcp_pkt) + 1);
        return;
    }

    // Only interested in DHCP offer packets
    if(dhdr->type != 2) {
        return;
    }

    // Verify DHCP cookie
    if(memcmp("\x63\x82\x53\x63", dhdr->cookie, 4) != 0) {
        log("%s: DEBUG - Offer pkt callback fail on magic cookie\n", __func__);
        // DPRINTF("%s: invalid DHCP packet cookie %02x,%02x,%02x,%02x\n",
        //        __func__, (unsigned char)dhdr->cookie[0],
        //        (unsigned char)dhdr->cookie[1],
        //        (unsigned char)dhdr->cookie[2],
        //        (unsigned char)dhdr->cookie[3]);
        return;
    }

    char oip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(dhdr->oaddr), oip_str, INET_ADDRSTRLEN);
    char sip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(dhdr->saddr), sip_str, INET_ADDRSTRLEN);

    log("%s: DEBUG - Offer pkt type: %u \n", __func__, dhdr->type);
    log("%s: DEBUG - Offer pkt oaddr: %s \n", __func__, oip_str);
    log("%s: DEBUG - Offer pkt saddr: %s \n", __func__, sip_str);
    log("%s: DEBUG - Offer pkt proc entry desc: %s \n", __func__, pe->desc);

    return;
}


int dt_dhcp_init(void)
{
    PKT_PROC_ENTRY_t *pe;

    // Add the collector packet processing entries.
    pe = &dt_dhcp_offr_pkt_proc;
    if(tpcap_add_proc_entry(pe) != 0)
    {
        log("%s: tpcap_add_proc_entry() failed for: %s\n",
            __func__, pe->desc);
        return -1;
    }

    return 0;
}

// INCOMPLETE: (lmower 20190628)
// Currently, the function dt_dhcp_tbl_stats() does nothing and has a signature
// does not return a DT_TABLE_STATS_t see devtelemetry_common.h comment for more
// information.
// void dt_dhcp_tbls_test(void)
// {    
//     dt_dhcp_tbl_stats();
// };
