#include "nitroWiFi/cps.h"

#include <nitro.h>
#include <nitroWiFi/wcm_cpsif.h>
#include <string.h>

#include <nitro/version_begin.h>
static char id_string[] = SDK_MIDDLEWARE_STRING("UBIQUITOUS", "CPS");
#include <nitro/version_end.h>

#define arpcache_entries  8
#define fragtable_entries 8

#define TCPIP_STACK_SIZE     2048
#define SCAVENGER_STACK_SIZE 2048

#define CPS_MIN_EPORT 1024
#define CPS_MAX_EPORT 5000

#define MAX_IP_PAYLOAD_SIZE (CPS_MAX_MTU - IP_HEADER_SIZE)

#define IPV4_LLC_SNAP_HEADER ((u8 *)"\xAA\xAA\x03\x00\x00\x00\x08\x00")

#define MTUtoMSS(mtu) (mtu - IP_HEADER_SIZE - TCP_HEADER_SIZE)

#define HARDWARE_TYPE_ETHERNET 1

#define ETHERTYPE_IPV4 0x800
#define ETHERTYPE_ARP  0x806

#define DHCP_MAGIC_COOKIE 0x63825363

enum Protocol {
    PROTOCOL_ICMP = 1,
    PROTOCOL_TCP = 6,
    PROTOCOL_UDP = 17,
};

enum Port {
    PORT_DNS = 53,
    PORT_DHCP_SERVER = 67,
    PORT_DHCP_CLIENT = 68,
    PORT_NB_NAME_SERVICE = 137,
};

enum ResolveResult {
    RESOLVE_RESULT_FATAL_ERROR = -1,
    RESOLVE_RESULT_SUCCESS = 1,
    RESOLVE_RESULT_NAME_TOO_LONG = 2,
};

#define IP_HEADER_SIZE          20
#define UDP_HEADER_SIZE         8
#define TCP_HEADER_SIZE         20
#define ETHERNET_HEADER_SIZE    14
#define ICMP_HEADER_SIZE        8
#define ARP_PACKET_SIZE         28
#define DHCP_FIXED_SEGMENT_SIZE 236
#define DNS_HEADER_SIZE         12
#define DNS_QUESTION_FIXED_SIZE 4
#define DNS_RR_FIXED_SIZE       10

enum IPHeaderOffset {
    IP_OFFSET_VERSION_IHL = 0,
    IP_OFFSET_DSCP_ECN = 1,
    IP_OFFSET_TOTAL_LENGTH = 2,
    IP_OFFSET_ID = 4,
    IP_OFFSET_FRAG_OFFSET = 6,
    IP_OFFSET_TTL = 8,
    IP_OFFSET_PROTOCOL = 9,
    IP_OFFSET_CHECKSUM = 10,
    IP_OFFSET_SOURCE_ADDRESS = 12,
    IP_OFFSET_DEST_ADDRESS = 16,
    IP_OFFSET_OPTIONS = 20,
};

enum UDPHeaderOffset {
    UDP_OFFSET_SOURCE_PORT = 0,
    UDP_OFFSET_DEST_PORT = 2,
    UDP_OFFSET_LENGTH = 4,
    UDP_OFFSET_CHECKSUM = 6,
};

enum TCPHeaderOffset {
    TCP_OFFSET_SOURCE_PORT = 0,
    TCP_OFFSET_DEST_PORT = 2,
    TCP_OFFSET_SEQ_NO = 4,
    TCP_OFFSET_ACK_NO = 8,
    TCP_OFFSET_DATA_OFFSET = 12,
    TCP_OFFSET_FLAG = 13,
    TCP_OFFSET_WINDOW = 14,
    TCP_OFFSET_CHECKSUM = 16,
    TCP_OFFSET_URGENT_POINTER = 18,
    TCP_OFFSET_OPTIONS = 20,
};

enum EthernetHeaderOffset {
    ETHERNET_OFFSET_MAC_DEST = 0,
    ETHERNET_OFFSET_MAC_SOURCE = 6,
    ETHERNET_OFFSET_TYPE = 12,
};

enum ICMPHeaderOffset {
    ICMP_OFFSET_TYPE = 0,
    ICMP_OFFSET_CODE = 1,
    ICMP_OFFSET_CHECKSUM = 2,
    ICMP_OFFSET_DATA = 4,
};

enum ARPPacketOffset {
    ARP_OFFSET_HARDWARE_TYPE = 0,
    ARP_OFFSET_PROTOCOL_TYPE = 2,
    ARP_OFFSET_HARDWARE_LENGTH = 4,
    ARP_OFFSET_PROTOCOL_LENGTH = 5,
    ARP_OFFSET_OPERATION = 6,
    ARP_OFFSET_SENDER_HARDWARE_ADDRESS = 8,
    ARP_OFFSET_SENDER_PROTOCOL_ADDRESS = 14,
    ARP_OFFSET_TARGET_HARDWARE_ADDRESS = 18,
    ARP_OFFSET_TARGET_PROTOCOL_ADDRESS = 24,
};

enum DHCPOffset {
    DHCP_OFFSET_OPERATION = 0,
    DHCP_OFFSET_HARDWARE_TYPE = 1,
    DHCP_OFFSET_HARDWARE_LENGTH = 2,
    DHCP_OFFSET_TRANSACTION_ID = 4,
    DHCP_OFFSET_CLIENT_IP_ADDRESS = 12,
    DHCP_OFFSET_YOUR_IP_ADDRESS = 16,
    DHCP_OFFSET_CLIENT_HARDWARE_ADDRESS = 28,
    DHCP_OFFSET_MAGIC_COOKIE = 236,
    DHCP_OFFSET_OPTIONS_START = 240,
};

enum DNSHeaderOffset {
    DNS_OFFSET_TRANSACTION_ID = 0,
    DNS_OFFSET_FLAGS = 2,
    DNS_OFFSET_QUESTION_COUNT = 4,
    DNS_OFFSET_ANSWER_COUNT = 6,
    DNS_OFFSET_AUTHORITY_RR_COUNT = 8,
    DNS_OFFSET_ADDITIONAL_RR_COUNT = 10,
};

enum DNSQuestionOffset {
    DNS_QUESTION_OFFSET_TYPE = 0,
    DNS_QUESTION_OFFSET_CLASS = 2,
};

enum DNSRROffset {
    DNS_RR_OFFSET_TYPE = 0,
    DNS_RR_OFFSET_CLASS = 2,
    DNS_RR_OFFSET_TTL = 4,
    DNS_RR_OFFSET_RLENGTH = 8,
    DNS_RR_OFFSET_RDATA = 10,
};

enum TCPFlag {
    TCP_FLAG_FIN = 1 << 0,
    TCP_FLAG_SYN = 1 << 1,
    TCP_FLAG_RST = 1 << 2,
    TCP_FLAG_PSH = 1 << 3,
    TCP_FLAG_ACK = 1 << 4,
    TCP_FLAG_URG = 1 << 5,
    TCP_FLAG_ECE = 1 << 6,
    TCP_FLAG_CWR = 1 << 7,
};

enum TCPOption {
    TCP_OPTION_END = 0,
    TCP_OPTION_NOP,
    TCP_OPTION_MSS,
};

#define TCP_DATA_OFFSET_MASK  0xF0
#define TCP_DATA_OFFSET_SHIFT 4

#define IP_VERSION_SHIFT 4

#define FLAG_MORE_FRAGMENTS (1 << 13)

#define IHL_MASK         0xF
#define FRAG_OFFSET_MASK 0x1FFF

enum ICMPMessageType {
    ICMP_ECHO_REPLY = 0,
    ICMP_ECHO_REQUEST = 8,
};

enum ARPOperation {
    ARP_REQUEST = 1,
    ARP_REPLY = 2,
};

enum DHCPMessageType {
    DHCPDISCOVER = 1,
    DHCPOFFER = 2,
    DHCPREQUEST = 3,
    DHCPACK = 5,
    DHCPRELEASE = 7,
};

enum DHCPOperation {
    DHCP_REQUEST = 1,
    DHCP_REPLY = 2,
};

enum DHCPOption {
    DHCP_OPTION_SUBNET_MASK = 1,
    DHCP_OPTION_ROUTER = 3,
    DHCP_OPTION_DNS_SERVER = 6,
    DHCP_OPTION_HOST_NAME = 12,
    DHCP_OPTION_REQUESTED_IP = 50,
    DHCP_OPTION_LEASE_TIME = 51,
    DHCP_OPTION_MESSAGE_TYPE = 53,
    DHCP_OPTION_SERVER_ID = 54,
    DHCP_OPTION_PARAMETER_REQ_LIST = 55,
    DHCP_OPTION_CLIENT_ID = 61,
    DHCP_OPTION_END = 0xFF,
};

enum DHCPState {
    DHCP_STATE_INIT = 0,
    DHCP_STATE_BOUND,
    DHCP_STATE_REBINDING,
    DHCP_STATE_FIXED_IP,
};

enum DHCPMode {
    DHCP_MODE_REQUEST_IP = 0,
    DHCP_MODE_RENEW,
    DHCP_MODE_REBIND,
};

enum DHCPResult {
    DHCP_RESULT_NONE = 0,
    DHCP_RESULT_OFFER,
    DHCP_RESULT_ACK,
    DHCP_RESULT_REPLY,
};

enum DNSType {
    DNS_TYPE_A = 1,
    DNS_TYPE_PTR = 12,
    DNS_TYPE_NB = 32,
};

enum DNSFlag {
    DNS_FLAG_CD = 1 << 4,
    DNS_FLAG_AD = 1 << 5,
    DNS_FLAG_Z = 1 << 6,
    DNS_FLAG_RA = 1 << 7,
    DNS_FLAG_RD = 1 << 8,
    DNS_FLAG_TC = 1 << 9,
    DNS_FLAG_AA = 1 << 10,
    DNS_FLAG_QR = 1 << 15,
};

enum DNSRCode {
    DNS_RCODE_NOERROR = 0,
    DNS_RCODE_FORMERR,
    DNS_RCODE_SERVFAIL,
    DNS_RCODE_NXDOMAIN,
};

#define DNS_CLASS_INTERNET 1

#define DNS_COMPRESSION_POINTER_MASK 0xC0

#define DNS_RCODE_MASK 0xF

static CPSMacAddress mac_broadcast = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static u32 helper_threads_priority = 16;

CPSMacAddress CPSMyMac;
CPSInAddr CPSMyIp;
CPSInAddr CPSNetMask;
static CPSDHCPCallback dhcp_callback;
CPSInAddr CPSDnsIp[2];
CPSInAddr CPSDhcpServerIp;
int CPSNoIpReason;
MATHRandContext32 CPSiRand32ctx;
static CPSInAddr offered_myip;
CPSFreeFunc CPSiFree;
static u16 ipid;
static u16 eport;
static u16 mymss;
static u32 yield_wait;
static u8 ip_conflict;
static u8 wfailed;
static CPSScavengerCallback scavenger_callback;
static CPSSoc tmpsoc;
static u8 tmpbuf[ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + TCP_HEADER_SIZE + 4];
CPSInAddr CPSGatewayIp;
static u32 mode;
static BOOL scavenger_force_exit;
static CPSLinkIsOnFunc link_is_on;
static u32 lease_time;
static CPSArpCache arpcache[arpcache_entries];
static CPSFragTable fragtable[fragtable_entries];
static OSThread *volatile receiver_thread;
static u8 *wlan_buf;
static vu32 wlan_buflen;
static vu32 wlan_putpnt;
static vu32 wlan_getpnt;
static OSThread tcpip_thread;
static u8 tcpip_stack[TCPIP_STACK_SIZE] ATTRIBUTE_ALIGN(32);
static OSThread scavenger_thread;
static u8 scavenger_stack[SCAVENGER_STACK_SIZE] ATTRIBUTE_ALIGN(32);
CPSAllocFunc CPSiAlloc;
static CPSSoc scavenger_soc;
static u8 scavenger_rcvbuf[384];
static u8 scavenger_sndbuf[384];

static void tcpip(void *unused);
static void scavenger(void *unused);
static BOOL dhcp_discover_server(void);
static BOOL dhcp_request_server(u32 *sleep, int mode);
static void dhcp_release_server(void);

static void reset_network_vars(int reason)
{
    BOOL had_ip = CPSMyIp != 0;

    CPSNoIpReason = reason;
    CPSMyIp = 0;
    CPSNetMask = 0;
    CPSGatewayIp = 0;
    CPSDnsIp[0] = 0;
    CPSDnsIp[1] = 0;
    CPSDhcpServerIp = 0;

    if (had_ip == 0) {
        return;
    }

    MI_CpuClear8(arpcache, sizeof(arpcache));

    OSThread *t = OS_GetThreadList();
    while (t != NULL) {
        CPSSoc *soc = OSi_GetSpecificData(t, OSi_SPECIFIC_CPS);
        if (soc != NULL && soc->thread != NULL) {
            if (soc->state != CPS_STT_DATAGRAM && soc->state != CPS_STT_PING) {
                soc->state = CPS_STT_CLOSED;
            }
            if (soc->block_type != CPS_BLOCK_NONE) {
                soc->block_type = CPS_BLOCK_NONE;
                OS_WakeupThreadDirect(soc->thread);
            }
        }
        t = OS_GetNextThread(t);
    }

    for (int i = 0; i < fragtable_entries; i++) {
        if (fragtable[i].frags != 0) {
            CPSiFree(fragtable[i].buf);
            fragtable[i].frags = 0;
        }
    }

    CPSi_SslCleanup();
}

static void yield_thread(void)
{
    if (yield_wait == 0) {
        OS_YieldThread();
    } else {
        OS_Sleep(yield_wait);
    }
}

static void empty_func(void)
{
    return;
}

static BOOL default_link_is_on(void)
{
    return TRUE;
}

void CPS_Startup(CPSConfig *config)
{
    SDK_USING_MIDDLEWARE(id_string);

    if (config->random_seed != 0) {
        MATH_InitRand32(&CPSiRand32ctx, config->random_seed);
    } else {
        MATH_InitRand32(&CPSiRand32ctx, OS_GetTick());
    }

    if (config->alloc != NULL && config->free != NULL) {
        CPSiAlloc = config->alloc;
        CPSiFree = config->free;
    } else {
        CPSiAlloc = (CPSAllocFunc)empty_func;
        CPSiFree = (CPSFreeFunc)empty_func;
    }

    mode = config->mode;

    if (config->mymss != 0) {
        mymss = config->mymss;
    } else {
        mymss = MTUtoMSS(CPS_MAX_MTU);
    }

    offered_myip = config->requested_ip;
    yield_wait = config->yield_wait;

    if (config->dhcp_callback != NULL) {
        dhcp_callback = config->dhcp_callback;
    } else {
        dhcp_callback = empty_func;
    }

    if (config->link_is_on != NULL) {
        link_is_on = config->link_is_on;
    } else {
        link_is_on = default_link_is_on;
    }

    wlan_buf = config->lan_buf;
    wlan_buflen = config->lan_buflen;
    wlan_getpnt = 0;
    wlan_putpnt = 0;

    eport = MATH_Rand32(&CPSiRand32ctx, CPS_MAX_EPORT - CPS_MIN_EPORT) + CPS_MIN_EPORT;
    OS_GetMacAddress(CPSMyMac);
    ip_conflict = FALSE;
    OS_CreateThread(&tcpip_thread, tcpip, NULL, tcpip_stack + TCPIP_STACK_SIZE, sizeof(tcpip_stack), helper_threads_priority);
    OS_CreateThread(&scavenger_thread, scavenger, NULL, scavenger_stack + SCAVENGER_STACK_SIZE, sizeof(scavenger_stack), helper_threads_priority);
    OS_WakeupThreadDirect(&tcpip_thread);
    OS_WakeupThreadDirect(&scavenger_thread);
}

int CPS_CalmDown(void)
{
    OSIntrMode enable = OS_DisableInterrupts();
    BOOL result = OS_IsThreadTerminated(&scavenger_thread);
    if (!result && !scavenger_force_exit) {
        scavenger_force_exit = TRUE;
        OS_WakeupThreadDirect(&scavenger_thread);
    }
    OS_RestoreInterrupts(enable);

    return result;
}

void CPS_SetScavengerCallback(CPSScavengerCallback f)
{
    scavenger_callback = f;
}

void CPS_Cleanup(void)
{
    CPS_CalmDown();

    OS_JoinThread(&scavenger_thread);
    OS_DestroyThread(&tcpip_thread);
    receiver_thread = NULL;

    reset_network_vars(CPS_NOIP_REASON_NONE);

    wlan_buf = NULL;
    wlan_buflen = 0;
}

u32 CPS_GetThreadPriority(void)
{
    return helper_threads_priority;
}

void CPS_SetThreadPriority(u32 new_prio)
{
    helper_threads_priority = new_prio;
    OS_SetThreadPriority(&tcpip_thread, new_prio);
    OS_SetThreadPriority(&scavenger_thread, new_prio);
}

static u32 calc_checksum_do(u8 *s, u32 len, u32 sum)
{
    if ((u32)s & 1) {
        while (len > 1) {
            sum += CPS_GETUSHORT1(s);
            s += 2;
            len -= 2;
        }
    } else {
        sum = CPS_htons(sum);
        while (len > 1) {
            sum += CPS_USHORT2_HOST(s);
            s += 2;
            len -= 2;
        }
        sum = CPS_htonl(sum);
    }

    if (len != 0) {
        sum += *s << 8;
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += sum >> 16;
    return sum & 0xFFFF;
}

static u16 invert_checksum(u16 sum)
{
    sum ^= 0xFFFF;
    if (sum == 0) {
        sum = 0xFFFF;
    }
    return sum;
}

static u16 calc_checksum(u8 *s, u32 len)
{
    return invert_checksum(calc_checksum_do(s, len, 0));
}

static BOOL check_tcpudpsum(u8 *tcpudp_hdr, u32 len, u8 *ip_hdr, u16 protocol)
{
    u32 sum = calc_checksum_do(tcpudp_hdr, len, protocol);
    sum = calc_checksum_do(&ip_hdr[IP_OFFSET_SOURCE_ADDRESS], sizeof(CPSInAddr) * 2, sum);
    sum += len;

    if (sum & 0x10000) {
        sum = (sum + 1) & 0xFFFF;
    }

    return sum != 0xFFFF;
}

static BOOL ip_islocal(CPSInAddr ip)
{
    return ip == CPS_MK_IPv4(255, 255, 255, 255) || ip == CPS_MK_IPv4(127, 0, 0, 1) || (ip & CPSNetMask) == (CPSMyIp & CPSNetMask);
}

static CPSInAddr get_targetip(CPSInAddr ip)
{
    if (!ip_islocal(ip)) {
        ip = CPSGatewayIp;
    }
    return ip;
}

static BOOL is_broadcast(CPSInAddr ip)
{
    return ip_islocal(ip) && (ip & ~CPSNetMask) == ~CPSNetMask;
}

static BOOL is_multicast(CPSInAddr ip)
{
    return (ip & 0xF0000000) == CPS_MK_IPv4(224, 0, 0, 0);
}

static BOOL ip_isme(CPSInAddr ip)
{
    return CPSMyIp == 0 || ip == CPSMyIp || ip == CPS_MK_IPv4(127, 0, 0, 1) || is_broadcast(ip) || is_multicast(ip);
}

static u32 maccmp(void *s1, void *s2)
{
    for (int i = 0; i < (int)(sizeof(CPSMacAddress) / sizeof(u16)); i++) {
        if (*((u16 *)s1)++ != *((u16 *)s2)++) {
            return 1;
        }
    }
    return 0;
}

static void send_packet(u8 *hdr, u32 hdr_len, u8 *body, u32 body_len)
{
    // note: this overwrites the source mac address
    MI_CpuCopy8(IPV4_LLC_SNAP_HEADER, &hdr[6], 6);
    wfailed = WCM_SendDCFDataEx(&hdr[ETHERNET_OFFSET_MAC_DEST], &hdr[6], hdr_len - 6, body, body_len) < 0;
}

static void put_in_buffer(const u8 *srcAddr, const u8 *dstAddr, const u8 *buf1, u32 size1, const u8 *buf2, u32 size2)
{
    if (wlan_buf == NULL || wlan_buflen == 0) {
        return;
    }

    u32 size = size1 + size2;
    if (size < 8 || CPS_MAX_MTU + 8 < size) {
        return;
    }

    if (buf1[0] != IPV4_LLC_SNAP_HEADER[0]
        || buf1[1] != IPV4_LLC_SNAP_HEADER[1]
        || buf1[2] != IPV4_LLC_SNAP_HEADER[2]
        || buf1[6] != ETHERTYPE_IPV4 >> 8
        || (buf1[7] != (ETHERTYPE_IPV4 & 0xFF) && buf1[7] != (ETHERTYPE_ARP & 0xFF))) {
        return;
    }

    u16 blocklen = (size + 9) & ~1;
    u32 new_putpnt = wlan_putpnt + blocklen;
    if (wlan_putpnt < wlan_getpnt && wlan_getpnt <= new_putpnt) {
        return;
    }

    if (new_putpnt == wlan_buflen) {
        new_putpnt = 0;
        if (wlan_getpnt == 0) {
            return;
        }
    } else if (new_putpnt > wlan_buflen) {
        new_putpnt = blocklen;
        if (wlan_getpnt <= new_putpnt) {
            return;
        }
    }

    if (wlan_putpnt + blocklen > wlan_buflen) {
        if (wlan_buflen - wlan_putpnt >= 2) {
            CPS_USHORT2_HOST(wlan_buf + wlan_putpnt) = 0;
        }
        wlan_putpnt = 0;
    }

    CPS_USHORT2_HOST(wlan_buf + wlan_putpnt) = blocklen;
    MI_CpuCopy8(dstAddr, wlan_buf + wlan_putpnt + 2, 6);
    MI_CpuCopy8(srcAddr, wlan_buf + wlan_putpnt + 8, 6);
    MI_CpuCopy8(buf1 + 6, wlan_buf + wlan_putpnt + 14, size1 - 6);
    if (buf2 != NULL && size2 != 0) {
        MI_CpuCopy8(buf2, wlan_buf + wlan_putpnt + 8 + size1, size2);
    }
    wlan_putpnt = new_putpnt;
}

void CPSi_RecvCallbackFunc(const u8 *srcAddr, const u8 *dstAddr, const u8 *buf, s32 size)
{
    put_in_buffer(srcAddr, dstAddr, buf, size, NULL, 0);

    if (receiver_thread != NULL && !OS_IsThreadTerminated(receiver_thread)) {
        OS_WakeupThreadDirect(receiver_thread);
    }
}

static u8 *receive_packet(u32 *len)
{
    u16 blocklen;
    OSIntrMode enable = OS_DisableInterrupts();
    while (wlan_getpnt == wlan_putpnt) {
        receiver_thread = OS_GetCurrentThread();
        OS_SleepThread(NULL);
        receiver_thread = NULL;
    }
    OS_RestoreInterrupts(enable);

    do {
        if (wlan_buflen - wlan_getpnt < 2) {
            wlan_getpnt = 0;
        }
        blocklen = CPS_USHORT2_HOST(wlan_buf + wlan_getpnt);
        if (blocklen == 0) {
            wlan_getpnt = 0;
        }
    } while (blocklen == 0);

    *len = blocklen - 2;
    return wlan_buf + wlan_getpnt + 2;
}

static void throw_packet(void)
{
    OSIntrMode enabled = OS_DisableInterrupts();
    wlan_getpnt += CPS_USHORT2_HOST(wlan_buf + wlan_getpnt);
    if (wlan_getpnt >= wlan_buflen) {
        wlan_getpnt = 0;
    }
    OS_RestoreInterrupts(enabled);
}

static CPSMacAddress *inq_arpcache(CPSInAddr ip)
{
    u32 i;

    OSIntrMode enabled = OS_DisableInterrupts();
    CPSMacAddress *result = NULL;
    if (ip == CPS_MK_IPv4(127, 0, 0, 1) || ip == CPSMyIp) {
        result = &CPSMyMac;
    } else {
        if (is_broadcast(ip) || is_multicast(ip)) {
            result = &mac_broadcast;
        } else {
            for (i = 0; i < arpcache_entries; i++) {
                if (ip == arpcache[i].ip) {
                    arpcache[i].when = CPSi_GetTick();
                    result = &arpcache[i].mac;
                    break;
                }
            }
        }
    }
    OS_RestoreInterrupts(enabled);

    return result;
}

static void send_arprequest(CPSInAddr ip)
{
    u8 buf[ETHERNET_HEADER_SIZE + ARP_PACKET_SIZE];

    MI_CpuClear8(buf, sizeof(buf));
    MI_CpuFill8(&buf[ETHERNET_OFFSET_MAC_DEST], 0xFF, sizeof(CPSMacAddress));
    MI_CpuCopy8(CPSMyMac, &buf[ETHERNET_OFFSET_MAC_SOURCE], sizeof(CPSMacAddress));
    CPS_SETUSHORT2(&buf[ETHERNET_OFFSET_TYPE], ETHERTYPE_ARP);

    buf[ETHERNET_HEADER_SIZE + ARP_OFFSET_HARDWARE_TYPE + 1] = HARDWARE_TYPE_ETHERNET;
    buf[ETHERNET_HEADER_SIZE + ARP_OFFSET_PROTOCOL_TYPE] = ETHERTYPE_IPV4 >> 8;
    CPS_SETUSHORT2(&buf[ETHERNET_HEADER_SIZE + ARP_OFFSET_HARDWARE_LENGTH], sizeof(CPSMacAddress) << 8 | sizeof(CPSInAddr));
    buf[ETHERNET_HEADER_SIZE + ARP_OFFSET_OPERATION + 1] = ARP_REQUEST;
    MI_CpuCopy8(CPSMyMac, &buf[ETHERNET_HEADER_SIZE + ARP_OFFSET_SENDER_HARDWARE_ADDRESS], sizeof(CPSMacAddress));
    CPS_SETULONG2(&buf[ETHERNET_HEADER_SIZE + ARP_OFFSET_SENDER_PROTOCOL_ADDRESS], CPSMyIp);
    CPS_SETULONG2(&buf[ETHERNET_HEADER_SIZE + ARP_OFFSET_TARGET_PROTOCOL_ADDRESS], ip);

    send_packet(buf, sizeof(buf), NULL, 0);
}

static CPSMacAddress *arprequest(CPSInAddr ip)
{
    for (u32 retry1 = 0; retry1 < 8; retry1++) {
        send_arprequest(ip);
        for (u32 retry2 = 0; retry2 < 20; retry2++) {
            if (CPSMyIp == 0) {
                return NULL;
            }

            OS_Sleep(100);

            CPSMacAddress *mac = inq_arpcache(ip);
            if (mac != NULL) {
                return mac;
            }
        }
    }

    return NULL;
}

static void reg_arpcache(CPSMacAddress *mac, CPSInAddr ip, BOOL new_entry)
{
    u32 i;
    u32 candidate;

    if (ip == CPS_MK_IPv4(127, 0, 0, 1) || ip == CPSMyIp || !ip_islocal(ip) || is_multicast(ip)) {
        return;
    }

    u16 now = CPSi_GetTick();
    for (i = 0; i < arpcache_entries; i++) {
        if (ip == arpcache[i].ip) {
            arpcache[i].when = now;
            MI_CpuCopy8(mac, &arpcache[i].mac, sizeof(CPSMacAddress));
            return;
        }
    }

    if (!new_entry) {
        return;
    }

    u16 oldest_time = 0;
    candidate = 0;
    for (i = 0; i < arpcache_entries; i++) {
        if (arpcache[i].ip == 0) {
            candidate = i;
            break;
        }

        if ((s16)(now - arpcache[i].when) > oldest_time) {
            oldest_time = now - arpcache[i].when;
            candidate = i;
        }
    }

    arpcache[candidate].ip = ip;
    MI_CpuCopy8(mac, &arpcache[candidate].mac, sizeof(CPSMacAddress));
    arpcache[candidate].when = now;
}

static void send_ether(u8 *hdr, u32 hdr_len, u8 *body, u32 body_len, CPSInAddr ip_to, u16 type)
{
    hdr -= ETHERNET_HEADER_SIZE;
    hdr_len += ETHERNET_HEADER_SIZE;

    CPS_SETUSHORT2(&hdr[ETHERNET_OFFSET_TYPE], type);

    if (!is_multicast(ip_to)) {
        ip_to = get_targetip(ip_to);
        if (ip_to == 0) {
            return;
        }
        CPSMacAddress *mac_to = inq_arpcache(ip_to);
        if (mac_to == NULL) {
            mac_to = arprequest(ip_to);
        }
        if (mac_to == NULL) {
            return;
        }
        MI_CpuCopy8(mac_to, &hdr[ETHERNET_OFFSET_MAC_DEST], sizeof(CPSMacAddress));
    } else {
        hdr[ETHERNET_OFFSET_MAC_DEST] = 1;
        hdr[ETHERNET_OFFSET_MAC_DEST + 1] = 0;
        hdr[ETHERNET_OFFSET_MAC_DEST + 2] = 0x5E;
        hdr[ETHERNET_OFFSET_MAC_DEST + 3] = (ip_to >> 16) & 0x7F;
        hdr[ETHERNET_OFFSET_MAC_DEST + 4] = ip_to >> 8;
        hdr[ETHERNET_OFFSET_MAC_DEST + 5] = ip_to;
    }

    MI_CpuCopy8(CPSMyMac, &hdr[ETHERNET_OFFSET_MAC_SOURCE], sizeof(CPSMacAddress));
    send_packet(hdr, hdr_len, body, body_len);
}

static void send_ip_frag(u8 *hdr, u32 hdr_len, u8 *body, u32 body_len, CPSInAddr ip_to, u32 offset)
{
    hdr -= IP_HEADER_SIZE;
    hdr_len += IP_HEADER_SIZE;

    CPS_SETUSHORT2(&hdr[IP_OFFSET_TOTAL_LENGTH], hdr_len + body_len);
    CPS_SETUSHORT2(&hdr[IP_OFFSET_FRAG_OFFSET], offset);
    CPS_SETUSHORT2(&hdr[IP_OFFSET_CHECKSUM], 0);
    CPS_SETUSHORT2(&hdr[IP_OFFSET_CHECKSUM], calc_checksum(hdr, IP_HEADER_SIZE));

    if (ip_to != CPS_MK_IPv4(127, 0, 0, 1) && ip_to != CPSMyIp) {
        send_ether(hdr, hdr_len, body, body_len, ip_to, ETHERTYPE_IPV4);
    }
    if (ip_to != CPS_MK_IPv4(127, 0, 0, 1) && ip_to != CPSMyIp && !is_multicast(ip_to)) {
        return;
    }

    hdr -= 8;
    MI_CpuCopy8(IPV4_LLC_SNAP_HEADER, hdr, 8);

    OSIntrMode enabled = OS_DisableInterrupts();
    put_in_buffer(CPSMyMac, CPSMyMac, hdr, hdr_len + 8, body, body_len);
    OS_RestoreInterrupts(enabled);
}

static void send_ip(u8 *hdr, u32 hdr_len, u8 *body, u32 body_len, CPSInAddr ip_to, u8 protocol)
{
    hdr -= IP_HEADER_SIZE;
    hdr[IP_OFFSET_VERSION_IHL] = (4 << IP_VERSION_SHIFT) | 5;
    hdr[IP_OFFSET_DSCP_ECN] = 0;
    CPS_SETUSHORT2(&hdr[IP_OFFSET_ID], ++ipid);
    hdr[IP_OFFSET_TTL] = 128;
    hdr[IP_OFFSET_PROTOCOL] = protocol;
    CPS_SETULONG2(&hdr[IP_OFFSET_SOURCE_ADDRESS], CPSMyIp);
    CPS_SETULONG2(&hdr[IP_OFFSET_DEST_ADDRESS], ip_to);
    hdr += IP_HEADER_SIZE;

    u16 offset = 0;
    if (hdr_len > MAX_IP_PAYLOAD_SIZE) {
        u8 *bodytmp = hdr;
        while (hdr_len > MAX_IP_PAYLOAD_SIZE) {
            send_ip_frag(hdr, 0, bodytmp, MAX_IP_PAYLOAD_SIZE, ip_to, offset | FLAG_MORE_FRAGMENTS);
            bodytmp += MAX_IP_PAYLOAD_SIZE;
            hdr_len -= MAX_IP_PAYLOAD_SIZE;
            offset += MAX_IP_PAYLOAD_SIZE / 8;
        }

        if (hdr_len != 0) {
            if (body_len != 0) {
                send_ip_frag(hdr, 0, bodytmp, hdr_len, ip_to, offset | FLAG_MORE_FRAGMENTS);
            } else {
                send_ip_frag(hdr, 0, bodytmp, hdr_len, ip_to, offset);
            }

            offset += hdr_len / 8;
            hdr_len = 0;
        }
    }

    while (hdr_len + body_len > MAX_IP_PAYLOAD_SIZE) {
        u32 this_len = MAX_IP_PAYLOAD_SIZE - hdr_len;
        send_ip_frag(hdr, hdr_len, body, this_len, ip_to, offset | FLAG_MORE_FRAGMENTS);
        body += this_len;
        body_len -= this_len;
        offset += MAX_IP_PAYLOAD_SIZE / 8;
        hdr_len = 0;
    }

    if (hdr_len + body_len != 0) {
        send_ip_frag(hdr, hdr_len, body, body_len, ip_to, offset);
    }
}

static void send_ping(u8 *pattern, u32 len, CPSSoc *soc)
{
    u8 *icmp = soc->sndbuf.data + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE;
    static u16 pingseq = 0;

    CPS_SETUSHORT2(&icmp[ICMP_OFFSET_TYPE], ICMP_ECHO_REQUEST << 8 | 0);
    CPS_USHORT2_HOST(&icmp[ICMP_OFFSET_DATA]) = (u16)OS_GetCurrentThread();
    CPS_USHORT2_HOST(&icmp[ICMP_OFFSET_CHECKSUM]) = 0;
    soc->local_port = pingseq;
    CPS_USHORT2_HOST(&icmp[ICMP_OFFSET_DATA + 2]) = pingseq++;
    CPS_SETUSHORT2(&icmp[ICMP_OFFSET_CHECKSUM], invert_checksum(calc_checksum_do(pattern, len, calc_checksum_do(icmp, ICMP_HEADER_SIZE, 0))));
    send_ip(icmp, ICMP_HEADER_SIZE, pattern, len, soc->remote_ip, PROTOCOL_ICMP);
}

static void send_udp(u8 *data, u32 len, CPSSoc *soc)
{
    u8 *hdr = soc->sndbuf.data + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE;

    CPS_SETULONG2(&hdr[-12], CPSMyIp);
    CPS_SETULONG2(&hdr[-8], soc->remote_ip);
    CPS_SETUSHORT2(&hdr[-4], PROTOCOL_UDP);
    CPS_SETUSHORT2(&hdr[UDP_OFFSET_LENGTH], len + 8);
    CPS_USHORT2_HOST(&hdr[-2]) = CPS_USHORT2_HOST(&hdr[UDP_OFFSET_LENGTH]);
    CPS_SETUSHORT2(&hdr[UDP_OFFSET_DEST_PORT], soc->remote_port);
    CPS_SETUSHORT2(&hdr[UDP_OFFSET_SOURCE_PORT], soc->local_port);
    CPS_SETUSHORT2(&hdr[UDP_OFFSET_CHECKSUM], 0);
    CPS_SETUSHORT2(&hdr[UDP_OFFSET_CHECKSUM], invert_checksum(calc_checksum_do(data, len, calc_checksum_do(&hdr[-12], UDP_HEADER_SIZE + 12, 0))));
    send_ip(hdr, UDP_HEADER_SIZE, data, len, soc->remote_ip, PROTOCOL_UDP);
}

static void send_tcp(u8 *data, u32 len, CPSSoc *soc, u8 flag, u16 urg)
{
    u8 *hdr;
    u32 this_tcp_size;

    if (soc->state == CPS_STT_CLOSED) {
        return;
    }

    if (OS_GetCurrentThread() == &tcpip_thread) {
        hdr = tmpbuf + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE;
    } else {
        hdr = soc->sndbuf.data + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE;
    }

    if (flag & TCP_FLAG_SYN) {
        this_tcp_size = TCP_HEADER_SIZE + 4;
    } else {
        this_tcp_size = TCP_HEADER_SIZE;
    }

    CPS_SETULONG2(&hdr[-12], CPSMyIp);
    CPS_SETULONG2(&hdr[-8], soc->remote_ip);
    CPS_SETUSHORT2(&hdr[-4], PROTOCOL_TCP);
    CPS_SETUSHORT2(&hdr[-2], this_tcp_size + len);

    CPS_SETUSHORT2(&hdr[TCP_OFFSET_SOURCE_PORT], soc->local_port);
    CPS_SETUSHORT2(&hdr[TCP_OFFSET_DEST_PORT], soc->remote_port);
    CPS_SETULONG2(&hdr[TCP_OFFSET_SEQ_NO], soc->seqno);
    CPS_SETULONG2(&hdr[TCP_OFFSET_ACK_NO], soc->ackno);
    hdr[TCP_OFFSET_DATA_OFFSET] = (this_tcp_size / sizeof(u32)) << TCP_DATA_OFFSET_SHIFT;
    hdr[TCP_OFFSET_FLAG] = flag;
    CPS_SETUSHORT2(&hdr[TCP_OFFSET_WINDOW], soc->rcvbuf.size - soc->rcvbufp);
    CPS_SETUSHORT2(&hdr[TCP_OFFSET_CHECKSUM], 0);
    CPS_USHORT2_HOST(&hdr[TCP_OFFSET_URGENT_POINTER]) = 0;
    if (flag & TCP_FLAG_SYN) {
        CPS_SETULONG2(&hdr[TCP_OFFSET_OPTIONS], mymss + (TCP_OPTION_MSS << 24 | 4 << 16));
    }
    CPS_SETUSHORT2(&hdr[TCP_OFFSET_CHECKSUM], invert_checksum(calc_checksum_do(data, len, calc_checksum_do(&hdr[-12], this_tcp_size + 12, 0))));

    send_ip(hdr, this_tcp_size, data, len, soc->remote_ip, PROTOCOL_TCP);
    soc->seqno += len;
    if (flag & (TCP_FLAG_FIN | TCP_FLAG_SYN)) {
        soc->seqno++;
    }
}

static void reply_arp(u8 *buf)
{
    CPS_SETUSHORT2(&buf[ARP_OFFSET_OPERATION], ARP_REPLY);
    MI_CpuCopy8(&buf[ARP_OFFSET_SENDER_HARDWARE_ADDRESS], &buf[ARP_OFFSET_TARGET_HARDWARE_ADDRESS], sizeof(CPSMacAddress) + sizeof(CPSInAddr));
    MI_CpuCopy8(CPSMyMac, &buf[ARP_OFFSET_SENDER_HARDWARE_ADDRESS], sizeof(CPSMacAddress));
    CPS_SETULONG2(&buf[ARP_OFFSET_SENDER_PROTOCOL_ADDRESS], CPSMyIp);

    buf -= ETHERNET_HEADER_SIZE;
    MI_CpuCopy8(&buf[ETHERNET_HEADER_SIZE + ARP_OFFSET_TARGET_HARDWARE_ADDRESS], &buf[ETHERNET_OFFSET_MAC_DEST], sizeof(CPSMacAddress));
    MI_CpuCopy8(CPSMyMac, &buf[ETHERNET_OFFSET_MAC_SOURCE], sizeof(CPSMacAddress));
    send_packet(buf, ETHERNET_HEADER_SIZE + ARP_PACKET_SIZE, NULL, 0);
}

void dispatch_arp(u8 *buf, u32 len)
{
    if (len < ARP_PACKET_SIZE
        || maccmp(&buf[ARP_OFFSET_SENDER_HARDWARE_ADDRESS], CPSMyMac) == 0
        || CPSMyIp == 0
        || CPS_USHORT2_HOST(&buf[ARP_OFFSET_HARDWARE_TYPE]) != CPS_htons(HARDWARE_TYPE_ETHERNET)
        || CPS_USHORT2_HOST(&buf[ARP_OFFSET_PROTOCOL_TYPE]) != CPS_htons(ETHERTYPE_IPV4)
        || CPS_USHORT2_HOST(&buf[ARP_OFFSET_HARDWARE_LENGTH]) != CPS_htons(sizeof(CPSMacAddress) << 8 | sizeof(CPSInAddr))) {
        return;
    }

    u16 op = CPS_GETUSHORT2(&buf[ARP_OFFSET_OPERATION]);
    if (op != ARP_REQUEST && op != ARP_REPLY) {
        return;
    }

    u32 ipfrom = CPS_GETULONG2(&buf[ARP_OFFSET_SENDER_PROTOCOL_ADDRESS]);
    BOOL from_me = ipfrom == CPSMyIp;
    BOOL to_me = CPSMyIp == CPS_GETULONG2(&buf[ARP_OFFSET_TARGET_PROTOCOL_ADDRESS]);

    if (!from_me) {
        reg_arpcache((CPSMacAddress *)&buf[ARP_OFFSET_SENDER_HARDWARE_ADDRESS], ipfrom, to_me);
    }

    if (op == ARP_REQUEST && to_me) {
        reply_arp(buf);
    } else if (op == ARP_REPLY && to_me && from_me) {
        ip_conflict = TRUE;
    }
}

static void reply_icmp(u8 *iphdr, u8 *icmpdata, u32 len)
{
    CPSInAddr ip_reply_to = get_targetip(CPS_GETULONG2(&iphdr[IP_OFFSET_SOURCE_ADDRESS]));
    if (ip_reply_to == 0) {
        return;
    }
    if (inq_arpcache(ip_reply_to) == NULL) {
        send_arprequest(ip_reply_to);
        return;
    }

    icmpdata[ICMP_OFFSET_TYPE] = ICMP_ECHO_REPLY;
    CPS_SETUSHORT2(&icmpdata[ICMP_OFFSET_CHECKSUM], 0);
    CPS_SETUSHORT2(&icmpdata[ICMP_OFFSET_CHECKSUM], calc_checksum(icmpdata, len));
    send_ip(icmpdata, len, NULL, 0, CPS_GETULONG2(&iphdr[IP_OFFSET_SOURCE_ADDRESS]), PROTOCOL_ICMP);
}

static void process_icmp_reply(u8 *iphdr, u8 *icmpdata, u32 len)
{
    CPSSoc *soc;

    OSIntrMode enable = OS_DisableInterrupts();
    OSThread *t = OS_GetThreadList();
    while (t != NULL) {
        soc = OSi_GetSpecificData(t, OSi_SPECIFIC_CPS);
        if (soc != NULL && soc->thread != NULL
            && soc->state == CPS_STT_PING
            && CPS_USHORT2_HOST(&icmpdata[ICMP_OFFSET_DATA]) == (u16)soc->thread
            && soc->local_port == CPS_USHORT2_HOST(&icmpdata[ICMP_OFFSET_DATA + 2])
            && soc->rcvbufp == 0
            && soc->remote_ip == CPS_GETULONG2(&iphdr[IP_OFFSET_SOURCE_ADDRESS])) {
            if (len - ICMP_HEADER_SIZE > soc->rcvbuf.size) {
                soc->rcvbufp = soc->rcvbuf.size;
            } else {
                soc->rcvbufp = len - ICMP_HEADER_SIZE;
            }

            MI_CpuCopy8(icmpdata + ICMP_HEADER_SIZE, soc->rcvbuf.data, soc->rcvbufp);

            if (soc->block_type == CPS_BLOCK_UDPREAD) {
                soc->block_type = CPS_BLOCK_NONE;
                OS_WakeupThreadDirect(soc->thread);
            }
            break;
        } else {
            t = OS_GetNextThread(t);
        }
    }
    OS_RestoreInterrupts(enable);
}

static BOOL valid_IP(CPSInAddr ip1, CPSInAddr ip2)
{
    return ip1 != 0 && ip1 != -1 && ip2 != 0 && ip2 != -1;
}

static void dispatch_icmp(u8 *iphdr, u8 *icmpdata, u32 len)
{
    if (calc_checksum(icmpdata, len) != 0xFFFF
        || !valid_IP(CPS_GETULONG2(&iphdr[IP_OFFSET_SOURCE_ADDRESS]), CPS_GETULONG2(&iphdr[IP_OFFSET_DEST_ADDRESS]))) {
        return;
    }

    switch (icmpdata[ICMP_OFFSET_TYPE]) {
    case ICMP_ECHO_REPLY:
        process_icmp_reply(iphdr, icmpdata, len);
        break;
    case ICMP_ECHO_REQUEST:
        reply_icmp(iphdr, icmpdata, len);
        break;
    }
}

static CPSSoc *check_listener(u8 *iphdr, u8 *tcphdr)
{
    CPSSoc *soc;
    OSThread *t = OS_GetThreadList();
    while (t != NULL) {
        soc = OSi_GetSpecificData(t, OSi_SPECIFIC_CPS);
        if (soc != NULL && soc->thread != NULL
            && soc->state == CPS_STT_LISTEN
            && soc->local_port == CPS_GETUSHORT2(&tcphdr[TCP_OFFSET_DEST_PORT])
            && (soc->remote_port == 0 || soc->remote_port == CPS_GETUSHORT2(&tcphdr[TCP_OFFSET_SOURCE_PORT]))
            && (soc->remote_ip == 0 || soc->remote_ip == CPS_GETULONG2(&iphdr[IP_OFFSET_SOURCE_ADDRESS]))) {
            return soc;
        }

        t = OS_GetNextThread(t);
    }

    return NULL;
}

static BOOL check_socket(u8 *iphdr, u8 *tcphdr, CPSSoc *soc)
{
    return soc->state != CPS_STT_DATAGRAM && soc->state != CPS_STT_PING
        && soc->local_port == CPS_GETUSHORT2(&tcphdr[TCP_OFFSET_DEST_PORT])
        && soc->remote_port == CPS_GETUSHORT2(&tcphdr[TCP_OFFSET_SOURCE_PORT])
        && soc->remote_ip == CPS_GETULONG2(&iphdr[IP_OFFSET_SOURCE_ADDRESS]);
}

static CPSSoc *find_socket(u8 *iphdr, u8 *tcphdr)
{
    CPSSoc *soc;
    OSThread *t = OS_GetThreadList();
    while (t != NULL) {
        soc = OSi_GetSpecificData(t, OSi_SPECIFIC_CPS);
        if (soc != NULL && soc->thread != NULL && check_socket(iphdr, tcphdr, soc)) {
            return soc;
        }
        t = OS_GetNextThread(t);
    }

    return NULL;
}

static void parse_mss(u8 *tcphdr, CPSSoc *soc)
{
    soc->remote_mss = MTUtoMSS(CPS_MIN_MTU);
    u32 len = (tcphdr[TCP_OFFSET_DATA_OFFSET] & TCP_DATA_OFFSET_MASK) / 4 - TCP_HEADER_SIZE;
    u8 *p = tcphdr + TCP_HEADER_SIZE;

    while (len-- != 0) {
        switch (*p++) {
        case TCP_OPTION_END:
            return;
        case TCP_OPTION_NOP:
            break;
        case TCP_OPTION_MSS:
            soc->remote_mss = CPS_GETUSHORT1(&p[1]);
            p += 3;
            len -= 3;
            break;
        default:
            len -= *p - 1;
            p += *p - 1;
            break;
        }
    }
}

static BOOL no_need_inq(CPSInAddr ip)
{
    ip = get_targetip(ip);
    if (!ip) {
        return TRUE;
    } else {
        return inq_arpcache(ip);
    }
}

static void tcp_send_handshake(CPSSoc *soc, u8 flag, u16 urg)
{
    if (no_need_inq(soc->remote_ip) || OS_GetCurrentThread() != &tcpip_thread) {
        send_tcp(NULL, 0, soc, flag, urg);
    } else {
        send_arprequest(get_targetip(soc->remote_ip));
    }
}

static void tcp_send_ack(CPSSoc *soc, u16 urg)
{
    tcp_send_handshake(soc, TCP_FLAG_ACK, urg);
}

static void tcp_send_finack(CPSSoc *soc, u16 urg)
{
    tcp_send_handshake(soc, TCP_FLAG_FIN | TCP_FLAG_ACK, urg);
}

static void tcp_send_rst(u8 *iphdr, u8 *tcphdr, u32 len, u16 urg)
{
    CPSSoc *soc = &tmpsoc;
    MI_CpuClear8(soc, sizeof(CPSSoc));
    soc->local_port = CPS_GETUSHORT2(&tcphdr[TCP_OFFSET_DEST_PORT]);
    soc->remote_port = CPS_GETUSHORT2(&tcphdr[TCP_OFFSET_SOURCE_PORT]);
    soc->remote_ip = CPS_GETULONG2(&iphdr[IP_OFFSET_SOURCE_ADDRESS]);

    if (tcphdr[TCP_OFFSET_FLAG] & TCP_FLAG_ACK) {
        soc->seqno = CPS_GETULONG2(&tcphdr[TCP_OFFSET_ACK_NO]);
        tcp_send_handshake(soc, TCP_FLAG_RST, urg);
    } else {
        soc->seqno = 0;
        soc->ackno = len + CPS_GETULONG2(&tcphdr[TCP_OFFSET_SEQ_NO]);
        if (tcphdr[TCP_OFFSET_FLAG] & (TCP_FLAG_FIN | TCP_FLAG_SYN)) {
            soc->ackno++;
        }
        tcp_send_handshake(soc, TCP_FLAG_RST | TCP_FLAG_ACK, urg);
    }
}

static void dt_syn_listen(u8 *iphdr, u8 *tcphdr, CPSSoc *soc)
{
    soc->state = CPS_STT_SYN_RCVD;
    soc->when = CPSi_GetTick();
    soc->local_ip_real = CPS_GETULONG2(&iphdr[IP_OFFSET_DEST_ADDRESS]);
    soc->remote_port = CPS_GETUSHORT2(&tcphdr[TCP_OFFSET_SOURCE_PORT]);
    soc->remote_ip = CPS_GETULONG2(&iphdr[IP_OFFSET_SOURCE_ADDRESS]);
    soc->ackno = CPS_GETULONG2(&tcphdr[TCP_OFFSET_SEQ_NO]) + 1;
    parse_mss(tcphdr, soc);
    tcp_send_handshake(soc, TCP_FLAG_SYN | TCP_FLAG_ACK, 0);
}

static BOOL find_specific_socket(u8 *iphdr, u8 *tcphdr, u32 len)
{
    CPSSoc *soc = find_socket(iphdr, tcphdr);
    if (soc != NULL) {
        if (soc->state == CPS_STT_LISTEN) {
            dt_syn_listen(iphdr, tcphdr, soc);
        } else if (soc->state == CPS_STT_SYN_RCVD || soc->state == CPS_STT_ESTABLISHED) {
            soc->seqno--;
            dt_syn_listen(iphdr, tcphdr, soc);
        } else {
            tcp_send_rst(iphdr, tcphdr, len, 0);
        }
        return TRUE;
    } else {
        return FALSE;
    }
}

static void dt_syn(u8 *iphdr, u8 *tcphdr, u32 len)
{
    if (!valid_IP(CPS_GETULONG2(&iphdr[IP_OFFSET_SOURCE_ADDRESS]), CPS_GETULONG2(&iphdr[IP_OFFSET_DEST_ADDRESS]))) {
        return;
    }
    if (find_specific_socket(iphdr, tcphdr, len)) {
        return;
    }

    CPSSoc *soc = check_listener(iphdr, tcphdr);
    if (soc != NULL) {
        dt_syn_listen(iphdr, tcphdr, soc);
        return;
    }

    OS_YieldThread();
    soc = check_listener(iphdr, tcphdr);
    if (soc != NULL) {
        dt_syn_listen(iphdr, tcphdr, soc);
    }
}

static void dt_synack(u8 *iphdr, u8 *tcphdr, u32 len)
{
    CPSSoc *soc = find_socket(iphdr, tcphdr);
    if (soc == NULL || soc->state != CPS_STT_SYN_SENT) {
        tcp_send_rst(iphdr, tcphdr, len, 0);
        return;
    }

    OS_YieldThread();
    soc->ackno = CPS_GETULONG2(&tcphdr[TCP_OFFSET_SEQ_NO]) + 1;
    soc->remote_ackno = CPS_GETULONG2(&tcphdr[TCP_OFFSET_ACK_NO]);
    soc->remote_win = CPS_GETUSHORT2(&tcphdr[TCP_OFFSET_WINDOW]);
    parse_mss(tcphdr, soc);
    tcp_send_ack(soc, 0);
    soc->state = CPS_STT_ESTABLISHED;

    if (soc->block_type == CPS_BLOCK_TCPCON) {
        soc->block_type = CPS_BLOCK_NONE;
        OS_WakeupThreadDirect(soc->thread);
    }
}

static void dt_ack(u8 *iphdr, u8 *tcphdr, u32 len)
{
    CPSSoc *soc = find_socket(iphdr, tcphdr);
    if (soc == NULL) {
        tcp_send_rst(iphdr, tcphdr, len, 0);
        return;
    }

    u8 flag = tcphdr[TCP_OFFSET_FLAG];

    u32 remote_ackno = CPS_GETULONG2(&tcphdr[TCP_OFFSET_ACK_NO]);
    if ((int)(remote_ackno - soc->remote_ackno) > 0) {
        soc->remote_ackno = remote_ackno;
    }

    u32 remote_seqno = CPS_GETULONG2(&tcphdr[TCP_OFFSET_SEQ_NO]);
    if (soc->state == CPS_STT_ESTABLISHED && soc->ackno != remote_seqno) {
        tcp_send_ack(soc, 0);
        return;
    }

    soc->remote_win = CPS_GETUSHORT2(&tcphdr[TCP_OFFSET_WINDOW]);

    switch (soc->state) {
    case CPS_STT_CLOSED:
    case CPS_STT_SYN_SENT:
        tcp_send_rst(iphdr, tcphdr, len, 0);
        break;
    case CPS_STT_SYN_RCVD:
        soc->state = CPS_STT_ESTABLISHED;
        if (soc->block_type == CPS_BLOCK_TCPCON) {
            soc->block_type = CPS_BLOCK_NONE;
            OS_WakeupThreadDirect(soc->thread);
        }
        if (len == 0) {
            break;
        }
    case CPS_STT_ESTABLISHED:
        soc->ackrcvd++;

        BOOL bufok;
        if (len > soc->rcvbuf.size - soc->rcvbufp) {
            bufok = FALSE;
            len = soc->rcvbuf.size - soc->rcvbufp;
        } else {
            bufok = TRUE;
        }

        if (len != 0) {
            OSIntrMode enabled = OS_DisableInterrupts();
            MI_CpuCopy8(tcphdr + (tcphdr[TCP_OFFSET_DATA_OFFSET] & TCP_DATA_OFFSET_MASK) / 4, soc->rcvbuf.data + soc->rcvbufp, len);
            soc->rcvbufp += len;
            soc->ackno += len;
            OS_RestoreInterrupts(enabled);

            if (soc->block_type == CPS_BLOCK_TCPREAD) {
                soc->block_type = CPS_BLOCK_NONE;
                OS_WakeupThreadDirect(soc->thread);
            }
        }

        if (bufok && (flag & TCP_FLAG_FIN)) {
            soc->state = CPS_STT_LAST_ACK;
            soc->ackno++;
            tcp_send_finack(soc, 0);

            if (len == 0 && soc->block_type == CPS_BLOCK_TCPREAD) {
                soc->block_type = CPS_BLOCK_NONE;
                OS_WakeupThreadDirect(soc->thread);
            }
        } else if (len != 0) {
            tcp_send_ack(soc, 0);
        }

        break;
    case CPS_STT_FIN_WAIT1:
    case CPS_STT_FIN_WAIT2:
        if (flag & TCP_FLAG_FIN) {
            soc->ackno += len + 1;
            tcp_send_ack(soc, 0);
            soc->state = CPS_STT_CLOSED;

            if (soc->block_type == CPS_BLOCK_TCPREAD) {
                soc->block_type = CPS_BLOCK_NONE;
                OS_WakeupThreadDirect(soc->thread);
            }
        } else {
            if (len != 0) {
                soc->ackno += len;
                tcp_send_ack(soc, 0);
            }

            soc->state = CPS_STT_FIN_WAIT2;
        }

        break;
    case CPS_STT_LAST_ACK:
    case CPS_STT_CLOSING:
        soc->state = CPS_STT_CLOSED;
        if (soc->block_type == CPS_BLOCK_TCPREAD) {
            soc->block_type = CPS_BLOCK_NONE;
            OS_WakeupThreadDirect(soc->thread);
        }

        break;
    case CPS_STT_LISTEN:
    case CPS_STT_CLOSE_WAIT:
    default:
        if (flag & TCP_FLAG_FIN) {
            soc->ackno++;
        }

        tcp_send_ack(soc, 0);
        break;
    }

    OS_YieldThread();
}

static void dt_fin(u8 *iphdr, u8 *tcphdr, u32 len)
{
    CPSSoc *soc = find_socket(iphdr, tcphdr);
    if (soc == NULL) {
        return;
    }

    switch (soc->state) {
    case CPS_STT_FIN_WAIT1:
        soc->ackno++;
        tcp_send_ack(soc, 0);
        soc->state = CPS_STT_CLOSING;
        break;
    case CPS_STT_FIN_WAIT2:
        soc->ackno++;
        tcp_send_ack(soc, 0);
        soc->state = CPS_STT_CLOSED;

        if (soc->block_type == CPS_BLOCK_TCPREAD) {
            soc->block_type = CPS_BLOCK_NONE;
            OS_WakeupThreadDirect(soc->thread);
        }

        break;
    case CPS_STT_ESTABLISHED:
        soc->ackno++;
        tcp_send_finack(soc, 0);
        soc->state = CPS_STT_LAST_ACK;
        break;
    default:
        tcp_send_rst(iphdr, tcphdr, len, 0);
        break;
    }
}

static void dt_rst(u8 *iphdr, u8 *tcphdr)
{
    CPSSoc *soc = find_socket(iphdr, tcphdr);
    if (soc == NULL) {
        return;
    }

    OS_YieldThread();
    soc->state = CPS_STT_CLOSED;

    if (soc->block_type == CPS_BLOCK_TCPCON || soc->block_type == CPS_BLOCK_TCPREAD) {
        soc->block_type = CPS_BLOCK_NONE;
        OS_WakeupThreadDirect(soc->thread);
    }
}

static void dispatch_tcp(u8 *iphdr, u8 *tcphdr, u32 len)
{
    if (check_tcpudpsum(tcphdr, len, iphdr, PROTOCOL_TCP)) {
        return;
    }

    len -= (tcphdr[TCP_OFFSET_DATA_OFFSET] & TCP_DATA_OFFSET_MASK) / 4;
    switch (tcphdr[TCP_OFFSET_FLAG] & (TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK)) {
    case TCP_FLAG_SYN:
        if (!(tcphdr[TCP_OFFSET_FLAG] & (TCP_FLAG_PSH | TCP_FLAG_URG))) {
            dt_syn(iphdr, tcphdr, len);
        }
        break;
    case (TCP_FLAG_SYN | TCP_FLAG_ACK):
        if (!(tcphdr[TCP_OFFSET_FLAG] & (TCP_FLAG_PSH | TCP_FLAG_URG))) {
            dt_synack(iphdr, tcphdr, len);
        }
        break;
    case (TCP_FLAG_FIN | TCP_FLAG_ACK):
    case TCP_FLAG_ACK:
        dt_ack(iphdr, tcphdr, len);
        break;
    case TCP_FLAG_FIN:
        dt_fin(iphdr, tcphdr, len);
        break;
    default:
        if (tcphdr[TCP_OFFSET_FLAG] & TCP_FLAG_RST) {
            dt_rst(iphdr, tcphdr);
        } else {
            tcp_send_rst(iphdr, tcphdr, len, 0);
        }
        break;
    }
}

static void dispatch_udp(u8 *iphdr, u8 *udphdr, u32 len)
{
    CPSSoc *soc;

    if (CPS_USHORT2_HOST(&udphdr[UDP_OFFSET_CHECKSUM]) != CPS_htons(0) && check_tcpudpsum(udphdr, len, iphdr, PROTOCOL_UDP)) {
        return;
    }

    OSIntrMode enabled = OS_DisableInterrupts();
    OSThread *t = OS_GetThreadList();
    while (t != NULL) {
        soc = OSi_GetSpecificData(t, OSi_SPECIFIC_CPS);
        if (soc != NULL && soc->thread != NULL
            && soc->state == CPS_STT_DATAGRAM
            && soc->local_port == CPS_GETUSHORT2(&udphdr[UDP_OFFSET_DEST_PORT])
            && (soc->remote_port == 0 || soc->remote_port == CPS_GETUSHORT2(&udphdr[UDP_OFFSET_SOURCE_PORT]))
            && (soc->remote_ip == 0 || soc->remote_ip == CPS_MK_IPv4(255, 255, 255, 255)
                || soc->remote_ip == CPS_GETULONG2(&iphdr[IP_OFFSET_SOURCE_ADDRESS]))) {
            soc->local_ip_real = CPS_GETULONG2(&iphdr[IP_OFFSET_DEST_ADDRESS]);

            if (soc->remote_ip == 0) {
                soc->remote_ip = CPS_GETULONG2(&iphdr[IP_OFFSET_SOURCE_ADDRESS]);
                soc->remote_port = CPS_GETUSHORT2(&udphdr[UDP_OFFSET_SOURCE_PORT]);
            }

            if (soc->rcvbufp == 0) {
                len -= UDP_HEADER_SIZE;
                if (len > soc->rcvbuf.size) {
                    soc->rcvbufp = soc->rcvbuf.size;
                } else {
                    soc->rcvbufp = len;
                }

                MI_CpuCopy8(udphdr + UDP_HEADER_SIZE, soc->rcvbuf.data, soc->rcvbufp);

                if (soc->block_type == CPS_BLOCK_UDPREAD) {
                    soc->block_type = CPS_BLOCK_NONE;
                    OS_WakeupThreadDirect(soc->thread);
                } else if (soc->udpread_callback != NULL && soc->udpread_callback(soc->rcvbuf.data, soc->rcvbufp, soc)) {
                    soc->rcvbufp = 0;
                }
            }

            break;
        } else {
            t = OS_GetNextThread(t);
        }
    }
    OS_RestoreInterrupts(enabled);
}

static u8 *check_frag(u8 *buf, BOOL *fragmented)
{
    u32 i;
    u32 frag;
    u32 id;
    u32 frag_size;
    u32 frag_ofs;
    u32 frag_last;
    u32 header_len;
    CPSFragTable *unused;
    CPSFragTable *p;
    u32 size;

    *fragmented = FALSE;
    frag = CPS_GETUSHORT2(&buf[IP_OFFSET_FRAG_OFFSET]);
    if (!(frag & (FLAG_MORE_FRAGMENTS | FRAG_OFFSET_MASK))) {
        return buf;
    }

    header_len = (buf[IP_OFFSET_VERSION_IHL] & IHL_MASK) * 4;
    id = CPS_USHORT2_HOST(&buf[IP_OFFSET_ID]);
    CPSInAddr ipfrom = CPS_GETULONG2(&buf[IP_OFFSET_SOURCE_ADDRESS]);
    unused = NULL;

    for (i = 0, p = &fragtable[0]; i < fragtable_entries; i++, p++) {
        if (p->frags != 0 && p->ipfrom == ipfrom && p->id == id) {
            break;
        }
        if (p->frags == 0 && unused == NULL) {
            unused = p;
        }
    }

    frag_size = CPS_GETUSHORT2(&buf[IP_OFFSET_TOTAL_LENGTH]) - header_len;
    frag_ofs = frag & FRAG_OFFSET_MASK;
    size = frag_size + frag_ofs * 8;
    if (i == 8) {
        if (unused == NULL || size > CPS_MAX_IPSIZE) {
            return NULL;
        }

        p = unused;
        p->buf = CPSiAlloc(CPS_MAX_IPSIZE + ETHERNET_HEADER_SIZE + header_len);
        if (p->buf == 0) {
            return NULL;
        }

        p->ipfrom = ipfrom;
        p->id = id;
        p->last = 0;
        p->when = CPSi_GetTick();
        p->ofs0 = p->buf + ETHERNET_HEADER_SIZE + header_len;
        MI_CpuCopy8(buf, p->buf + ETHERNET_HEADER_SIZE, header_len);
    }

    if (p->frags == CPS_MAX_IPFRAG || size > CPS_MAX_IPSIZE) {
        p->frags = 0;
        CPSiFree(p->buf);
        return NULL;
    }

    frag_last = frag_ofs + (frag_size + 7) / 8;

    if (!(frag & FLAG_MORE_FRAGMENTS)) {
        p->size = size;
        p->last = frag_last;
    }

    p->from[p->frags] = frag_ofs;
    p->to[p->frags] = frag_last;
    p->frags++;
    MI_CpuCopy8(buf + header_len, p->ofs0 + frag_ofs * 8, frag_size);

    if (p->last == 0) {
        return NULL;
    }

    frag_ofs = 0;
    for (i = 0; i < p->frags;) {
        if (p->from[i] <= frag_ofs && frag_ofs < p->to[i]) {
            frag_ofs = p->to[i];
            i = 0;
        } else {
            i++;
        }
    }

    if (frag_ofs < p->last) {
        return NULL;
    }

    buf = p->buf + ETHERNET_HEADER_SIZE;
    CPS_SETUSHORT2(&buf[IP_OFFSET_TOTAL_LENGTH], p->size + (buf[IP_OFFSET_VERSION_IHL] & IHL_MASK) * 4);
    p->frags = 0;
    *fragmented = TRUE;
    return buf;
}

static void dispatch_ip(u8 *buf, u32 len)
{
    BOOL fragmented;

    if (CPS_GETULONG2(&buf[IP_OFFSET_DEST_ADDRESS]) != CPS_GETULONG2(&buf[IP_OFFSET_SOURCE_ADDRESS])) {
        if (!ip_isme(CPS_GETULONG2(&buf[IP_OFFSET_DEST_ADDRESS]))
            || len < CPS_GETUSHORT2(&buf[IP_OFFSET_TOTAL_LENGTH])
            || calc_checksum(buf, (buf[IP_OFFSET_VERSION_IHL] & IHL_MASK) * 4) != 0xFFFF) {
            return;
        }

        if (CPSMyIp == CPS_GETULONG2(&buf[IP_OFFSET_DEST_ADDRESS])) {
            reg_arpcache(
                (CPSMacAddress *)(&buf[ETHERNET_OFFSET_MAC_SOURCE - ETHERNET_HEADER_SIZE]),
                CPS_GETULONG2(&buf[IP_OFFSET_SOURCE_ADDRESS]),
                TRUE);
        }
    }

    buf = check_frag(buf, &fragmented);
    if (buf == NULL) {
        return;
    }

    u32 header_len = (buf[IP_OFFSET_VERSION_IHL] & IHL_MASK) * 4;
    u8 *data = buf + header_len;
    len = CPS_GETUSHORT2(&buf[IP_OFFSET_TOTAL_LENGTH]) - header_len;
    u8 type = buf[IP_OFFSET_PROTOCOL];

    if (type == PROTOCOL_UDP) {
        dispatch_udp(buf, data, len);
    } else if (CPSMyIp != 0) {
        if (type == PROTOCOL_ICMP) {
            dispatch_icmp(buf, data, len);
        } else if (type == PROTOCOL_TCP) {
            dispatch_tcp(buf, data, len);
        }
    }

    if (fragmented) {
        CPSiFree(buf - ETHERNET_HEADER_SIZE);
    }
}

static void tcpip(void *unused)
{
    u32 len;

    while (TRUE) {
        u8 *buf = receive_packet(&len);
        if (len > ETHERNET_HEADER_SIZE + IP_HEADER_SIZE) {
            switch (CPS_GETUSHORT2(&buf[ETHERNET_OFFSET_TYPE])) {
            case ETHERTYPE_IPV4:
                dispatch_ip(buf + ETHERNET_HEADER_SIZE, len - ETHERNET_HEADER_SIZE);
                break;
            case ETHERTYPE_ARP:
                dispatch_arp(buf + ETHERNET_HEADER_SIZE, len - ETHERNET_HEADER_SIZE);
                break;
            }
        }

        throw_packet();
    }
}

u16 CPS_SocGetEport(void)
{
    BOOL conflict;

    do {
        conflict = FALSE;
        eport++;
        if (eport < CPS_MIN_EPORT || CPS_MAX_EPORT <= eport) {
            eport = CPS_MIN_EPORT;
        }

        OSThread *t = OS_GetThreadList();
        while (t != NULL) {
            CPSSoc *soc = OSi_GetSpecificData(t, OSi_SPECIFIC_CPS);
            if (soc != NULL && soc->thread != NULL && soc->local_port == eport) {
                conflict = TRUE;
                break;
            } else {
                t = OS_GetNextThread(t);
            }
        }
    } while (conflict);

    return eport;
}

static u32 get_seqno(void)
{
    return MATH_Rand32(&CPSiRand32ctx, 0);
}

void CPS_SocRegister(CPSSoc *soc)
{
    CPS_SET_CURSOC(soc);
}

void CPS_SocUnRegister(void)
{
    CPS_SET_CURSOC(NULL);
}

void CPS_SocDatagramMode(void)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc == NULL) {
        return;
    }

    soc->state = CPS_STT_DATAGRAM;
    soc->rcvbufp = 0;
}

void CPS_SocPingMode(void)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc == NULL) {
        return;
    }

    soc->state = CPS_STT_PING;
    soc->rcvbufp = 0;
}

void CPS_SocBind(u16 local_port, u16 remote_port, CPSInAddr remote_ip)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc == NULL) {
        return;
    }

    if (remote_ip == CPS_MK_IPv4(127, 0, 0, 1)) {
        remote_ip = CPSMyIp;
    }

    soc->remote_port_bound = remote_port;
    soc->remote_port = soc->remote_port_bound;
    soc->remote_ip_bound = remote_ip;
    soc->remote_ip = remote_ip;

    if (local_port != 0) {
        soc->local_port = local_port;
    } else {
        soc->local_port = CPS_SocGetEport();
    }
}

void CPS_SocUse(void)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc == NULL) {
        return;
    }

    soc->thread = OS_GetCurrentThread();
    soc->state = CPS_STT_CLOSED;
    soc->rcvbufp = 0;
    soc->outbufp = 0;
    soc->udpread_callback = NULL;
}

void CPS_SocRelease(void)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc != NULL) {
        soc->thread = NULL;
    }
}

void CPS_SocDup(OSThread *thread)
{
    OSi_SetSpecificData(thread, OSi_SPECIFIC_CPS, CPS_CURSOC);
}

void CPSi_TcpListenRaw(CPSSoc *soc)
{
    soc->seqno = get_seqno();
    soc->remote_ackno = soc->seqno;
    soc->state = CPS_STT_LISTEN;

    OSIntrMode enable = OS_DisableInterrupts();
    soc->block_type = CPS_BLOCK_TCPCON;
    OS_SleepThread(NULL);
    OS_RestoreInterrupts(enable);
}

void CPS_SetUdpCallback(CPSUDPReadCallback callback)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc != NULL) {
        soc->udpread_callback = callback;
    }
}

void CPS_TcpListen(void)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc == NULL) {
        return;
    }

    if (soc->ssl) {
        CPSi_SslListen(soc);
    } else {
        CPSi_TcpListenRaw(soc);
    }
}

u32 CPSi_TcpConnectRaw(CPSSoc *soc)
{
    u32 retry;
    u32 seqno = get_seqno();

    for (retry = 0; retry < 3; retry++) {
        soc->seqno = seqno;
        soc->state = CPS_STT_SYN_SENT;
        soc->when = CPSi_GetTick();
        tcp_send_handshake(soc, TCP_FLAG_SYN, 24);

        OSIntrMode enabled = OS_DisableInterrupts();
        if (soc->state == CPS_STT_SYN_SENT && CPSMyIp != 0) {
            soc->block_type = CPS_BLOCK_TCPCON;
            OS_SleepThread(NULL);
        }
        OS_RestoreInterrupts(enabled);

        if (soc->state == CPS_STT_ESTABLISHED) {
            return 0;
        }

        if (CPSMyIp == 0) {
            break;
        }
    }

    return 1;
}

u32 CPS_TcpConnect(void)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc != NULL) {
        if (soc->ssl) {
            return CPSi_SslConnect(soc);
        } else {
            return CPSi_TcpConnectRaw(soc);
        }
    }

    return 1;
}

CPSInAddr CPS_SocWho(u16 *remote_port, CPSInAddr *local_ip)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc != NULL && (soc->state == CPS_STT_ESTABLISHED || soc->state == CPS_STT_DATAGRAM)) {
        if (remote_port != NULL) {
            *remote_port = soc->remote_port;
        }
        if (local_ip != NULL) {
            *local_ip = soc->local_ip_real;
        }

        return soc->remote_ip;
    }

    return 0;
}

void CPSi_TcpShutdownRaw(CPSSoc *soc)
{
    OS_YieldThread();

    if (soc->state == CPS_STT_SYN_RCVD || soc->state == CPS_STT_ESTABLISHED) {
        tcp_send_finack(soc, 25);
        soc->state = CPS_STT_FIN_WAIT1;
    } else if (soc->state != CPS_STT_CLOSED) {
        tcp_send_ack(soc, 26);
    }
}

void CPS_TcpShutdown(void)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc == NULL) {
        return;
    }

    if (soc->ssl) {
        CPSi_SslShutdown(soc);
    }

    CPSi_TcpShutdownRaw(soc);
}

void CPS_TcpClose(void)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc == NULL) {
        return;
    }

    if (soc->ssl) {
        CPSi_SslClose(soc);
    }

    u32 start = CPSi_GetTick();
    while (link_is_on() && soc->state != CPS_STT_CLOSED && (int)(CPSi_GetTick() - start) < CPS_MilliSecondsToLTicks(5000)) {
        yield_thread();
    }

    soc->state = CPS_STT_CLOSED;
}

static u8 *udp_read_raw(u32 *len, CPSSoc *soc)
{
    u32 tmp;
    OSIntrMode enable = OS_DisableInterrupts();
    while ((tmp = soc->rcvbufp) == 0) {
        soc->block_type = CPS_BLOCK_UDPREAD;
        OS_SleepThread(NULL);
    }
    OS_RestoreInterrupts(enable);

    *len = tmp;
    return soc->rcvbuf.data;
}

u8 *CPSi_TcpReadRaw(u32 *len, CPSSoc *soc)
{
    if (soc->rcvbufp == 0 && soc->state == CPS_STT_ESTABLISHED) {
        OSIntrMode enable = OS_DisableInterrupts();
        while (soc->rcvbufp == 0 && soc->state == CPS_STT_ESTABLISHED) {
            soc->block_type = CPS_BLOCK_TCPREAD;
            OS_SleepThread(NULL);
        }
        OS_RestoreInterrupts(enable);
    } else {
        OS_YieldThread();
    }

    *len = soc->rcvbufp;
    if (*len != 0) {
        return soc->rcvbuf.data;
    } else {
        return 0;
    }
}

u8 *CPS_SocRead(u32 *len)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc != NULL) {
        if (soc->state == CPS_STT_DATAGRAM || soc->state == CPS_STT_PING) {
            return udp_read_raw(len, soc);
        } else if (soc->ssl) {
            return CPSi_SslRead(len, soc);
        } else {
            return CPSi_TcpReadRaw(len, soc);
        }
    } else {
        *len = 0;
        return NULL;
    }
}

void CPSi_SocConsumeRaw(u32 len, CPSSoc *soc)
{
    OSIntrMode enabled = OS_DisableInterrupts();
    BOOL buf_was_full = FALSE;
    if (soc->rcvbufp == soc->rcvbuf.size && len != 0) {
        buf_was_full = TRUE;
    }

    if (len >= soc->rcvbufp) {
        soc->rcvbufp = 0;
    } else {
        u8 *d = soc->rcvbuf.data;
        u8 *s = d + len;
        len = soc->rcvbufp - len;
        soc->rcvbufp = len;
        memmove(d, s, len);
    }
    OS_RestoreInterrupts(enabled);

    if (soc->state != CPS_STT_DATAGRAM && soc->state != CPS_STT_PING && (soc->rcvbufp == 0 || buf_was_full)) {
        tcp_send_ack(soc, 27);
    }
}

void CPS_SocConsume(u32 len)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc == NULL) {
        return;
    }

    if (soc->ssl) {
        CPSi_SslConsume(len, soc);
    } else {
        CPSi_SocConsumeRaw(len, soc);
    }
}

void CPS_TcpAck(void)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc == NULL) {
        return;
    }

    tcp_send_ack(soc, 28);
}

static u32 tcp_write_do(u8 *buf, u32 len, CPSSoc *soc, BOOL need_probe)
{
    u32 this_len;
    u32 remote_win;

    if (need_probe) {
        remote_win = 1;
    } else {
        remote_win = soc->remote_win;
    }

    u32 ackrcvd_save = soc->ackrcvd;
    u32 limit = ackrcvd_save * 2 + 4;
    while (len != 0 && soc->state == CPS_STT_ESTABLISHED) {
        if (soc->remote_mss < remote_win) {
            this_len = soc->remote_mss;
        } else {
            this_len = remote_win;
        }

        if (mymss < this_len) {
            this_len = mymss;
        }

        if (!need_probe) {
            this_len &= ~1;
        }

        if (len < this_len) {
            this_len = len;
        }

        limit += (soc->ackrcvd - ackrcvd_save);
        ackrcvd_save = soc->ackrcvd;

        if (limit-- == 0) {
            this_len = 0;
        }
        if (this_len == 0) {
            break;
        }

        remote_win -= this_len;
        send_tcp(buf, this_len, soc, TCP_FLAG_PSH | TCP_FLAG_ACK, 0);
        OS_YieldThread();
        buf += this_len;
        len -= this_len;
    }

    return this_len;
}

static void tcp_write_do2(u8 *buf, u32 len, u8 *buf2, u32 len2, CPSSoc *soc, BOOL need_probe)
{
    if (tcp_write_do(buf, len, soc, need_probe) != 0 && len2 != 0) {
        tcp_write_do(buf2, len2, soc, FALSE);
    }
}

u32 CPSi_TcpWrite2Raw(u8 *buf, u32 len, u8 *buf2, u32 len2, CPSSoc *soc)
{
    u32 total_written = 0;
    u32 acked_len;
    BOOL need_probe = FALSE;

    soc->ackrcvd = 0;
    u32 start_time = CPSi_GetTick();
    while (link_is_on() && len != 0 && soc->state == CPS_STT_ESTABLISHED
        && (int)(CPSi_GetTick() - start_time) < CPS_MilliSecondsToLTicks(20000)) {
        u32 seqno = soc->seqno;
        tcp_write_do2(buf, len, buf2, len2, soc, need_probe);
        u32 retry_time = CPSi_GetTick();
        do {
            yield_thread();
        } while (link_is_on() && soc->state == CPS_STT_ESTABLISHED && soc->seqno != soc->remote_ackno
            && (int)(CPSi_GetTick() - retry_time) < CPS_MilliSecondsToLTicks(2000) && (!need_probe || soc->remote_win == 0));

        acked_len = soc->remote_ackno - seqno;
        if (acked_len > soc->seqno - seqno) {
            acked_len = 0;
        }

        total_written += acked_len;
        if (acked_len != 0) {
            start_time = CPSi_GetTick();
        }

        soc->seqno = soc->remote_ackno;
        if (soc->state == CPS_STT_ESTABLISHED && soc->remote_win == 0 && acked_len == 0) {
            if (!need_probe) {
                retry_time = CPSi_GetTick();
                while (link_is_on() && (int)(CPSi_GetTick() - retry_time) < CPS_MilliSecondsToLTicks(2000)) {
                    yield_thread();
                    if (soc->remote_win != 0) {
                        break;
                    }
                }

                if (soc->remote_win == 0) {
                    need_probe = TRUE;
                }
            }
        } else {
            need_probe = FALSE;
        }

        if (acked_len >= len) {
            acked_len -= len;
            buf = buf2 + acked_len;
            len = len2 - acked_len;
            buf2 = NULL;
            len2 = NULL;
        } else {
            buf += acked_len;
            len -= acked_len;
        }
    }

    return total_written;
}

u32 CPSi_SocWrite2(u8 *buf, u32 len, u8 *buf2, u32 len2)
{
    CPSSoc *soc = CPS_CURSOC;
    u32 total_written;

    if (soc != NULL) {
        if (soc->state == CPS_STT_DATAGRAM) {
            if (len != 0) {
                send_udp(buf, len, soc);
            }
            if (len2 != 0) {
                send_udp(buf2, len2, soc);
            }
            total_written = len + len2;
        } else if (soc->state == CPS_STT_PING) {
            if (len != 0) {
                send_ping(buf, len, soc);
            }
            if (len2 != 0) {
                send_ping(buf2, len2, soc);
            }
            total_written = len + len2;
        } else if (soc->ssl) {
            total_written = CPSi_SslWrite2(buf, len, buf2, len2, soc);
        } else {
            total_written = CPSi_TcpWrite2Raw(buf, len, buf2, len2, soc);
        }

        if (wfailed == 0) {
            return total_written;
        }
    }

    return 0;
}

u32 CPS_SocWrite(u8 *buf, u32 len)
{
    u32 total_written;
    CPSSoc *soc = CPS_CURSOC;
    if (soc != NULL) {
        if (soc->outbufp != 0) {
            total_written = CPSi_SocWrite2(soc->outbuf.data, soc->outbufp, buf, len);
            if (total_written < soc->outbufp) {
                memmove(soc->outbuf.data, soc->outbuf.data + total_written, soc->outbufp - total_written);
                soc->outbufp -= total_written;
                total_written = 0;
            } else {
                total_written -= soc->outbufp;
                soc->outbufp = 0;
            }
        } else {
            total_written = CPSi_SocWrite2(buf, len, NULL, 0);
        }
        return total_written;
    } else {
        return 0;
    }
}

s32 CPS_SocGetLength(void)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc != NULL) {
        if (soc->ssl) {
            return CPSi_SslGetLength(soc);
        }

        s32 count = soc->rcvbufp;
        if (count != 0 || soc->state == CPS_STT_ESTABLISHED || soc->state == CPS_STT_DATAGRAM || soc->state == CPS_STT_PING) {
            return count;
        } else {
            return -1;
        }
    } else {
        return 0;
    }
}

int CPS_SocGetChar(void)
{
    u32 len;
    u8 *s = CPS_SocRead(&len);
    if (s == NULL) {
        return -1;
    }

    u8 c = *s;
    CPS_SocConsume(1);
    return c;
}

void CPS_SocFlush(void)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc != NULL && soc->outbufp != 0) {
        CPSi_SocWrite2(soc->outbuf.data, soc->outbufp, NULL, 0);
        soc->outbufp = 0;
    }
}

void CPS_SocPutChar(char c)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc != NULL && soc->outbuf.data != NULL) {
        soc->outbuf.data[soc->outbufp++] = c;
        if (soc->outbufp == soc->outbuf.size) {
            CPS_SocFlush();
        }
    }
}

void CPS_SocPuts(char *s)
{
    char c;
    while (c = *s++) {
        CPS_SocPutChar(c);
    }
}

u8 *CPS_SocGets(void)
{
    CPSSoc *soc = CPS_CURSOC;
    u8 *d;
    u8 *s;
    u8 *s0;
    u32 len;
    u32 valid_len;

    if (soc != NULL && soc->linbuf.data != NULL) {
        CPS_SocFlush();
        d = soc->linbuf.data;
        int seen_cr = 0;
        BOOL truncated = FALSE;
        while (s = CPS_SocRead(&len)) {
            for (valid_len = 0, s0 = s; valid_len < len; valid_len++) {
                if (*s0++ == '\r') {
                    seen_cr = 1;
                    break;
                }
            }

            u32 room = soc->linbuf.size - (d - soc->linbuf.data);
            if (valid_len >= room) {
                valid_len = room - 1;
                seen_cr = 0;
                truncated = TRUE;
            }

            MI_CpuCopy8(s, d, valid_len);
            CPS_SocConsume(valid_len + seen_cr);
            d += valid_len;

            if (truncated) {
                *d = '\0';
                return soc->linbuf.data;
            }

            if (seen_cr) {
                int c = CPS_SocGetChar();
                if (c == -1) {
                    return NULL;
                }
                *d = '\0';
                return soc->linbuf.data;
            }
        }
    }

    return NULL;
}

s32 CPS_GetProperSize(void)
{
    CPSSoc *soc = CPS_CURSOC;
    s32 len;
    if (soc != NULL && soc->state == CPS_STT_ESTABLISHED) {
        if (soc->remote_mss < soc->remote_win) {
            len = soc->remote_mss;
        } else {
            len = soc->remote_win;
        }

        if (mymss < len) {
            len = mymss;
        }

        if ((int)(soc->sndbuf.size - (ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + TCP_HEADER_SIZE)) < len) {
            len = soc->sndbuf.size - (ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + TCP_HEADER_SIZE);
        }

        return len;
    } else {
        return -1;
    }
}

static void set_fixed_ip(void)
{
    dhcp_callback();
    if (CPSMyIp == 0) {
        return;
    }

    send_arprequest(CPSMyIp);
    OS_Sleep(100);
    send_arprequest(CPSMyIp);

    u32 start = CPSi_GetTick();

    while (link_is_on() && (int)(CPSi_GetTick() - start) < CPS_MilliSecondsToLTicks(3000)) {
        if (ip_conflict) {
            reset_network_vars(CPS_NOIP_REASON_COLLISION);
            return;
        }
        OS_Sleep(100);
    }
}

static void scavenger(void *unused)
{
    int i;

    scavenger_force_exit = FALSE;
    MI_CpuClear8(&scavenger_soc, sizeof(CPSSoc));

    scavenger_soc.rcvbuf.size = sizeof(scavenger_rcvbuf);
    scavenger_soc.rcvbuf.data = scavenger_rcvbuf;
    scavenger_soc.sndbuf.size = sizeof(scavenger_sndbuf);
    scavenger_soc.sndbuf.data = scavenger_sndbuf;

    CPS_SocRegister(&scavenger_soc);
    int dhcp_state = DHCP_STATE_INIT;
    u32 dhcp_sleep = 1;
    u32 gwcache_sleep = 1;
    BOOL first = TRUE;
    CPSNoIpReason = CPS_NOIP_REASON_LINKOFF;

    while (TRUE) {
        OS_Sleep(1000);
        if (scavenger_force_exit) {
            break;
        }

        u32 now = CPSi_GetTick();
        if (link_is_on()) {
            if (--dhcp_sleep == 0) {
                if (mode & CPS_DONOTUSE_DHCP) {
                    if (dhcp_state == DHCP_STATE_INIT) {
                        set_fixed_ip();
                        dhcp_state = DHCP_STATE_BOUND;
                    }
                } else {
                    switch (dhcp_state) {
                    case DHCP_STATE_INIT:
                        if (first) {
                            CPSNoIpReason = CPS_NOIP_REASON_DHCPDISCOVERY;
                            first = FALSE;
                        }

                        if (!dhcp_discover_server() || !dhcp_request_server(&dhcp_sleep, DHCP_MODE_REQUEST_IP)) {
                            set_fixed_ip();
                            dhcp_state = DHCP_STATE_FIXED_IP;
                        } else {
                            dhcp_state = DHCP_STATE_BOUND;
                        }
                        break;
                    case DHCP_STATE_BOUND:
                        if (!dhcp_request_server(&dhcp_sleep, DHCP_MODE_RENEW)) {
                            if (dhcp_sleep < 60) {
                                dhcp_state = DHCP_STATE_REBINDING;
                            }
                        }
                        break;
                    case DHCP_STATE_REBINDING:
                        if (dhcp_request_server(&dhcp_sleep, DHCP_MODE_REBIND)) {
                            dhcp_state = DHCP_STATE_BOUND;
                        } else if (dhcp_sleep < 60) {
                            reset_network_vars(CPS_NOIP_REASON_LEASETIMEOUT);
                            gwcache_sleep = 1;
                            dhcp_sleep = 1;
                            dhcp_state = DHCP_STATE_INIT;
                        }
                        break;
                    case DHCP_STATE_FIXED_IP:
                    default:
                        break;
                    }
                }
            }
        } else {
            reset_network_vars(CPS_NOIP_REASON_LINKOFF);
            gwcache_sleep = 1;
            dhcp_sleep = 1;
            dhcp_state = DHCP_STATE_INIT;
        }

        for (i = 0; i < arpcache_entries; i++) {
            if (arpcache[i].ip != 0 && (s16)(now - arpcache[i].when) > CPS_MilliSecondsToLTicks(120000)) {
                arpcache[i].ip = 0;
            }
        }

        if (CPSGatewayIp != 0) {
            if (--gwcache_sleep == 0) {
                send_arprequest(CPSGatewayIp);
                gwcache_sleep = 105;
            }
        }

        OSThread *t = OS_GetThreadList();
        while (t != NULL) {
            CPSSoc *soc = OSi_GetSpecificData(t, OSi_SPECIFIC_CPS);
            if (soc != NULL && soc->thread != NULL) {
                if (soc->state == CPS_STT_SYN_RCVD && (int)(now - soc->when) > CPS_MilliSecondsToLTicks(5000)) {
                    soc->state = CPS_STT_LISTEN;
                    soc->remote_port = soc->remote_port_bound;
                    soc->remote_ip = soc->remote_ip_bound;
                } else if (soc->state == CPS_STT_SYN_SENT && (int)(now - soc->when) > CPS_MilliSecondsToLTicks(5000)) {
                    if (soc->block_type == CPS_BLOCK_TCPCON) {
                        soc->state = CPS_STT_CLOSED;
                        soc->block_type = CPS_BLOCK_NONE;
                        OS_WakeupThreadDirect(soc->thread);
                    }
                } else if (soc->state != CPS_STT_ESTABLISHED) {
                    if (soc->block_type == CPS_BLOCK_TCPREAD) {
                        soc->block_type = CPS_BLOCK_NONE;
                        OS_WakeupThreadDirect(soc->thread);
                    }
                }
            }
            t = OS_GetNextThread(t);
        }

        for (i = 0; i < fragtable_entries; i++) {
            if (fragtable[i].frags != 0 && (int)(now - fragtable[i].when) > CPS_MilliSecondsToLTicks(30000)) {
                CPSiFree(fragtable[i].buf);
                fragtable[i].frags = 0;
            }
        }

        CPSi_SslPeriodical(now);
        if (scavenger_callback != NULL) {
            scavenger_callback();
        }
    }

    if (!(mode & CPS_DONOTUSE_DHCP) && dhcp_state != DHCP_STATE_FIXED_IP) {
        dhcp_release_server();
    }

    CPS_SocUnRegister();
}

static u8 *dhcp_setcommon(u8 *d, int type, u32 *pid)
{
    MI_CpuClear8(d, DHCP_FIXED_SEGMENT_SIZE);
    CPS_SETUSHORT2(&d[DHCP_OFFSET_OPERATION], DHCP_REQUEST << 8 | HARDWARE_TYPE_ETHERNET);
    d[DHCP_OFFSET_HARDWARE_LENGTH] = sizeof(CPSMacAddress);
    u32 id = MATH_Rand32(&CPSiRand32ctx, 0);
    if (pid != NULL) {
        *pid = id;
    }
    CPS_SETULONG2(&d[DHCP_OFFSET_TRANSACTION_ID], id);
    CPS_SETULONG2(&d[DHCP_OFFSET_CLIENT_IP_ADDRESS], CPSMyIp);
    MI_CpuCopy8(CPSMyMac, &d[DHCP_OFFSET_CLIENT_HARDWARE_ADDRESS], sizeof(CPSMacAddress));
    CPS_SETULONG2(&d[DHCP_OFFSET_MAGIC_COOKIE], DHCP_MAGIC_COOKIE);

    CPS_SETUSHORT2(&d[DHCP_OFFSET_OPTIONS_START], DHCP_OPTION_MESSAGE_TYPE << 8 | 1);
    d += DHCP_OFFSET_OPTIONS_START + 2;
    *d++ = type;

    *d++ = DHCP_OPTION_CLIENT_ID;
    *d++ = sizeof(CPSMacAddress) + 1;
    *d++ = 1;
    MI_CpuCopy8(CPSMyMac, d, sizeof(CPSMacAddress));
    d += sizeof(CPSMacAddress);

    *d++ = DHCP_OPTION_HOST_NAME;
    *d++ = 10;
    MI_CpuCopy8("NintendoDS", d, 10);
    d += 10;

    *d++ = DHCP_OPTION_PARAMETER_REQ_LIST;
    *d++ = 3;
    *d++ = DHCP_OPTION_SUBNET_MASK;
    *d++ = DHCP_OPTION_ROUTER;
    *d++ = DHCP_OPTION_DNS_SERVER;

    return d;
}

static u8 *pad_mem(u8 pattern, u32 minimum, u8 *d, u32 curlen)
{
    if (curlen < minimum) {
        MI_CpuFill8(d, pattern, minimum - curlen);
        d += minimum - curlen;
    }
    return d;
}

static u32 dhcp_send_discover(void)
{
    u32 id;

    u8 *buf = scavenger_sndbuf + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE;
    u8 *d = dhcp_setcommon(buf, DHCPDISCOVER, &id);
    if (offered_myip != 0) {
        *d++ = DHCP_OPTION_REQUESTED_IP;
        *d++ = sizeof(CPSInAddr);
        CPS_SETULONG1(d, offered_myip);
        d += sizeof(CPSInAddr);
    }
    *d++ = DHCP_OPTION_END;
    CPS_SocWrite(buf, pad_mem(0, 300, d, d - buf) - buf);
    return id;
}

static u32 dhcp_send_request(int mode)
{
    u32 id;

    u8 *buf = scavenger_sndbuf + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE;
    u8 *d = dhcp_setcommon(buf, DHCPREQUEST, &id);

    if (mode == DHCP_MODE_REQUEST_IP) {
        *d++ = DHCP_OPTION_REQUESTED_IP;
        *d++ = sizeof(CPSInAddr);
        CPS_SETULONG1(d, offered_myip);
        d += sizeof(CPSInAddr);
        *d++ = DHCP_OPTION_SERVER_ID;
        *d++ = sizeof(CPSInAddr);
        CPS_SETULONG1(d, CPSDhcpServerIp);
        d += sizeof(CPSInAddr);
    }

    *d++ = DHCP_OPTION_END;
    CPS_SocWrite(buf, pad_mem(0, 300, d, d - buf) - buf);
    return id;
}

static int dhcp_analyze_response(u32 id, int retry)
{
    u8 *s;
    u8 *end;
    u32 len;
    u8 c;

    s32 timeout = (retry + 1) * CPS_MilliSecondsToLTicks(2000);
    u32 start = CPSi_GetTick();
    int result = DHCP_RESULT_NONE;

    while (link_is_on() && result == DHCP_RESULT_NONE && (int)(CPSi_GetTick() - start) < timeout) {
        if (CPS_SocGetLength() == 0) {
            yield_thread();
        } else {
            s = CPS_SocRead(&len);
            if (len > DHCP_OFFSET_OPTIONS_START && s[0] == DHCP_REPLY && id == CPS_GETULONG2(&s[DHCP_OFFSET_TRANSACTION_ID])
                && maccmp(&s[DHCP_OFFSET_CLIENT_HARDWARE_ADDRESS], CPSMyMac) == 0) {
                result = DHCP_RESULT_REPLY;
                u32 myip_tmp = CPS_GETULONG1(&s[DHCP_OFFSET_YOUR_IP_ADDRESS]);
                end = s + len;
                s += DHCP_OFFSET_MAGIC_COOKIE;
                if (*s++ == ((DHCP_MAGIC_COOKIE >> 24) & 0xFF) && *s++ == ((DHCP_MAGIC_COOKIE >> 16) & 0xFF)
                    && *s++ == ((DHCP_MAGIC_COOKIE >> 8) & 0xFF) && *s++ == (DHCP_MAGIC_COOKIE & 0xFF)) {
                    while (s < end && (c = *s++) != DHCP_OPTION_END) {
                        if (c != 0) {
                            switch (c) {
                            case DHCP_OPTION_SUBNET_MASK:
                                CPSNetMask = CPS_GETULONG1(&s[1]);
                                break;
                            case DHCP_OPTION_ROUTER:
                                CPSGatewayIp = CPS_GETULONG1(&s[1]);
                                break;
                            case DHCP_OPTION_DNS_SERVER:
                                if (s[0] < 8) {
                                    CPSDnsIp[1] = 0;
                                } else {
                                    CPSDnsIp[1] = CPS_GETULONG1(&s[5]);
                                }
                                CPSDnsIp[0] = CPS_GETULONG1(&s[1]);
                                break;
                            case DHCP_OPTION_LEASE_TIME:
                                lease_time = CPS_GETULONG1(&s[1]);
                                break;
                            case DHCP_OPTION_MESSAGE_TYPE:
                                switch (s[1]) {
                                case DHCPOFFER:
                                    offered_myip = myip_tmp;
                                    result = DHCP_RESULT_OFFER;
                                    break;
                                case DHCPACK:
                                    CPSMyIp = myip_tmp;
                                    result = DHCP_RESULT_ACK;
                                    break;
                                }
                                break;
                            case DHCP_OPTION_SERVER_ID:
                                CPSDhcpServerIp = CPS_GETULONG1(&s[1]);
                                break;
                            }
                            s += s[0] + 1;
                        }
                    }
                }
            }
            CPS_SocConsume(len);
        }
    }

    return result;
}

static BOOL dhcp_discover_server(void)
{
    int result;

    CPS_SocUse();
    CPS_SocDatagramMode();
    CPS_SocBind(PORT_DHCP_CLIENT, PORT_DHCP_SERVER, CPS_MK_IPv4(255, 255, 255, 255));

    for (int retry = 0; retry < 4; retry++) {
        result = dhcp_analyze_response(dhcp_send_discover(), retry);
        if (result == DHCP_RESULT_OFFER) {
            break;
        }
    }

    CPS_SocRelease();
    return result == DHCP_RESULT_OFFER;
}

static BOOL dhcp_request_server(u32 *sleep, int mode)
{
    int result;
    static u32 sleep_save = 0;

    CPS_SocUse();
    CPS_SocDatagramMode();

    if (mode == DHCP_MODE_RENEW) {
        CPS_SocBind(PORT_DHCP_CLIENT, PORT_DHCP_SERVER, CPSDhcpServerIp);
    } else {
        CPS_SocBind(PORT_DHCP_CLIENT, PORT_DHCP_SERVER, CPS_MK_IPv4(255, 255, 255, 255));
    }

    for (int retry = 0; retry < 4; retry++) {
        result = dhcp_analyze_response(dhcp_send_request(mode), retry);
        if (result != DHCP_RESULT_NONE) {
            break;
        }
    }

    CPS_SocRelease();

    if (result == DHCP_RESULT_ACK) {
        *sleep = lease_time / 2;
        sleep_save = (lease_time * 3) / 8;
        return TRUE;
    }

    sleep_save /= 2;
    *sleep = sleep_save;

    switch (mode) {
    case DHCP_MODE_RENEW:
        if (sleep_save < 60) {
            *sleep = 1;
            sleep_save = lease_time / 8;
        }
        break;
    case DHCP_MODE_REBIND:
        if (sleep_save < 60) {
            *sleep = 1;
        }
        break;
    }

    return FALSE;
}

static void dhcp_release_server(void)
{
    CPS_SocUse();
    CPS_SocDatagramMode();
    CPS_SocBind(PORT_DHCP_CLIENT, PORT_DHCP_SERVER, CPSDhcpServerIp);

    u8 *buf = scavenger_sndbuf + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE;
    u8 *d = dhcp_setcommon(buf, DHCPRELEASE, NULL);
    *d++ = DHCP_OPTION_END;

    CPS_SocWrite(buf, pad_mem(0, 300, d, d - buf) - buf);
    CPS_SocRelease();
}

static u8 *dns_skipname(u8 *s)
{
    u8 c;
    while ((c = *s++) != '\0') {
        if ((c & DNS_COMPRESSION_POINTER_MASK) == DNS_COMPRESSION_POINTER_MASK) {
            return s + 1;
        }
        s += c;
    }
    return s;
}

static CPSInAddr resolve_common(u8 *name, u32 type, u16 id, u8 *rname, u32 rname_max)
{
    u8 outbuf[60];
    u8 c;

    CPS_SETUSHORT2(&outbuf[DNS_OFFSET_TRANSACTION_ID], id);
    if (type != DNS_TYPE_NB) {
        CPS_SETUSHORT2(&outbuf[DNS_OFFSET_FLAGS], DNS_FLAG_RD);
    } else {
        CPS_SETUSHORT2(&outbuf[DNS_OFFSET_FLAGS], DNS_FLAG_RD | DNS_FLAG_CD);
    }
    CPS_SETUSHORT2(&outbuf[DNS_OFFSET_QUESTION_COUNT], 1);
    CPS_SETUSHORT2(&outbuf[DNS_OFFSET_ANSWER_COUNT], 0);
    CPS_SETUSHORT2(&outbuf[DNS_OFFSET_AUTHORITY_RR_COUNT], 0);
    CPS_SETUSHORT2(&outbuf[DNS_OFFSET_ADDITIONAL_RR_COUNT], 0);

    u8 *d0 = outbuf + DNS_HEADER_SIZE;
    u8 *d = d0 + 1;
    u32 len = 0;

    while ((c = *name++) != '\0') {
        if (c != '.') {
            if ((int)(d - outbuf) >= (int)sizeof(outbuf)) {
                return RESOLVE_RESULT_FATAL_ERROR;
            }
            *d++ = c;
            len++;
        } else {
            *d0 = len;
            d0 = d;
            d++;
            len = 0;
        }
    }
    *d0 = len;
    *d++ = '\0';
    CPS_SETUSHORT1(&d[DNS_QUESTION_OFFSET_TYPE], type);
    CPS_SETUSHORT1(&d[DNS_QUESTION_OFFSET_CLASS], DNS_CLASS_INTERNET);

    CPS_SocWrite(outbuf, d + DNS_QUESTION_FIXED_SIZE - outbuf);
    CPSInAddr ip = 0;

    u32 start = CPSi_GetTick();
    while (link_is_on() && ip == 0 && (int)(CPSi_GetTick() - start) < CPS_MilliSecondsToLTicks(2000)) {
        if (CPS_SocGetLength() == 0) {
            yield_thread();
        } else {
            u8 *buf = CPS_SocRead(&len);
            if (len > DNS_HEADER_SIZE) {
                if (id == CPS_GETUSHORT2(&buf[DNS_OFFSET_TRANSACTION_ID])) {
                    if ((buf[DNS_OFFSET_FLAGS + 1] & DNS_RCODE_MASK) == DNS_RCODE_NXDOMAIN) {
                        ip = RESOLVE_RESULT_FATAL_ERROR;
                    } else if ((buf[DNS_OFFSET_FLAGS + 1] & DNS_RCODE_MASK) == DNS_RCODE_NOERROR) {
                        d = buf + len;
                        u32 cnt = CPS_GETUSHORT1(&buf[DNS_OFFSET_QUESTION_COUNT]);
                        buf += DNS_HEADER_SIZE;

                        while (cnt-- != 0) {
                            buf = dns_skipname(buf) + DNS_QUESTION_FIXED_SIZE;
                        }

                        while (buf < d) {
                            buf = dns_skipname(buf);
                            cnt = CPS_GETUSHORT1(&buf[DNS_RR_OFFSET_RLENGTH]);
                            if (type == CPS_GETUSHORT1(&buf[DNS_RR_OFFSET_TYPE])) {
                                if (type != DNS_TYPE_PTR) {
                                    // cnt should be 4 here, making this equivalent to &buf[DNS_RR_OFFSET_RDATA]
                                    ip = CPS_GETULONG1(buf + 6 + cnt);
                                } else if (cnt <= rname_max) {
                                    MI_CpuCopy8(&buf[DNS_RR_OFFSET_RDATA], rname, cnt);
                                    ip = RESOLVE_RESULT_SUCCESS;
                                } else {
                                    ip = RESOLVE_RESULT_NAME_TOO_LONG;
                                }
                                break;
                            } else {
                                buf += cnt + DNS_RR_FIXED_SIZE;
                            }
                        }
                    }
                }
            }
            CPS_SocConsume(len);
        }
    }

    return ip;
}

static u32 strtol10(u8 *s, u8 **endptr)
{
    *endptr = s;
    u32 acc = 0;

    while (TRUE) {
        u8 c = *s - '0';
        if (c > 9) {
            break;
        }
        acc = (10 * acc) + c;
        s++;
        *endptr = s;
    }

    return acc;
}

static BOOL rawip(u8 *name, CPSInAddr *pip)
{
    u8 *next;
    CPSInAddr ip = 0;

    for (int i = 0; i < 4; i++) {
        ip <<= 8;
        u32 field = strtol10(name, &next);

        if (name == next) {
            return FALSE;
        }

        name = next;

        if (field > 255 || (i != 3 && *name++ != '.') || (i == 3 && *name != '\0')) {
            return FALSE;
        }

        ip |= field;
    }

    *pip = ip;
    return TRUE;
}

static CPSInAddr resolve_sub(u8 *name, u32 dnsip, u16 id)
{
    if (dnsip == 0) {
        return RESOLVE_RESULT_FATAL_ERROR;
    }

    CPS_SocUse();
    CPS_SocDatagramMode();
    CPS_SocBind(0, PORT_DNS, dnsip);
    CPSInAddr ip = resolve_common(name, DNS_TYPE_A, id, NULL, 0);
    CPS_SocRelease();
    return ip;
}

CPSInAddr CPS_Resolve(const char *name)
{
    CPSInAddr ip;
    u16 id[2];
    u8 ask_this[2];

    id[0] = MATH_Rand32(&CPSiRand32ctx, 65536);
    id[1] = MATH_Rand32(&CPSiRand32ctx, 65536);

    if (rawip(name, &ip)) {
        return ip;
    }

    ask_this[0] = TRUE;
    ask_this[1] = TRUE;

    for (int retries = 0; retries < 3; retries++) {
        for (int server = 0; server < 2; server++) {
            if (ask_this[server]) {
                ip = resolve_sub(name, CPSDnsIp[server], id[server]);
                if (ip != 0 && ip != RESOLVE_RESULT_FATAL_ERROR) {
                    goto exit;
                }
                if (ip == RESOLVE_RESULT_FATAL_ERROR) {
                    ask_this[server] = FALSE;
                }
            }
        }
    }
exit:
    if (ip == RESOLVE_RESULT_FATAL_ERROR) {
        ip = 0;
    }
    return ip;
}

static CPSInAddr rev_resolve_sub(u8 *name, u32 dnsip, u16 id, u8 *rname, u32 rname_max)
{
    if (dnsip == 0) {
        return RESOLVE_RESULT_FATAL_ERROR;
    }

    CPS_SocUse();
    CPS_SocDatagramMode();
    CPS_SocBind(0, PORT_DNS, dnsip);
    CPSInAddr ip = resolve_common(name, DNS_TYPE_PTR, id, rname, rname_max);
    CPS_SocRelease();
    return ip;
}

static u8 *byte2a(u8 *d, u32 val)
{
    BOOL flag = FALSE;
    int div = 100;
    while (div != 1) {
        if (flag || val >= div) {
            *d++ = val / div + '0';
            val %= div;
            flag = TRUE;
        }
        div /= 10;
    }

    *d++ = val + '0';
    *d++ = '.';
    *d = 0;
    return d;
}

int CPS_RevResolve(CPSInAddr ip, char *name, u32 name_max)
{
    u16 id[2];
    u8 ask_this[2];
    u8 tmp[29];
    int i, j;

    id[0] = MATH_Rand32(&CPSiRand32ctx, 65536);
    id[1] = MATH_Rand32(&CPSiRand32ctx, 65536);

    ask_this[0] = TRUE;
    ask_this[1] = TRUE;

    u8 *d = tmp;

    d = byte2a(d, (u8)ip);
    d = byte2a(d, (u8)(ip >> 8));
    d = byte2a(d, (u8)(ip >> 16));
    d = byte2a(d, (u8)(ip >> 24));

    strcpy(d, "in-addr.arpa");

    for (int retries = 0; retries < 3; retries++) {
        for (int server = 0; server < 2; server++) {
            if (ask_this[server]) {
                ip = rev_resolve_sub(tmp, CPSDnsIp[server], id[server], name, name_max);
                if (ip != 0 && ip != RESOLVE_RESULT_FATAL_ERROR) {
                    goto exit;
                }

                if (ip == RESOLVE_RESULT_FATAL_ERROR) {
                    ask_this[server] = FALSE;
                }
            }
        }
    }
exit:
    if (ip == 0 || ip == RESOLVE_RESULT_FATAL_ERROR) {
        *name = '\0';
        return 1;
    }

    if (ip == RESOLVE_RESULT_NAME_TOO_LONG) {
        *name = '\0';
        return -1;
    }

    i = j = 0;
    while (j < name_max) {
        u32 cnt = name[i++];
        if ((cnt & DNS_COMPRESSION_POINTER_MASK) == DNS_COMPRESSION_POINTER_MASK) {
            *name = '\0';
            return 1;
        }

        if (cnt != 0) {
            memmove(&name[j], &name[i], cnt);
            j += cnt;
            i += cnt;
            name[j++] = '.';
        } else {
            if (j != 0) {
                j--;
            }
            name[j] = '\0';
            return 0;
        }
    }

    return -1;
}

void CPS_EncodeNbName(u8 *d, u8 *s)
{
    for (int i = 0; i < 15; i++) {
        u8 c;
        if (*s == '\0') {
            c = ' ';
        } else {
            c = *s++;
        }

        if ('a' <= c && c <= 'z') {
            c &= ~0x20;
        }

        *d++ = (c >> 4) + 'A';
        *d++ = (c & 0xF) + 'A';
    }

    *d++ = 'A';
    *d++ = 'A';
    *d = '\0';
}

CPSInAddr CPS_NbResolve(const char *name)
{
    u8 nbname[33];
    CPSInAddr ip;

    if (rawip(name, &ip)) {
        return ip;
    }

    CPS_EncodeNbName(nbname, name);
    CPS_SocUse();
    CPS_SocDatagramMode();
    CPS_SocBind(PORT_NB_NAME_SERVICE, PORT_NB_NAME_SERVICE, CPS_MK_IPv4(255, 255, 255, 255));
    ip = resolve_common(nbname, DNS_TYPE_NB, MATH_Rand32(&CPSiRand32ctx, 65536), NULL, 0);
    CPS_SocRelease();

    if (ip == RESOLVE_RESULT_FATAL_ERROR) {
        ip = 0;
    }

    return ip;
}

static void strlwr(u8 *s)
{
    u8 c;
    while ((c = *s) != '\0') {
        if ((u32)(c - 'A') <= 25) {
            *s = c ^ 0x20;
        }
        s++;
    }
}

static void tostring(u8 *d, u32 v, u32 radix)
{
    u32 digit;
    u8 *p = d;

    do {
        digit = v % radix;
        if (digit < 10) {
            *p++ = digit + '0';
        } else {
            *p++ = digit - 10 + 'A';
        }
        v /= radix;
    } while (v != 0);

    *p-- = '\0';
    if (p > d) {
        for (; d < p; d++, p--) {
            digit = *d;
            *d = *p;
            *p = digit;
        }
    }
}

typedef struct FORMAT {
    u8 type;
    u8 leftjustify;
    u8 sign;
    u8 padding;
    u32 width;
} FORMAT;

static void justify_string(u8 *d, u8 *s, FORMAT *f, u8 padding, u8 preceding)
{
    u32 len = strlen(s);
    int padcnt = f->width - len - (preceding != 0 ? 1 : 0);

    if (f->leftjustify) {
        if (preceding != '\0') {
            *d++ = preceding;
        }
        strcpy(d, s);
        d += len;
        while (padcnt-- > 0) {
            *d++ = ' ';
        }
        *d = '\0';
        return;
    }

    if (preceding != '\0' && padding == ' ') {
        while (padcnt-- > 0) {
            *d++ = ' ';
        }
        *d = preceding;
        strcpy(d + 1, s);
        return;
    }

    if (preceding != 0) {
        *d++ = preceding;
    }

    while (padcnt-- > 0) {
        *d++ = padding;
    }

    strcpy(d, s);
}

static void return_integer(u8 *buf, FORMAT *f, va_list *argpp, BOOL issigned, u32 radix)
{
    u8 tmp[12];

    s32 val = va_arg(*argpp, s32);
    u8 preceding = '\0';

    if (issigned != 0) {
        if (val < 0) {
            val = -val;
            preceding = '-';
        } else if (f->sign != '\0') {
            preceding = f->sign;
        }
    }

    tostring(tmp, val, radix);
    justify_string(buf, tmp, f, f->padding, preceding);
}

static void handle_arg(u8 *buf, FORMAT *f, va_list *argpp)
{
    switch (f->type) {
    case 'd':
        return_integer(buf, f, argpp, TRUE, 10);
        return;
    case 'u':
        return_integer(buf, f, argpp, FALSE, 10);
        return;
    case 'x':
        return_integer(buf, f, argpp, FALSE, 16);
        strlwr(buf);
        return;
    case 'X':
        return_integer(buf, f, argpp, FALSE, 16);
        return;
    case 'c':
        buf[0] = va_arg(*argpp, s32);
        buf[1] = '\0';
        return;
    }
}

static u8 *analyze_format(u8 *format, FORMAT *f)
{
    u8 *next;

    f->leftjustify = FALSE;
    f->sign = '\0';
    f->width = 0;

    if (*format == '-') {
        f->leftjustify = TRUE;
        format++;
    } else if (*format == '+') {
        f->sign = '+';
        format++;
    } else if (*format == ' ') {
        f->sign = ' ';
        format++;
    }

    if (*format == '0') {
        f->padding = '0';
    } else {
        f->padding = ' ';
    }

    f->width = strtol10(format, &next);
    if (f->width > 31) {
        f->width = 31;
    }

    format = next;
    if (*format == 'l' || *format == 'L') {
        format++;
    }
    f->type = *format++;
    return format;
}

void CPS_SocPrintf(const char *format_str, ...)
{
    va_list argp;
    FORMAT form;
    u8 tmp[32];
    u8 *s;
    u8 *d;
    u8 c;

    va_start(argp, format_str);

    s = format_str;
    while ((c = *s++) != 0) {
        if (c == '%') {
            if (*s == '%') {
                CPS_SocPutChar('%');
                s++;
            } else {
                s = analyze_format(s, &form);
                if (form.type == 's') {
                    d = va_arg(argp, char *);
                    if (d == NULL) {
                        d = "(null)";
                    }
                } else {
                    handle_arg(tmp, &form, &argp);
                    d = tmp;
                }

                CPS_SocPuts(d);
            }
        } else {
            CPS_SocPutChar(c);
        }
    }

    va_end(argp);
}
