#ifndef NITROWIFI_CPS_H_
#define NITROWIFI_CPS_H_

#include <nitro.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CPSSoc CPSSoc;

typedef u32 CPSInAddr;
typedef u8 CPSMacAddress[6];

typedef void (*CPSScavengerCallback)(void);
typedef void (*CPSDHCPCallback)(void);
typedef BOOL (*CPSUDPReadCallback)(u8 *data, u32 len, CPSSoc *soc);
typedef BOOL (*CPSLinkIsOnFunc)(void);
typedef void *(*CPSAllocFunc)(u32 size);
typedef void (*CPSFreeFunc)(void *ptr);

typedef struct CPSSocBuf {
    u32 size;
    u8 *data;
} CPSSocBuf;

typedef struct CPSSoc {
    OSThread *thread;
    u32 block_type;
    u8 state;
    u8 ssl;
    u16 local_port;
    void *con;
    u32 when;
    u32 local_ip_real;
    u16 remote_port;
    u16 remote_port_bound;
    CPSInAddr remote_ip;
    CPSInAddr remote_ip_bound;
    u32 ackno;
    u32 seqno;
    u16 remote_win;
    u16 remote_mss;
    u32 remote_ackno;
    u32 ackrcvd;
    CPSUDPReadCallback udpread_callback;
    CPSSocBuf rcvbuf;
    u32 rcvbufp;
    CPSSocBuf sndbuf;
    CPSSocBuf linbuf;
    CPSSocBuf outbuf;
    u32 outbufp;
} CPSSoc;

enum {
    CPS_STT_CLOSED = 0,
    CPS_STT_LISTEN,
    CPS_STT_SYN_SENT,
    CPS_STT_SYN_RCVD,
    CPS_STT_ESTABLISHED,
    CPS_STT_CLOSE_WAIT,
    CPS_STT_LAST_ACK,
    CPS_STT_FIN_WAIT1,
    CPS_STT_FIN_WAIT2,
    CPS_STT_CLOSING,
    CPS_STT_DATAGRAM,
    CPS_STT_PING
};

enum {
    CPS_BLOCK_NONE = 0,
    CPS_BLOCK_TCPCON,
    CPS_BLOCK_TCPREAD,
    CPS_BLOCK_UDPREAD
};

enum {
    CPS_NOIP_REASON_NONE = 0,
    CPS_NOIP_REASON_LINKOFF,
    CPS_NOIP_REASON_DHCPDISCOVERY,
    CPS_NOIP_REASON_LEASETIMEOUT,
    CPS_NOIP_REASON_COLLISION
};

typedef struct CPSArpCache {
    CPSInAddr ip;
    CPSMacAddress mac;
    u16 when;
} CPSArpCache;

#define CPS_MAX_IPSIZE 4096
#define CPS_MIN_MTU    576
#define CPS_MAX_MTU    1500
#define CPS_MAX_IPFRAG (CPS_MAX_IPSIZE / CPS_MIN_MTU + 1)

typedef struct CPSFragTable {
    CPSInAddr ipfrom;
    u16 frags;
    u16 id;
    u16 last;
    u16 size;
    u16 from[CPS_MAX_IPFRAG];
    u16 to[CPS_MAX_IPFRAG];
    u32 when;
    u8 *ofs0;
    u8 *buf;
} CPSFragTable;

typedef struct CPSConfig {
    u32 mode;
    CPSAllocFunc alloc;
    CPSFreeFunc free;
    CPSDHCPCallback dhcp_callback;
    CPSLinkIsOnFunc link_is_on;
    u64 random_seed;
    u8 *lan_buf;
    u32 lan_buflen;
    u32 mymss;
    CPSInAddr requested_ip;
    u32 yield_wait;
} CPSConfig;

#define CPS_DONOTUSE_DHCP 0x0001

#if defined(BIG_ENDIAN)
    #define CPS_htons(data) (data)
    #define CPS_htonl(data) (data)
#else
    static inline u16 CPS_htons (u16 data)
    {
        return (u16)((data >> 8) | (data << 8));
    }

    static inline u32 CPS_htonl (u32 data)
    {
        u32 tmp;

        tmp = ((data >> 8) & 0x00ff00ff) | ((data << 8) & 0xff00ff00);
        return (tmp >> 16) | (tmp << 16);
    }
#endif

#define CPS_USHORT2_HOST(p) (*(u16 *)(p))

#define CPS_GETUSHORT1(p) ((u16)(((u8 *)(p))[0] << 8 | ((u8 *)(p))[1]))
#define CPS_GETULONG1(p) (((u32)CPS_GETUSHORT1(p) << 16) | CPS_GETUSHORT1((p) + 2))

#define CPS_GETUSHORT2(p) (CPS_htons(CPS_USHORT2_HOST(p)))
#define CPS_GETULONG2(p) (((u32)CPS_GETUSHORT2(p) << 16) | CPS_GETUSHORT2((p) + 2))

#define CPS_SETUSHORT1(p, v) do {((u8 *)(p))[0] = (u8)((v) >> 8); ((u8 *)(p))[1] = (u8)(v);} while (0)
#define CPS_SETULONG1(p, v) do {CPS_SETUSHORT1(p, (u16)((v) >> 16)); CPS_SETUSHORT1((p) + 2, (u16)(v));} while (0)

#define CPS_SETUSHORT2(p, v) CPS_USHORT2_HOST(p) = CPS_htons((u16)(v))
#define CPS_SETULONG2(p, v) do {CPS_SETUSHORT2(p, (u32)(v) >> 16); CPS_SETUSHORT2((p) + 2, v);} while (0)

#define CPS_MilliSecondsToLTicks(msec) (((OS_SYSTEM_CLOCK / 64 / 1000) * (msec)) >> 16)

#ifndef SDK_THREAD_INFINITY
    #define CPS_CURSOC (CPSSocTab[OS_GetCurrentThread()->id])
    #define CPS_SET_CURSOC(p) CPS_CURSOC = p
#else
    #define CPS_CURSOC ((CPSSoc *)OSi_GetSpecificData(OS_GetCurrentThread(), OSi_SPECIFIC_CPS))
    #define CPS_SET_CURSOC(p) OSi_SetSpecificData(OS_GetCurrentThread(), OSi_SPECIFIC_CPS, (void *)(p))
#endif

static inline u32 CPSi_GetTick ()
{
    return (u32)(OS_GetTick() >> 16);
}

extern CPSAllocFunc CPSiAlloc;
extern CPSFreeFunc CPSiFree;

extern CPSInAddr CPSMyIp;
extern CPSInAddr CPSNetMask;
extern CPSInAddr CPSGatewayIp;
extern CPSInAddr CPSDnsIp[2];
extern CPSMacAddress CPSMyMac;
extern CPSInAddr CPSDhcpServerIp;

extern int CPSNoIpReason;
extern MATHRandContext32 CPSiRand32ctx;

#ifndef SDK_THREAD_INFINITY
    extern CPSSoc *CPSSocTab[];
#endif

extern void CPSi_SslListen(CPSSoc *soc);
extern u32 CPSi_SslConnect(CPSSoc *soc);
extern u8 *CPSi_SslRead(u32 *, CPSSoc *);
extern void CPSi_SslConsume(u32, CPSSoc *);
extern s32 CPSi_SslGetLength(CPSSoc *);
extern u32 CPSi_SslWrite2(u8 *, u32, u8 *, u32, CPSSoc *);
extern void CPSi_SslShutdown(CPSSoc *);
extern void CPSi_SslClose(CPSSoc *);
extern void CPSi_SslPeriodical(u32 now);
extern void CPSi_SslCleanup(void);

void CPSi_SocConsumeRaw(u32 len, CPSSoc *soc);
u32 CPSi_TcpWrite2Raw(u8 *buf, u32 len, u8 *buf2, u32 len2, CPSSoc *soc);
u32 CPSi_TcpConnectRaw(CPSSoc *soc);
void CPSi_TcpShutdownRaw(CPSSoc *soc);
void CPSi_TcpListenRaw(CPSSoc *soc);
u8 *CPSi_TcpReadRaw(u32 *len, CPSSoc *soc);

void CPS_Startup(CPSConfig *config);
void CPS_Cleanup(void);
u32 CPS_GetThreadPriority(void);
void CPS_SetThreadPriority(u32 new_prio);
void CPS_SocRegister(CPSSoc *soc);
void CPS_SocUnRegister(void);
void CPS_SocUse(void);
void CPS_SocRelease(void);
void CPS_SocDup(OSThread *thread);
void CPS_SetUdpCallback(CPSUDPReadCallback callback);
int CPS_CalmDown(void);
void CPS_SetScavengerCallback(CPSScavengerCallback f);

void CPS_SocBind(u16 local_port, u16 remote_port, CPSInAddr remote_ip);
void CPS_SocDatagramMode(void);
void CPS_SocPingMode(void);
u8 *CPS_SocRead(u32 *len);
void CPS_SocConsume(u32 len);
s32 CPS_SocGetLength(void);
u32 CPS_SocWrite(u8 *buf, u32 len);
u32 CPSi_SocWrite2(u8 *buf, u32 len, u8 *buf2, u32 len2);
u32 CPS_TcpConnect(void);
void CPS_TcpListen(void);
CPSInAddr CPS_SocWho(u16 *remote_port, CPSInAddr *local_ip);
void CPS_TcpShutdown(void);
void CPS_TcpClose(void);
void CPS_TcpAck(void);
u16 CPS_SocGetEport(void);

int CPS_SocGetChar(void);
u8 *CPS_SocGets(void);
void CPS_SocPutChar(char c);
void CPS_SocPuts(char *s);
void CPS_SocPrintf(const char *format_str, ...);
void CPS_SocFlush(void);
s32 CPS_GetProperSize(void);

extern void CPS_SetSsl(int);
extern u32 CPS_GetSslHandshakePriority(void);
extern void CPS_SetSslHandshakePriority(u32);

#define CPS_SetSslLowThreadPriority CPS_SetSslHandshakePriority
#define CPS_GetSslLowThreadPriority CPS_GetSslHandshakePriority

CPSInAddr CPS_Resolve(const char *name);
int CPS_RevResolve(CPSInAddr ip, char *name, u32 name_max);
CPSInAddr CPS_NbResolve(const char *name);
void CPS_EncodeNbName(u8 *d, u8 *s);

void CPSi_RecvCallbackFunc(const u8 *srcAddr, const u8 *dstAddr, const u8 *buf, s32 size);

#define CPS_MK_IPv4(a, b, c, d) (((u32)(a) << 24) + ((u32)(b) << 16) + ((u32)(c) << 8) + (u32)(d))
#define CPS_CV_IPv4(ip) (u8)((ip) >> 24), (u8)((ip) >> 16), (u8)((ip) >> 8), (u8)(ip)

#ifdef __cplusplus
}
#endif

#endif
