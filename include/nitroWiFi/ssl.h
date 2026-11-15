#ifndef NITROWIFI_SSL_H_
#define NITROWIFI_SSL_H_

#ifdef __cplusplus

extern "C" {
#endif

#include <nitro.h>

#include "cps.h"

typedef struct CPSMd5Ctx {
    u32 state[4];
    u32 count[2];
    u8 buffer[64];
} CPSMd5Ctx;

void CPSi_md5_init(CPSMd5Ctx *ctx);
void CPSi_md5_calc(CPSMd5Ctx *ctx, void *data0, u32 datalen);
void CPSi_md5_result(CPSMd5Ctx *ctx, u8 *digest);

#define MD5_HASH_SIZE 16

typedef struct CPSSha1Ctx {
    u32 state[5];
    u32 count[2];
    u8 buffer[64];
} CPSSha1Ctx;

void CPSi_sha1_init(CPSSha1Ctx *ctx);
void CPSi_sha1_calc(CPSSha1Ctx *ctx, void *data0, u32 datalen);
void CPSi_sha1_result(CPSSha1Ctx *ctx, u8 *digest);
void CPSi_sha1_result_prng(CPSSha1Ctx *ctx, u8 *digest);

#define SHA1_HASH_SIZE 20

typedef struct CPSRc4Ctx {
    u8 x;
    u8 y;
    u8 m[256];
    u16 padding;
} CPSRc4Ctx;

void CPSi_rc4_init(CPSRc4Ctx *ctx, u8 *key, int len);
void CPSi_rc4_crypt(CPSRc4Ctx *ctx, u8 *data, int len);

#define RC4_KEY_LENGTH 16

void CPSi_big_add(u16 *c, u16 *a, u16 *b, int digits);
void CPSi_big_sub(u16 *c, u16 *a, u16 *b, int digits);
void CPSi_big_mult(u16 *c, u16 *a, u16 *b, int digits);
void CPSi_big_div(u16 *c, u16 *a, u16 *b, u16 *r, int digits, u16 *work);
void CPSi_big_power(u16 *c, u16 *a, u16 *b, int digits, u16 *n);
void CPSi_big_montpower(u16 *c, u16 *m, u16 *e, int digits, u16 *n);
void CPSi_big_negate(u16 *a, int digits);
int CPSi_big_sign(u16 *a, int digits);
void CPSi_big_from_char(u16 *d, u8 *s, int numbytes, int digits);
void CPSi_char_from_big(u8 *d, u16 *s, int numbytes, int digits);

typedef struct CPSCaInfo {
    char *dn;
    int modulus_len;
    u8 *modulus;
    int exponent_len;
    u8 *exponent;
} CPSCaInfo;

typedef struct CPSCertificate {
    int certificate_len;
    u8 *certificate;
} CPSCertificate;

typedef struct CPSPrivateKey {
    int modulus_len;
    u8 *modulus;
    int prime1_len;
    u8 *prime1;
    int prime2_len;
    u8 *prime2;
    int exponent1_len;
    u8 *exponent1;
    int exponent2_len;
    u8 *exponent2;
    int coefficient_len;
    u8 *coefficient;
} CPSPrivateKey;

void CPS_SetRootCa(CPSCaInfo **ca, int ca_num);
void CPS_SetMyCert(CPSCertificate *c, CPSPrivateKey *k);

#define CPS_CERT_OUTOFDATE 0x8000
#define CPS_CERT_BADSERVER 0x4000
#define CPS_CERT_ERRMASK   0x00FF

enum {
    CPS_CERT_NOERROR = 0,
    CPS_CERT_NOROOTCA,
    CPS_CERT_BADSIGNATURE,
    CPS_CERT_UNKNOWN_SIGALGORITHM,
    CPS_CERT_UNKNOWN_PUBKEYALGORITHM
};

#define SESSION_ID_LEN    32
#define MASTER_SECRET_LEN 48

typedef struct CPSSslSession {
    u8 sessionID[SESSION_ID_LEN];
    u8 master_secret[MASTER_SECRET_LEN];
    u32 when;
    CPSInAddr ip;
    u16 port;
    u8 valid;
    u8 padding;
} CPSSslSession;

#define CPS_MAX_DN_LEN                 255
#define CPS_MAX_CN_LEN                 79
#define CPS_MIN_RSA_LEN                (408 / 8)
#define CPS_MAX_RSA_LEN                (2048 / 8)
#define CPS_MAX_RSA_PUBLICEXPONENT_LEN (64 / 8)
#define CPS_RANDOM_LEN                 32

typedef struct CPSSslConnection {
    u8 master_secret[MASTER_SECRET_LEN];
    u8 session_cached;
    u8 reuse_session;
    u16 method;
    u8 client_random[CPS_RANDOM_LEN];
    u8 server_random[CPS_RANDOM_LEN];
    union {
        u8 sessionID[SESSION_ID_LEN];
        u8 key_block[2 * (SHA1_HASH_SIZE + RC4_KEY_LENGTH + 0)];
    } common1;
    u8 *send_mac;
    u8 *send_key;
    u8 *send_iv;
    CPSRc4Ctx send_cipher;
    u8 send_seq[8];
    u8 *rcv_mac;
    u8 *rcv_key;
    u8 *rcv_iv;
    CPSRc4Ctx rcv_cipher;
    u8 rcv_seq[8];
    CPSSha1Ctx sha1_hash;
    CPSSha1Ctx sha1_hash_tmp;
    CPSMd5Ctx md5_hash;
    CPSMd5Ctx md5_hash_tmp;
    u8 server;
    u8 state;
    u8 inbuf_decrypted;
    u8 padding2;
    int sig_algorithm;
    int pub_algorithm;
    u8 *hash_start;
    u8 *hash_end;
    u8 hash_val[20];
    int hash_len;
    CPSCaInfo midca_info;
    u8 modulus[CPS_MAX_RSA_LEN];
    u32 modulus_len;
    u8 exponent[CPS_MAX_RSA_PUBLICEXPONENT_LEN];
    int exponent_len;
    u8 *signature;
    int signature_len;
    u8 seen_validity;
    u8 seen_pub_algorithm;
    u8 seen_attr;
    u8 date_ok;
    char issuer[CPS_MAX_DN_LEN + 1];
    char subject[CPS_MAX_DN_LEN + 1];
    char cn[CPS_MAX_CN_LEN + 1];
    char *server_name;
    u8 *cert;
    int certlen;
    u32 cur_date;
    int (*auth_callback)(int result, CPSSslConnection *con, int level);
    CPSCaInfo **ca_info;
    int ca_builtins;
    CPSPrivateKey *my_key;
    CPSCertificate *my_certificate;
    u8 *inbuf;
    long inbuf_len;
    long inbuf_pnt;
} CPSSslConnection;

void CPS_SslAddRandomSeed(void *random_seed, u32 len);

void CPSi_SslListen(CPSSoc *soc);
u32 CPSi_SslConnect(CPSSoc *soc);
u8 *CPSi_SslRead(u32 *len, CPSSoc *soc);
void CPSi_SslConsume(u32 len, CPSSoc *soc);
s32 CPSi_SslGetLength(CPSSoc *soc);
u32 CPSi_SslWrite2(u8 *buf, u32 len, u8 *buf2, u32 len2, CPSSoc *soc);
void CPSi_SslShutdown(CPSSoc *soc);
void CPSi_SslClose(CPSSoc *soc);
void CPSi_SslPeriodical(u32 now);
void CPSi_SslCleanup(void);

void CPS_SetSsl(BOOL mode);
u32 CPS_GetSslHandshakePriority(void);
void CPS_SetSslHandshakePriority(u32 new_prio);

#ifdef __cplusplus
}
#endif

#endif
