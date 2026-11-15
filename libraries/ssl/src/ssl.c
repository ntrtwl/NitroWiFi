#include "nitroWiFi/ssl.h"

#include <nitro.h>
#include <string.h>

#include "nitroWiFi/cps.h"

#include <nitro/version_begin.h>
static char id_string[] = SDK_MIDDLEWARE_STRING("UBIQUITOUS", "SSL");
#include <nitro/version_end.h>

#define SSL_RSA_WITH_RC4_128_MD5 4
#define SSL_RSA_WITH_RC4_128_SHA 5

#define MAX_SESSION 4

#define MAX_BLOAT 25

#define ssl_blklen (2 * MTUtoMSS(CPS_MAX_MTU) - MAX_BLOAT)

#define SSL_MAX_RECORD_SIZE 16384

#define SSL_MAX_PADDING 2048

enum SSLState {
    SSL_STATE_INIT = 0,
    SSL_STATE_CLIENT_HELLO_RECEIVED,
    SSL_STATE_SERVER_HELLO_RECEIVED,
    SSL_STATE_CERTIFICATE_RECEIVED,
    SSL_STATE_SERVER_HELLO_DONE_RECEIVED,
    SSL_STATE_CLIENT_KEY_EXCHANGE_RECEIVED,
    SSL_STATE_FINISHED_RECEIVED,
    SSL_STATE_CHANGE_CIPHER_SPEC_RECEIVED,
    SSL_STATE_ESTABLISHED,
    SSL_STATE_ERROR,
};

enum DERType {
    DER_TYPE_INTEGER = 2,
    DER_TYPE_BIT_STRING,
    DER_TYPE_OID = 6,
    DER_TYPE_UTF8_STRING = 12,
    DER_TYPE_SEQUENCE = 16,
    DER_TYPE_SET,
    DER_TYPE_PRINTABLE_STRING = 19,
    DER_TYPE_T61_STRING,
    DER_TYPE_IA5_STRING = 22,
    DER_TYPE_UTC_TIME,
    DER_TYPE_GENERALIZED_TIME,
};

#define DER_TYPE_MASK 0x1F

#define DER_FLAG_CONSTRUCTED      (1 << 5)
#define DER_FLAG_CONTEXT_SPECIFIC (1 << 7)

#define EMSA_PKCS1_HEADER_0 0
#define EMSA_PKCS1_HEADER_1 1

enum SSLHeaderOffset {
    SSL_OFFSET_CONTENT_TYPE = 0,
    SSL_OFFSET_VERSION_MAJOR,
    SSL_OFFSET_VERSION_MINOR,
    SSL_OFFSET_RECORD_LENGTH,
};

enum SSLV2HeaderOffset {
    SSL_V2_OFFSET_LENGTH = 1,
    SSL_V2_OFFSET_MSG_TYPE
};

enum SSLV2HelloOffset {
    SSL_V2_HELLO_OFFSET_VERSION_MAJOR = 0,
    SSL_V2_HELLO_OFFSET_VERSION_MINOR,
    SSL_V2_HELLO_OFFSET_CIPHER_SPECS_LENGTH,
    SSL_V2_HELLO_OFFSET_SESSION_ID_LENGTH = 4,
    SSL_V2_HELLO_OFFSET_RANDOM_LENGTH = 6,
    SSL_V2_HELLO_OFFSET_CIPHER_SPECS = 8,
};

enum SSLHelloOffset {
    SSL_HELLO_OFFSET_VERSION_MAJOR = 0,
    SSL_HELLO_OFFSET_VERSION_MINOR,
    SSL_HELLO_OFFSET_RANDOM
};

#define SSL_HEADER_SIZE 5

#define SSL_GET_USHORT(p) (((p)[0] << 8) + (p)[1])

enum SSLContentType {
    SSL_CHANGE_CIPHER_SPEC = 20,
    SSL_ALERT,
    SSL_HANDSHAKE,
    SSL_APPLICATION_DATA,
    SSL_V2_RECORD = 0x80
};

#define SSL_V2_CLIENT_HELLO 1

enum SSLAlertLevel {
    SSL_ALERT_LEVEL_WARNING = 1,
    SSL_ALERT_LEVEL_FATAL,
};

enum SSLAlertType {
    SSL_ALERT_CLOSE_MESSAGE = 0,
    SSL_ALERT_NO_CERTIFICATE = 41,
};

enum SSLHandshakeType {
    SSL_HANDSHAKE_CLIENT_HELLO = 1,
    SSL_HANDSHAKE_SERVER_HELLO,
    SSL_HANDSHAKE_CERTIFICATE = 11,
    SSL_HANDSHAKE_CERTIFICATE_REQUEST = 13,
    SSL_HANDSHAKE_SERVER_HELLO_DONE,
    SSL_HANDSHAKE_CLIENT_KEY_EXCHANGE = 16,
    SSL_HANDSHAKE_FINISHED = 20,
};

enum CertificateParseMode {
    CERT_PARSE_MODE_INITIAL,
    CERT_PARSE_MODE_NORMAL,
    CERT_PARSE_MODE_INTERMEDIATE,
};

static CPSSslSession session[MAX_SESSION];
static u32 ssl_handshake_priority = -1;

static u16 pairlist[] = {
    SSL_RSA_WITH_RC4_128_MD5,
    SSL_RSA_WITH_RC4_128_SHA,
};

#define PAIRLIST_LEN (sizeof(pairlist) / sizeof(pairlist[0]))

enum OIDIndex {
    OID_NONE,
    OID_RSA_ENCRYPTION,
    OID_RSA,
    OID_MD5_WITH_RSA,
    OID_SHA1_WITH_RSA,
    OID_COMMON_NAME,
    OID_COUNT,
};

static u8 *object[6] = {
    [OID_NONE] = "\xFF\xFF\xFF",
    [OID_RSA_ENCRYPTION] = "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01",
    [OID_RSA] = "\x55\x08\x01\x01",
    [OID_MD5_WITH_RSA] = "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x04",
    [OID_SHA1_WITH_RSA] = "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05",
    [OID_COMMON_NAME] = "\x55\x04\x03"
};

// dumb hack to force the compiler to order the data correctly
extern const u8 *unused = "1234";

static u8 pool[SHA1_HASH_SIZE];
static u8 pool_initialized = FALSE;

static const u8 alert_nocert[7] = { SSL_ALERT, 3, 0, 0, 2, SSL_ALERT_LEVEL_WARNING, SSL_ALERT_NO_CERTIFICATE };

static void find_session_from_id(CPSSslConnection *con)
{
    int i;

    OSIntrMode enabled = OS_DisableInterrupts();
    con->session_cached = FALSE;
    for (i = 0; i < MAX_SESSION; i++) {
        CPSSslSession *p = &session[i];
        if (p->valid && p->ip == 0 && p->port == 0 && memcmp(p->sessionID, con->common1.sessionID, SESSION_ID_LEN) == 0) {
            MI_CpuCopy8(p->master_secret, con->master_secret, MASTER_SECRET_LEN);
            con->session_cached = TRUE;
            break;
        }
    }
    OS_RestoreInterrupts(enabled);
}

static void find_session_from_IP(CPSSslConnection *con, CPSInAddr ip, u16 port)
{
    OSIntrMode enabled = OS_DisableInterrupts();
    con->session_cached = FALSE;
    for (int i = 0; i < MAX_SESSION; i++) {
        CPSSslSession *p = &session[i];
        if (p->valid && p->ip == ip && p->port == port) {
            MI_CpuCopy8(p->sessionID, con->common1.sessionID, SESSION_ID_LEN);
            MI_CpuCopy8(p->master_secret, con->master_secret, MASTER_SECRET_LEN);
            p->when = CPSi_GetTick();
            con->session_cached = TRUE;
            break;
        }
    }
    OS_RestoreInterrupts(enabled);
}

static void cache_session(CPSSslConnection *con, CPSInAddr ip, u16 port)
{
    int i;
    CPSSslSession *candidate;
    u32 biggest;

    u32 enabled = OS_DisableInterrupts();
    u32 now = CPSi_GetTick();

    biggest = 0;
    candidate = &session[0];

    for (i = 0; i < MAX_SESSION; i++) {
        CPSSslSession *p = &session[i];
        if (p->valid && ip != 0 && ip == p->ip && port != 0 && port == p->port) {
            candidate = p;
            break;
        }

        if (biggest != -1) {
            if (!p->valid) {
                biggest = -1;
                candidate = p;
            } else {
                if (now - p->when > biggest) {
                    biggest = now - p->when;
                    candidate = p;
                }
            }
        }
    }

    MI_CpuCopy8(con->common1.sessionID, candidate->sessionID, SESSION_ID_LEN);
    MI_CpuCopy8(con->master_secret, candidate->master_secret, MASTER_SECRET_LEN);
    candidate->when = now;
    candidate->valid = TRUE;
    candidate->ip = ip;
    candidate->port = port;
    OS_RestoreInterrupts(enabled);
}

static void purge_session(CPSSslConnection *con)
{
    int i;

    OSIntrMode enabled = OS_DisableInterrupts();
    for (i = 0; i < MAX_SESSION; i++) {
        CPSSslSession *p = &session[i];
        if (p->valid && memcmp(p->sessionID, con->common1.sessionID, SESSION_ID_LEN) == 0) {
            p->valid = FALSE;
            break;
        }
    }
    OS_RestoreInterrupts(enabled);
}

#define MIDNIGHT_JAN_1_2000_EPOCH 946684800

static u32 date2sec(void)
{
    RTCDate date;
    RTCTime time;
    RTC_GetDate(&date);
    RTC_GetTime(&time);

    u32 sec = RTC_ConvertDateTimeToSecond(&date, &time);
    return sec + MIDNIGHT_JAN_1_2000_EPOCH;
}

u32 CPS_GetSslHandshakePriority(void)
{
    return ssl_handshake_priority;
}

void CPS_SetSslHandshakePriority(u32 new_prio)
{
    ssl_handshake_priority = new_prio;
}

static u32 enter_computebound(void)
{
    if (ssl_handshake_priority >= OS_THREAD_PRIORITY_MAX + 1) {
        return -1;
    }

    OSThread *cur_thread = OS_GetCurrentThread();
    u32 old_priority = OS_GetThreadPriority(cur_thread);
    OS_SetThreadPriority(cur_thread, ssl_handshake_priority);
    return old_priority;
}

static void exit_computebound(u32 old_priority)
{
    if (old_priority >= OS_THREAD_PRIORITY_MAX + 1) {
        return;
    }

    OS_SetThreadPriority(OS_GetCurrentThread(), old_priority);
}

void CPS_SetMyCert(CPSCertificate *c, CPSPrivateKey *k)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc != NULL) {
        CPSSslConnection *con = soc->con;
        if (con != NULL) {
            con->my_key = k;
            con->my_certificate = c;
        }
    }
}

void CPS_SetRootCa(CPSCaInfo **ca, int ca_num)
{
    CPSSoc *soc = CPS_CURSOC;
    if (soc != NULL) {
        CPSSslConnection *con = soc->con;
        if (con != NULL) {
            con->ca_info = ca;
            con->ca_builtins = ca_num;
        }
    }
}

static CPSCaInfo *get_rootCA(CPSSslConnection *con, char *dn)
{
    for (int i = 0; i < con->ca_builtins; i++) {
        if (strcmp(con->ca_info[i]->dn, dn) == 0) {
            return con->ca_info[i];
        }
    }
    return NULL;
}

static int cert_item_len(u8 **ps)
{
    u8 *s = *ps;
    int len = *s++;
    if ((len & 0x80) != 0) {
        int lenlen = len & 0x7F;
        len = 0;
        while (lenlen-- != 0) {
            if (len & 0xFF000000) {
                return -1;
            }
            len = (len << 8) + *s++;
        }
    }

    *ps = s;
    return len;
}

static void make_dn(char *d, char *s, int len)
{
    char *d0 = d;
    if (*d != '\0') {
        do {
            d++;
        } while (*d != '\0');

        if (d - d0 >= CPS_MAX_DN_LEN) {
            return;
        }

        *d++ = ',';
        *d++ = ' ';
    }

    while (len-- && (d - d0 < CPS_MAX_DN_LEN)) {
        *d++ = *s++;
    }

    *d = '\0';
}

static inline u32 parse2digits(u8 *s)
{
    return s[0] * 10 + s[1] - '0' * 10 - '0';
}

static u32 parse_time(u8 *s, int type)
{
    u32 year = parse2digits(s);
    s += 2;
    if (type == DER_TYPE_UTC_TIME) {
        // bug: y2k
        if (year < 50) {
            year += 2000;
        } else {
            year += 1900;
        }
    } else {
        year = year * 100 + parse2digits(s);
        s += 2;
    }

    return (year << 16) + (parse2digits(s) << 8) + parse2digits(s + 2);
}

static BOOL cert_item(CPSSslConnection *con, u8 **ps, int level, int seq, int mode)
{
    u8 *s = *ps;
    u8 type = *s++;
    int len = cert_item_len(&s);
    if (len < 0 || 2000 < len) {
        return TRUE;
    }
    u8 *end;
    int i;

    switch (type & DER_TYPE_MASK) {
    case DER_TYPE_INTEGER:
        if (con->seen_pub_algorithm != 0) {
            if (seq == 0) {
                while (*s == 0) {
                    s++;
                    len--;
                }

                switch (mode) {
                case CERT_PARSE_MODE_INITIAL:
                    if (len <= CPS_MAX_RSA_LEN) {
                        MI_CpuCopy8(s, con->modulus, len);
                        con->modulus_len = len;
                    }
                    break;
                case CERT_PARSE_MODE_INTERMEDIATE:
                    con->midca_info.modulus_len = len;
                    con->midca_info.modulus = s;
                    break;
                }
            } else if (seq == 1) {
                while (*s == 0) {
                    s++;
                    len--;
                }

                switch (mode) {
                case CERT_PARSE_MODE_INITIAL:
                    if (len <= CPS_MAX_RSA_PUBLICEXPONENT_LEN) {
                        MI_CpuCopy8(s, con->exponent, len);
                        con->exponent_len = len;
                    }
                    break;
                case CERT_PARSE_MODE_INTERMEDIATE:
                    con->midca_info.exponent_len = len;
                    con->midca_info.exponent = s;
                    break;
                }
            }
        }
        s += len;
        break;
    case DER_TYPE_BIT_STRING:
        if (level == 1 && mode != CERT_PARSE_MODE_INTERMEDIATE) {
            con->signature = s + 1;
            con->signature_len = len - 1;
        }

        if (con->seen_pub_algorithm != 0) {
            s++;
            if (cert_item(con, &s, level, 0, mode)) {
                return TRUE;
            }
            con->seen_pub_algorithm = 0;
        } else {
            s += len;
        }
        break;
    case DER_TYPE_OID:
        for (i = 0; i < OID_COUNT; i++) {
            if (memcmp(s, object[i], strlen(object[i])) == 0) {
                switch (i) {
                default:
                    break;
                case OID_RSA_ENCRYPTION:
                case OID_RSA:
                    if (mode == CERT_PARSE_MODE_INITIAL) {
                        con->pub_algorithm = i;
                    }
                    con->seen_pub_algorithm = i;
                    break;
                case OID_MD5_WITH_RSA:
                case OID_SHA1_WITH_RSA:
                    if (mode != CERT_PARSE_MODE_INTERMEDIATE) {
                        con->sig_algorithm = i;
                    }
                    break;
                case OID_COMMON_NAME:
                    if (mode != CERT_PARSE_MODE_INTERMEDIATE) {
                        con->seen_attr = i;
                    }
                    break;
                }
                break;
            }
        }
        s += len;
        break;
    case DER_TYPE_UTF8_STRING:
    case DER_TYPE_PRINTABLE_STRING:
    case DER_TYPE_T61_STRING:
    case DER_TYPE_IA5_STRING:
        if (mode != CERT_PARSE_MODE_INTERMEDIATE) {
            if (con->seen_validity) {
                make_dn(con->subject, s, len);
                if (con->seen_attr == OID_COMMON_NAME && len <= CPS_MAX_CN_LEN) {
                    MI_CpuCopy8(s, con->cn, len);
                    con->cn[len] = '\0';
                }
            } else {
                make_dn(con->issuer, s, len);
            }
        }
        con->seen_attr = 0;
        s += len;
        break;
    case DER_TYPE_UTC_TIME:
    case DER_TYPE_GENERALIZED_TIME:
        if (mode != CERT_PARSE_MODE_INTERMEDIATE) {
            u32 cert_date = parse_time(s, type & DER_TYPE_MASK);
            if (seq == 0) {
                if (con->cur_date >= cert_date) {
                    con->date_ok = TRUE;
                }
            } else if (con->cur_date > cert_date) {
                con->date_ok = FALSE;
            }
        }

        s += len;
        con->seen_validity = TRUE;
        break;
    case DER_TYPE_SEQUENCE:
        if (level == 0 && seq == 0 && mode != CERT_PARSE_MODE_INTERMEDIATE) {
            con->hash_start = s;
        }

        end = s + len;
        int sub_seq = 0;
        while (s < end) {
            if (cert_item(con, &s, level + 1, sub_seq++, mode)) {
                return TRUE;
            }
        }

        if (level == 1 && seq == 0 && mode != CERT_PARSE_MODE_INTERMEDIATE) {
            con->hash_end = s;
        }
        break;
    case DER_TYPE_SET:
        end = s + len;
        while (s < end) {
            if (cert_item(con, &s, level + 1, 0, mode)) {
                return TRUE;
            }
        }
        break;
    default:
        if (type == (DER_FLAG_CONTEXT_SPECIFIC | DER_FLAG_CONSTRUCTED)) {
            end = s + len;
            while (s < end) {
                if (cert_item(con, &s, level + 1, 0, mode)) {
                    return TRUE;
                }
            }
        } else {
            s += len;
        }
        break;
    }

    *ps = s;
    return FALSE;
}

static int validate_signature(CPSSslConnection *con, CPSCaInfo *ca)
{
    u16 *a;
    u16 *b;
    u16 *c;
    u16 *n;
    int i;

    if (con->signature == NULL || con->signature_len == 0
        || ca->exponent == NULL || ca->exponent_len == 0
        || ca->modulus == NULL || ca->modulus_len == 0) {
        return CPS_CERT_BADSIGNATURE;
    }

    int digits = ca->modulus_len * 2 / 2;

    a = CPSiAlloc(digits * 8);
    if (a == NULL) {
        return CPS_CERT_BADSIGNATURE;
    }
    b = a + digits;
    c = b + digits;
    n = c + digits;

    CPSi_big_from_char(b, con->signature, con->signature_len, digits);
    CPSi_big_from_char(c, ca->exponent, ca->exponent_len, digits);
    CPSi_big_from_char(n, ca->modulus, ca->modulus_len, digits);

    u32 old_priority = enter_computebound();
    CPSi_big_power(a, b, c, digits, n);
    exit_computebound(old_priority);

    u8 *s = b;
    CPSi_char_from_big(s, a, ca->modulus_len, digits);

    int result = CPS_CERT_NOERROR;

    if (s[0] != EMSA_PKCS1_HEADER_0 || s[1] != EMSA_PKCS1_HEADER_1) {
        result = CPS_CERT_BADSIGNATURE;
    } else {
        for (i = 2; i < ca->modulus_len; i++) {
            if (s[i] != 0xFF) {
                break;
            }
        }

        if (i + 1 >= ca->modulus_len || s[i] != 0 || s[i + 1] != (DER_FLAG_CONSTRUCTED | DER_TYPE_SEQUENCE)
            || memcmp(con->hash_val, s + ca->modulus_len - con->hash_len, con->hash_len) != 0) {
            result = CPS_CERT_BADSIGNATURE;
        }
    }

    CPSiFree(a);
    return result;
}

static int auth_cert(CPSSslConnection *con)
{
    int result;

    if (con->date_ok) {
        result = CPS_CERT_NOERROR;
    } else {
        result = CPS_CERT_OUTOFDATE;
    }

    if (con->pub_algorithm == -1) {
        return result | CPS_CERT_UNKNOWN_PUBKEYALGORITHM;
    }

    switch (con->sig_algorithm) {
    case OID_MD5_WITH_RSA:
        CPSi_md5_init(&con->md5_hash_tmp);
        CPSi_md5_calc(&con->md5_hash_tmp, con->hash_start, con->hash_end - con->hash_start);
        CPSi_md5_result(&con->md5_hash_tmp, con->hash_val);
        con->hash_len = MD5_HASH_SIZE;
        break;
    case OID_SHA1_WITH_RSA:
        CPSi_sha1_init(&con->sha1_hash_tmp);
        CPSi_sha1_calc(&con->sha1_hash_tmp, con->hash_start, con->hash_end - con->hash_start);
        CPSi_sha1_result(&con->sha1_hash_tmp, con->hash_val);
        con->hash_len = SHA1_HASH_SIZE;
        break;
    default:
        return result | CPS_CERT_UNKNOWN_SIGALGORITHM;
    }

    CPSCaInfo *ca = get_rootCA(con, con->issuer);
    if (ca == NULL) {
        return result | CPS_CERT_NOROOTCA;
    }

    return result | validate_signature(con, ca);
}

static int chars_till_end(char *s)
{
    char *s0 = s;
    while (*s != '.' && *s != '\0') {
        s++;
    }
    return s - s0;
}

static BOOL compare_fqdn(char *name, char *pat)
{
    char c1, c2;

    while (TRUE) {
        while ((c1 = *name++) == (c2 = *pat++)) {
            if (c1 == '\0') {
                return FALSE;
            }
        }

        if (c2 != '*') {
            return TRUE;
        }

        name--;
        int name_cnt = chars_till_end(name);
        int pat_cnt = chars_till_end(pat);
        if (pat_cnt > name_cnt) {
            return TRUE;
        }

        name += name_cnt - pat_cnt;
    }
}

static void rcv_certificate(CPSSslConnection *con, u8 *s)
{
    RTCDate date;
    int result0;
    int result;

    int remaining_certlen = (((s[0] << 8) + s[1]) << 8) + s[2];
    s += 3;
    result = CPS_CERT_NOERROR;
    con->pub_algorithm = -1;
    RTC_GetDate(&date);
    int parse_mode = CERT_PARSE_MODE_INITIAL;
    con->cur_date = ((date.year + 2000) << 16) + (date.month << 8) + date.day;
    con->subject[0] = '\0';
    con->exponent_len = 0;
    con->modulus_len = con->exponent_len;
    int level = 0;

    while (TRUE) {
        int this_certlen = (((s[0] << 8) + s[1]) << 8) + s[2];
        s += 3;
        remaining_certlen -= this_certlen + 3;

        con->sig_algorithm = -1;
        con->seen_pub_algorithm = 0;
        con->seen_validity = FALSE;
        con->date_ok = FALSE;
        con->subject[0] = '\0';
        con->issuer[0] = '\0';
        con->cn[0] = '\0';
        con->cert = s;
        con->certlen = this_certlen;

        if (cert_item(con, &s, 0, 0, parse_mode) || con->modulus_len < CPS_MIN_RSA_LEN || con->exponent_len == 0) {
            con->state = SSL_STATE_ERROR;
            return;
        }

        result = auth_cert(con);
        if (level == 0 && con->server_name != NULL && compare_fqdn(con->server_name, con->cn)) {
            result |= CPS_CERT_BADSERVER;
        }

        result0 = result & CPS_CERT_ERRMASK;
        if (result0 == CPS_CERT_NOROOTCA && remaining_certlen != 0) {
            u8 *s2 = s + 3;
            con->seen_pub_algorithm = 0;
            if (cert_item(con, &s2, 0, 0, CERT_PARSE_MODE_INTERMEDIATE)) {
                con->state = SSL_STATE_ERROR;
                return;
            }
            result = (result & ~CPS_CERT_ERRMASK) | validate_signature(con, &con->midca_info);
        }

        if (con->auth_callback != NULL) {
            result = con->auth_callback(result, con, level);
        }

        level++;

        if (result0 == CPS_CERT_NOERROR || result != CPS_CERT_NOERROR || remaining_certlen == 0) {
            break;
        }

        parse_mode = CERT_PARSE_MODE_NORMAL;
    }

    if (result == CPS_CERT_NOERROR) {
        con->state = SSL_STATE_CERTIFICATE_RECEIVED;
    } else {
        con->state = SSL_STATE_ERROR;
    }
}

static void rcv_server_hello(CPSSslConnection *con, u8 *s)
{
    s += 2;
    MI_CpuCopy8(s, con->server_random, CPS_RANDOM_LEN);
    s += CPS_RANDOM_LEN;

    int session_id_len = *s++;
    if (con->session_cached && session_id_len == SESSION_ID_LEN && memcmp(con->common1.sessionID, s, SESSION_ID_LEN) == 0) {
        con->reuse_session = TRUE;
    } else {
        if (con->session_cached) {
            purge_session(con);
        }

        if (session_id_len == 0) {
            con->session_cached = FALSE;
        } else {
            MI_CpuCopy8(s, con->common1.sessionID, SESSION_ID_LEN);
            con->session_cached = TRUE;
        }

        con->reuse_session = FALSE;
    }

    s += session_id_len;
    con->method = SSL_GET_USHORT(s);
    con->state = SSL_STATE_SERVER_HELLO_RECEIVED;
}

static BOOL has_method(u8 *s, int num, int size, u16 method)
{
    for (int i = 0; i < num; i++) {
        u32 n = SSL_GET_USHORT(&s[0]);
        if (size == 3) {
            n = (n << 8) + s[2];
        }

        if (n == method) {
            return TRUE;
        }

        s += size;
    }

    return FALSE;
}

static int select_method(u8 *s, int num, int size)
{
    for (int i = 0; i < PAIRLIST_LEN; i++) {
        if (has_method(s, num, size, pairlist[i])) {
            return pairlist[i];
        }
    }

    return 0;
}

static BOOL version_ok(u8 major, u8 minor)
{
    return major == 3;
}

static void client_hello_v2(CPSSslConnection *con, u8 *s)
{
    if (!version_ok(s[SSL_V2_HELLO_OFFSET_VERSION_MAJOR], s[SSL_V2_HELLO_OFFSET_VERSION_MINOR])) {
        return;
    }

    int pairlist_len = SSL_GET_USHORT(&s[SSL_V2_HELLO_OFFSET_CIPHER_SPECS_LENGTH]);
    u16 method = select_method(&s[SSL_V2_HELLO_OFFSET_CIPHER_SPECS], pairlist_len / 3, 3);
    if (method == 0) {
        return;
    }

    con->method = method;

    int sessionID_len = SSL_GET_USHORT(&s[SSL_V2_HELLO_OFFSET_SESSION_ID_LENGTH]);
    int random_len = SSL_GET_USHORT(&s[SSL_V2_HELLO_OFFSET_RANDOM_LENGTH]);
    con->session_cached = FALSE;
    s += SSL_V2_HELLO_OFFSET_CIPHER_SPECS + pairlist_len + sessionID_len;

    if (random_len >= CPS_RANDOM_LEN) {
        MI_CpuCopy8(s, con->client_random, CPS_RANDOM_LEN);
    } else {
        MI_CpuClear8(con->client_random, CPS_RANDOM_LEN - random_len);
        MI_CpuCopy8(s, con->server_random - random_len, random_len);
    }

    con->state = SSL_STATE_CLIENT_HELLO_RECEIVED;
}

static void client_hello(CPSSslConnection *con, u8 *s)
{
    if (!version_ok(s[SSL_HELLO_OFFSET_VERSION_MAJOR], s[SSL_HELLO_OFFSET_VERSION_MINOR])) {
        return;
    }

    MI_CpuCopy8(&s[SSL_HELLO_OFFSET_RANDOM], con->client_random, CPS_RANDOM_LEN);
    s += CPS_RANDOM_LEN + 2;

    int sessionID_len = *s++;
    if (sessionID_len != SESSION_ID_LEN) {
        con->session_cached = FALSE;
    } else {
        MI_CpuCopy8(s, con->common1.sessionID, SESSION_ID_LEN);
        find_session_from_id(con);
    }
    s += sessionID_len;

    u16 method = select_method(&s[2], SSL_GET_USHORT(&s[0]) / 2, 2);
    con->method = method;
    if (method != 0) {
        con->state = SSL_STATE_CLIENT_HELLO_RECEIVED;
    }
}

static void decrypt_premaster_secret(u8 *d, u8 *s, CPSPrivateKey *k)
{
    if (k != NULL && k->modulus_len != 0) {
        int digits = k->modulus_len * 2 / 2 + 1;
        u16 *tmp_var = CPSiAlloc(digits * 20);
        if (tmp_var == 0) {
            return;
        }

        u16 *a = tmp_var;
        u16 *b = a + digits;
        u16 *c = b + digits;
        u16 *k1 = c + digits;
        u16 *k2 = k1 + digits;
        u16 *n = k2 + digits;
        u16 *l = n + digits;
        u16 *divwork = l + digits;

        CPSi_big_from_char(tmp_var, s, k->modulus_len, digits);
        CPSi_big_from_char(b, k->exponent1, k->exponent1_len, digits);
        CPSi_big_from_char(n, k->prime1, k->prime1_len, digits);

        u32 old_priority = enter_computebound();
        CPSi_big_montpower(k1, tmp_var, b, digits, n);
        CPSi_big_from_char(b, k->exponent2, k->exponent2_len, digits);
        CPSi_big_from_char(n, k->prime2, k->prime2_len, digits);
        CPSi_big_montpower(k2, tmp_var, b, digits, n);
        exit_computebound(old_priority);

        CPSi_big_sub(tmp_var, k1, k2, digits);
        CPSi_big_from_char(b, k->coefficient, k->coefficient_len, digits);
        CPSi_big_mult(c, tmp_var, b, digits);
        CPSi_big_from_char(b, k->prime2, k->prime2_len, digits);
        CPSi_big_mult(tmp_var, c, b, digits);
        CPSi_big_add(c, tmp_var, k2, digits);
        CPSi_big_from_char(b, k->modulus, k->modulus_len, digits);

        if (CPSi_big_sign(c, digits) < 0) {
            CPSi_big_negate(c, digits);
            CPSi_big_div(0, c, b, l, digits, divwork);
            CPSi_big_sub(l, b, l, digits);
        } else {
            CPSi_big_div(0, c, b, l, digits, divwork);
        }

        CPSi_char_from_big(d, l, MASTER_SECRET_LEN, digits);
        CPSiFree(tmp_var);
    }
}

static void create_ms_sub(u8 *d, char *salt, CPSSslConnection *con)
{
    u8 tmp[SHA1_HASH_SIZE];

    void *p = &con->sha1_hash_tmp;
    CPSi_sha1_init(p);
    CPSi_sha1_calc(p, salt, strlen(salt));
    CPSi_sha1_calc(p, con->master_secret, MASTER_SECRET_LEN);
    CPSi_sha1_calc(p, con->client_random, CPS_RANDOM_LEN * 2);
    CPSi_sha1_result(p, tmp);

    p = &con->md5_hash_tmp;
    CPSi_md5_init(p);
    CPSi_md5_calc(p, con->master_secret, MASTER_SECRET_LEN);
    CPSi_md5_calc(p, tmp, SHA1_HASH_SIZE);
    CPSi_md5_result(p, d);
}

static void create_master_secret(CPSSslConnection *con)
{
    u8 tmp[MD5_HASH_SIZE * 3];

    create_ms_sub(tmp, "A", con);
    create_ms_sub(tmp + MD5_HASH_SIZE, "BB", con);
    create_ms_sub(tmp + MD5_HASH_SIZE * 2, "CCC", con);
    MI_CpuCopy8(tmp, con->master_secret, MASTER_SECRET_LEN);
}

static void create_key_block(CPSSslConnection *con)
{
    u8 tmp[MATH_MAX(MD5_HASH_SIZE, SHA1_HASH_SIZE)];
    int size1;
    int size2;
    int size3;

    switch (con->method) {
    case SSL_RSA_WITH_RC4_128_MD5:
        size1 = MD5_HASH_SIZE;
        size2 = RC4_KEY_LENGTH;
        size3 = 0;
        break;
    case SSL_RSA_WITH_RC4_128_SHA:
        size1 = SHA1_HASH_SIZE;
        size2 = RC4_KEY_LENGTH;
        size3 = 0;
        break;
    }

    int len = (size1 + size2 + size3) * 2;
    for (int i = 0; i * MD5_HASH_SIZE < len; i++) {
        void *p = &con->sha1_hash_tmp;
        CPSi_sha1_init(p);
        u8 c = i + 'A';
        for (int j = 0; j < i + 1; j++) {
            CPSi_sha1_calc(p, &c, 1);
        }
        CPSi_sha1_calc(p, con->master_secret, MASTER_SECRET_LEN);
        CPSi_sha1_calc(p, con->server_random, CPS_RANDOM_LEN);
        CPSi_sha1_calc(p, con->client_random, CPS_RANDOM_LEN);
        CPSi_sha1_result(p, tmp);

        p = &con->md5_hash_tmp;
        CPSi_md5_init(p);
        CPSi_md5_calc(p, con->master_secret, MASTER_SECRET_LEN);
        CPSi_md5_calc(p, tmp, SHA1_HASH_SIZE);
        CPSi_md5_result(p, con->common1.key_block + i * MD5_HASH_SIZE);
    }

    if (con->server) {
        con->rcv_mac = con->common1.key_block;
        con->rcv_key = con->rcv_mac + (size1 * 2);
        con->send_mac = con->common1.key_block + size1;
        con->send_key = con->send_mac + size1 + size2;
    } else {
        con->send_mac = con->common1.key_block;
        con->send_key = con->send_mac + (size1 * 2);
        con->rcv_mac = con->common1.key_block + size1;
        con->rcv_key = con->rcv_mac + size1 + size2;
    }

    CPSi_rc4_init(&con->rcv_cipher, con->rcv_key, RC4_KEY_LENGTH);
    CPSi_rc4_init(&con->send_cipher, con->send_key, RC4_KEY_LENGTH);
}

static void rcv_client_key_exchange(CPSSslConnection *con, u8 *s)
{
    decrypt_premaster_secret(con->master_secret, s, con->my_key);
    create_master_secret(con);
    cache_session(con, 0, 0);
    create_key_block(con);
    con->state = SSL_STATE_CLIENT_KEY_EXCHANGE_RECEIVED;
}

static void finished_md5(CPSSslConnection *con, u8 *d, int flag)
{
    u8 tmp[48];
    CPSMd5Ctx *p = &con->md5_hash;

    if (con->server ^ flag) {
        CPSi_md5_calc(p, "SRVR", 4);
    } else {
        CPSi_md5_calc(p, "CLNT", 4);
    }
    CPSi_md5_calc(p, con->master_secret, MASTER_SECRET_LEN);
    MI_CpuFill8(tmp, 0x36, 48);
    CPSi_md5_calc(p, tmp, 48);
    CPSi_md5_result(p, d);

    CPSi_md5_init(p);
    CPSi_md5_calc(p, con->master_secret, MASTER_SECRET_LEN);
    MI_CpuFill8(tmp, 0x5C, 48);
    CPSi_md5_calc(p, tmp, 48);
    CPSi_md5_calc(p, d, 16);
    CPSi_md5_result(p, d);
}

static void finished_sha1(CPSSslConnection *con, u8 *d, BOOL flag)
{
    u8 tmp[40];
    CPSSha1Ctx *p = &con->sha1_hash;

    if (con->server ^ flag) {
        CPSi_sha1_calc(p, "SRVR", 4);
    } else {
        CPSi_sha1_calc(p, "CLNT", 4);
    }
    CPSi_sha1_calc(p, con->master_secret, MASTER_SECRET_LEN);
    MI_CpuFill8(&tmp, 0x36, 40);
    CPSi_sha1_calc(p, tmp, 40);
    CPSi_sha1_result(p, d);

    CPSi_sha1_init(p);
    CPSi_sha1_calc(p, con->master_secret, MASTER_SECRET_LEN);
    MI_CpuFill8(&tmp, 0x5C, 40);
    CPSi_sha1_calc(p, tmp, 40);
    CPSi_sha1_calc(p, d, 20);
    CPSi_sha1_result(p, d);
}

static void rcv_finished(CPSSslConnection *con, u8 *s)
{
    u8 tmp[MATH_MAX(MD5_HASH_SIZE, SHA1_HASH_SIZE)];

    MI_CpuCopy8(&con->md5_hash, &con->md5_hash_tmp, sizeof(CPSMd5Ctx));
    finished_md5(con, tmp, TRUE);
    MI_CpuCopy8(&con->md5_hash_tmp, &con->md5_hash, sizeof(CPSMd5Ctx));
    if (memcmp(s, tmp, MD5_HASH_SIZE) != 0) {
        con->state = SSL_STATE_ERROR;
        return;
    }

    MI_CpuCopy8(&con->sha1_hash, &con->sha1_hash_tmp, sizeof(CPSSha1Ctx));
    finished_sha1(con, tmp, TRUE);
    MI_CpuCopy8(&con->sha1_hash_tmp, &con->sha1_hash, sizeof(CPSSha1Ctx));
    if (memcmp(s + MD5_HASH_SIZE, tmp, SHA1_HASH_SIZE) != 0) {
        con->state = SSL_STATE_ERROR;
        return;
    }

    con->state = SSL_STATE_FINISHED_RECEIVED;
}

static void add1_be8(u8 *d)
{
    for (int i = 8; i != 0; i--) {
        d--;
        u8 tmp = *d + 1;
        *d = tmp;
        if (tmp != 0) {
            return;
        }
    }
}

static int decrypt(CPSSslConnection *con, u8 *s, int len)
{
    CPSi_rc4_crypt(&con->rcv_cipher, s, len);
    return len;
}

static int make_plaintext(CPSSslConnection *con, u8 *s)
{
    u8 tmp[MATH_MAX(MD5_HASH_SIZE, SHA1_HASH_SIZE)];
    u8 pad[48];

    int len = decrypt(con, s + SSL_HEADER_SIZE, SSL_GET_USHORT(&s[SSL_OFFSET_RECORD_LENGTH]));
    int hash_len;
    void *p;

    switch (con->method) {
    case SSL_RSA_WITH_RC4_128_MD5:
        len -= MD5_HASH_SIZE;
        CPS_SETUSHORT1(&s[SSL_OFFSET_RECORD_LENGTH], len);
        p = &con->md5_hash_tmp;
        CPSi_md5_init(p);
        CPSi_md5_calc(p, con->rcv_mac, MD5_HASH_SIZE);
        MI_CpuFill8(pad, 0x36, 48);
        CPSi_md5_calc(p, pad, 48);
        CPSi_md5_calc(p, con->rcv_seq, sizeof(con->rcv_seq));
        CPSi_md5_calc(p, s, 1);
        CPSi_md5_calc(p, s + SSL_OFFSET_RECORD_LENGTH, len + 2);
        CPSi_md5_result(p, tmp);
        CPSi_md5_init(p);
        CPSi_md5_calc(p, con->rcv_mac, MD5_HASH_SIZE);
        MI_CpuFill8(pad, 0x5C, 48);
        CPSi_md5_calc(p, pad, 48);
        CPSi_md5_calc(p, tmp, MD5_HASH_SIZE);
        CPSi_md5_result(p, tmp);
        hash_len = MD5_HASH_SIZE;
        break;
    case SSL_RSA_WITH_RC4_128_SHA:
        len -= SHA1_HASH_SIZE;
        CPS_SETUSHORT1(&s[SSL_OFFSET_RECORD_LENGTH], len);
        p = &con->sha1_hash_tmp;
        CPSi_sha1_init(p);
        CPSi_sha1_calc(p, con->rcv_mac, SHA1_HASH_SIZE);
        MI_CpuFill8(pad, 0x36, 40);
        CPSi_sha1_calc(p, pad, 40);
        CPSi_sha1_calc(p, con->rcv_seq, sizeof(con->rcv_seq));
        CPSi_sha1_calc(p, s, 1);
        CPSi_sha1_calc(p, s + SSL_OFFSET_RECORD_LENGTH, len + 2);
        CPSi_sha1_result(p, tmp);
        CPSi_sha1_init(p);
        CPSi_sha1_calc(p, con->rcv_mac, SHA1_HASH_SIZE);
        MI_CpuFill8(pad, 0x5C, 40);
        CPSi_sha1_calc(p, pad, 40);
        CPSi_sha1_calc(p, tmp, SHA1_HASH_SIZE);
        CPSi_sha1_result(p, tmp);
        hash_len = SHA1_HASH_SIZE;
        break;
    }

    if (memcmp(s + SSL_HEADER_SIZE + len, tmp, hash_len) != 0) {
        con->state = SSL_STATE_ERROR;
    }

    add1_be8(con->rcv_seq + 8);
    return len + SSL_HEADER_SIZE;
}

static int make_ciphertext(CPSSslConnection *con, u8 *s)
{
    u8 tmp[48];

    int len = SSL_GET_USHORT(&s[SSL_OFFSET_RECORD_LENGTH]);
    u8 *mac = s + SSL_HEADER_SIZE + len;
    void *p;

    switch (con->method) {
    case SSL_RSA_WITH_RC4_128_MD5:
        p = &con->md5_hash_tmp;
        CPSi_md5_init(p);
        CPSi_md5_calc(p, con->send_mac, MD5_HASH_SIZE);
        MI_CpuFill8(tmp, 0x36, 48);
        CPSi_md5_calc(p, tmp, 48);
        CPSi_md5_calc(p, con->send_seq, 8);
        CPSi_md5_calc(p, s, 1);
        CPSi_md5_calc(p, s + SSL_OFFSET_RECORD_LENGTH, len + 2);
        CPSi_md5_result(p, mac);
        CPSi_md5_init(p);
        CPSi_md5_calc(p, con->send_mac, MD5_HASH_SIZE);
        MI_CpuFill8(tmp, 0x5C, 48);
        CPSi_md5_calc(p, tmp, 48);
        CPSi_md5_calc(p, mac, MD5_HASH_SIZE);
        CPSi_md5_result(p, mac);
        len += MD5_HASH_SIZE;
        break;
    case SSL_RSA_WITH_RC4_128_SHA:
        p = &con->sha1_hash_tmp;
        CPSi_sha1_init(p);
        CPSi_sha1_calc(p, con->send_mac, SHA1_HASH_SIZE);
        MI_CpuFill8(tmp, 0x36, 40);
        CPSi_sha1_calc(p, tmp, 40);
        CPSi_sha1_calc(p, con->send_seq, 8);
        CPSi_sha1_calc(p, s, 1);
        CPSi_sha1_calc(p, s + SSL_OFFSET_RECORD_LENGTH, len + 2);
        CPSi_sha1_result(p, mac);
        CPSi_sha1_init(p);
        CPSi_sha1_calc(p, con->send_mac, SHA1_HASH_SIZE);
        MI_CpuFill8(tmp, 0x5C, 40);
        CPSi_sha1_calc(p, tmp, 40);
        CPSi_sha1_calc(p, mac, SHA1_HASH_SIZE);
        CPSi_sha1_result(p, mac);
        len += SHA1_HASH_SIZE;
        break;
    }

    CPS_SETUSHORT1(&s[SSL_OFFSET_RECORD_LENGTH], len);

    CPSi_rc4_crypt(&con->send_cipher, s + SSL_HEADER_SIZE, len);
    add1_be8(con->send_seq + 8);

    return len + SSL_HEADER_SIZE;
}

static int tcp_read_raw_nbytes(u8 *d, int len, CPSSoc *soc)
{
    do {
        u32 thislen;
        u8 *s = CPSi_TcpReadRaw(&thislen, soc);
        if (thislen == 0) {
            return -1;
        }

        if (thislen > len) {
            thislen = len;
        }

        MI_CpuCopy8(s, d, thislen);
        CPSi_SocConsumeRaw(thislen, soc);

        len -= thislen;
        d += thislen;
    } while (len > 0);

    return 0;
}

static void update_digest(CPSSslConnection *con, u8 *s, u32 len)
{
    CPSi_sha1_calc(&con->sha1_hash, s, len);
    CPSi_md5_calc(&con->md5_hash, s, len);
}

static void parse_record_in_buf(CPSSslConnection *con, u8 *buf)
{
    u8 *s;

    if (con->state == SSL_STATE_ERROR) {
        CPSiFree(buf);
        return;
    }

    u8 type = buf[SSL_OFFSET_CONTENT_TYPE];
    u32 len = SSL_GET_USHORT(&buf[SSL_OFFSET_RECORD_LENGTH]) + SSL_HEADER_SIZE;
    if (((con->state == SSL_STATE_CHANGE_CIPHER_SPEC_RECEIVED || con->state == SSL_STATE_ESTABLISHED) && type != SSL_ALERT)
        || (type == SSL_ALERT && len > SSL_HEADER_SIZE + 2)) {
        len = make_plaintext(con, buf);
        if (con->state == SSL_STATE_ERROR) {
            CPSiFree(buf);
            return;
        }
    }

    s = buf + SSL_HEADER_SIZE;
    len -= SSL_HEADER_SIZE;

    switch (type) {
    case SSL_CHANGE_CIPHER_SPEC:
        if (con->rcv_mac == NULL) {
            con->state = SSL_STATE_ERROR;
        } else {
            MI_CpuClear8(con->rcv_seq, sizeof(con->rcv_seq));
            con->state = SSL_STATE_CHANGE_CIPHER_SPEC_RECEIVED;
        }
        break;
    case SSL_ALERT:
        if (*s == SSL_ALERT_LEVEL_FATAL) {
            con->state = SSL_STATE_ERROR;
        }
        break;
    case SSL_HANDSHAKE:
        do {
            type = s[0];
            s32 msglen = (s[1] << 16) + (s[2] << 8) + s[3];
            s += 4;

            switch (type) {
            case SSL_HANDSHAKE_CLIENT_HELLO:
                if (con->server && con->state == SSL_STATE_INIT) {
                    client_hello(con, s);
                }
                break;
            case SSL_HANDSHAKE_CLIENT_KEY_EXCHANGE:
                rcv_client_key_exchange(con, s);
                break;
            case SSL_HANDSHAKE_SERVER_HELLO:
                rcv_server_hello(con, s);
                break;
            case SSL_HANDSHAKE_CERTIFICATE:
                rcv_certificate(con, s);
                con->seen_validity = FALSE;
                break;
            case SSL_HANDSHAKE_CERTIFICATE_REQUEST:
                con->seen_validity = TRUE;
                break;
            case SSL_HANDSHAKE_SERVER_HELLO_DONE:
                con->state = SSL_STATE_SERVER_HELLO_DONE_RECEIVED;
                break;
            case SSL_HANDSHAKE_FINISHED:
                rcv_finished(con, s);
                break;
            default:
                con->state = SSL_STATE_ERROR;
                break;
            }

            update_digest(con, s - 4, msglen + 4);
            s += msglen;
            len -= msglen + 4;
        } while (len != 0 && con->state != SSL_STATE_ERROR);
        break;
    case SSL_APPLICATION_DATA:
        con->inbuf = buf;
        con->inbuf_pnt = SSL_HEADER_SIZE;
        con->inbuf_len = len + SSL_HEADER_SIZE;
        con->inbuf_decrypted = TRUE;
        return;
    default:
        con->state = SSL_STATE_ERROR;
        break;
    }

    CPSiFree(buf);
}

static int parse_record(CPSSoc *soc)
{
    u8 *s;
    u32 len;

    CPSSslConnection *con = soc->con;

    do {
        s = CPSi_TcpReadRaw(&len, soc);
        if (len == 0) {
            con->state = SSL_STATE_ERROR;
            return SSL_STATE_ERROR;
        }
    } while (len < SSL_HEADER_SIZE);

    if (s[SSL_OFFSET_CONTENT_TYPE] == SSL_V2_RECORD) {
        if (con->server && con->state == SSL_STATE_INIT) {
            len = s[SSL_V2_OFFSET_LENGTH];
            CPSi_SocConsumeRaw(2, soc);

            u8 *buf = CPSiAlloc(len);
            if (buf == NULL) {
                con->state = SSL_STATE_ERROR;
                return SSL_STATE_ERROR;
            }

            if (tcp_read_raw_nbytes(buf, len, soc) == 0 && *buf == SSL_V2_CLIENT_HELLO) {
                client_hello_v2(con, buf + 1);
            } else {
                con->state = SSL_STATE_ERROR;
            }

            update_digest(con, buf, len);
            CPSiFree(buf);
        } else {
            con->state = SSL_STATE_ERROR;
        }
    } else {
        len = SSL_GET_USHORT(&s[SSL_OFFSET_RECORD_LENGTH]) + SSL_HEADER_SIZE;
        if (len > SSL_MAX_RECORD_SIZE + SSL_MAX_PADDING + SSL_HEADER_SIZE) {
            con->state = SSL_STATE_ERROR;
            return SSL_STATE_ERROR;
        }

        u8 *buf = CPSiAlloc(len);
        if (buf == NULL) {
            con->state = SSL_STATE_ERROR;
            return SSL_STATE_ERROR;
        }

        if (tcp_read_raw_nbytes(buf, len, soc) != 0) {
            CPSiFree(buf);
            con->state = SSL_STATE_ERROR;
            return SSL_STATE_ERROR;
        }

        parse_record_in_buf(con, buf);
    }

    return con->state;
}

static void set_random(u8 *d, int len)
{
    CPSSha1Ctx ctx;
    u8 x[SHA1_HASH_SIZE];
    int j;
    u32 tmp;

    if (!pool_initialized) {
        tmp = MATH_Rand32(&CPSiRand32ctx, 0);
        CPS_SslAddRandomSeed(&tmp, sizeof(tmp));
    }

    for (int i = 0, r = SHA1_HASH_SIZE; i < len; r++) {
        if (r == SHA1_HASH_SIZE) {
            CPSi_sha1_init(&ctx);
            OSIntrMode enabled = OS_DisableInterrupts();
            CPSi_sha1_calc(&ctx, pool, SHA1_HASH_SIZE);
            CPSi_sha1_result_prng(&ctx, x);
            u32 carry = 1;
            for (j = SHA1_HASH_SIZE - 1; j >= 0; j--) {
                tmp = pool[j] + x[j] + carry;
                pool[j] = tmp;
                carry = tmp >> 8;
            }
            OS_RestoreInterrupts(enabled);
            r = 0;
        }

        if (x[r] != 0) {
            d[i++] = x[r];
        }
    }
}

void CPS_SslAddRandomSeed(void *random_seed, u32 len)
{
    CPSSha1Ctx ctx;
    CPSi_sha1_init(&ctx);

    OSIntrMode enabled = OS_DisableInterrupts();
    CPSi_sha1_calc(&ctx, pool, SHA1_HASH_SIZE);
    CPSi_sha1_calc(&ctx, random_seed, len);
    CPSi_sha1_result(&ctx, pool);
    OS_RestoreInterrupts(enabled);

    pool_initialized = TRUE;
}

static BOOL send_server_hello(CPSSoc *soc)
{
    CPSSslConnection *con = soc->con;
    u8 *buf;
    u8 *d;
    int certificate_len;
    static u32 cnt = 0;

    CPSCertificate *c = con->my_certificate;
    if (c != NULL) {
        certificate_len = c->certificate_len;
    } else {
        certificate_len = 0;
    }

    u32 sec = date2sec();
    con->server_random[0] = sec >> 24;
    con->server_random[1] = sec >> 16;
    con->server_random[2] = sec >> 8;
    con->server_random[3] = sec;
    set_random(&con->server_random[4], CPS_RANDOM_LEN - 4);

    buf = CPSiAlloc(certificate_len + 157);
    if (buf == NULL) {
        con->state = SSL_STATE_ERROR;
        return TRUE;
    }
    d = buf + SSL_HEADER_SIZE;
    *d++ = SSL_HANDSHAKE_SERVER_HELLO;
    *d++ = 0;
    *d++ = 0;
    *d++ = 70;
    *d++ = 3;
    *d++ = 0;
    MI_CpuCopy8(con->server_random, d, CPS_RANDOM_LEN);
    d += CPS_RANDOM_LEN;
    *d++ = SESSION_ID_LEN;

    if (con->session_cached) {
        MI_CpuCopy8(con->common1.sessionID, d, SESSION_ID_LEN);
        d += SESSION_ID_LEN;
        con->reuse_session = TRUE;
    } else {
        set_random(d, SESSION_ID_LEN - 4);
        d += SESSION_ID_LEN - 4;
        *d++ = cnt >> 24;
        *d++ = cnt >> 16;
        *d++ = cnt >> 8;
        *d++ = cnt;
        MI_CpuCopy8(d - SESSION_ID_LEN, con->common1.sessionID, SESSION_ID_LEN);
        cnt++;
        con->reuse_session = FALSE;
    }

    *d++ = con->method >> 8;
    *d++ = con->method;
    *d++ = 0;
    if (!con->reuse_session) {
        if (certificate_len != 0) {
            *d++ = SSL_HANDSHAKE_CERTIFICATE;
            *d++ = (certificate_len + 6) >> 16;
            *d++ = (certificate_len + 6) >> 8;
            *d++ = certificate_len + 6;
            *d++ = (certificate_len + 3) >> 16;
            *d++ = (certificate_len + 3) >> 8;
            *d++ = certificate_len + 3;
            *d++ = certificate_len >> 16;
            *d++ = certificate_len >> 8;
            *d++ = certificate_len;
            MI_CpuCopy8(c->certificate, d, certificate_len);
            d += certificate_len;
        }

        *d++ = SSL_HANDSHAKE_SERVER_HELLO_DONE;
        *d++ = 0;
        *d++ = 0;
        *d++ = 0;
    }

    int len = (d - buf) - SSL_HEADER_SIZE;
    buf[SSL_OFFSET_CONTENT_TYPE] = SSL_HANDSHAKE;
    buf[SSL_OFFSET_VERSION_MAJOR] = 3;
    buf[SSL_OFFSET_VERSION_MINOR] = 0;
    CPS_SETUSHORT1(&buf[SSL_OFFSET_RECORD_LENGTH], len);
    update_digest(con, buf + SSL_HEADER_SIZE, len);
    CPSi_TcpWrite2Raw(buf, len + SSL_HEADER_SIZE, NULL, 0, soc);
    CPSiFree(buf);
    return con->reuse_session;
}

static void send_change_cipher_spec_and_finished(CPSSoc *soc)
{
    CPSSslConnection *con = soc->con;
    u8 *buf = CPSiAlloc(131);
    if (buf == NULL) {
        con->state = SSL_STATE_ERROR;
        return;
    }

    u8 *d = buf;
    *d++ = SSL_CHANGE_CIPHER_SPEC;
    *d++ = 3;
    *d++ = 0;
    *d++ = 0;
    *d++ = 1;
    *d++ = 1;
    MI_CpuClear8(con->send_seq, sizeof(con->send_seq));
    *d++ = SSL_HANDSHAKE;
    *d++ = 3;
    *d++ = 0;
    *d++ = 0;
    *d++ = 4 + MD5_HASH_SIZE + SHA1_HASH_SIZE;
    *d++ = SSL_HANDSHAKE_FINISHED;
    *d++ = 0;
    *d++ = 0;
    *d++ = MD5_HASH_SIZE + SHA1_HASH_SIZE;

    MI_CpuCopy8(&con->md5_hash, &con->md5_hash_tmp, sizeof(CPSMd5Ctx));
    finished_md5(con, d, FALSE);
    MI_CpuCopy8(&con->md5_hash_tmp, &con->md5_hash, sizeof(CPSMd5Ctx));

    MI_CpuCopy8(&con->sha1_hash, &con->sha1_hash_tmp, sizeof(CPSSha1Ctx));
    finished_sha1(con, d + MD5_HASH_SIZE, FALSE);
    MI_CpuCopy8(&con->sha1_hash_tmp, &con->sha1_hash, sizeof(CPSSha1Ctx));

    update_digest(con, buf + 11, 4 + MD5_HASH_SIZE + SHA1_HASH_SIZE);
    CPSi_TcpWrite2Raw(buf, make_ciphertext(con, buf + 6) + 6, NULL, 0, soc);
    CPSiFree(buf);
}

static void send_client_hello(CPSSoc *soc)
{
    int i;

    CPSSslConnection *con = soc->con;
    u8 *buf = CPSiAlloc(152);
    if (buf == NULL) {
        con->state = SSL_STATE_ERROR;
        return;
    }

    u8 *d = buf + SSL_HEADER_SIZE + 4;
    *d++ = 3;
    *d++ = 0;

    u32 sec = date2sec();
    con->client_random[0] = sec >> 24;
    con->client_random[1] = sec >> 16;
    con->client_random[2] = sec >> 8;
    con->client_random[3] = sec;
    set_random(&con->client_random[4], CPS_RANDOM_LEN - 4);
    MI_CpuCopy8(con->client_random, d, CPS_RANDOM_LEN);
    d += CPS_RANDOM_LEN;

    find_session_from_IP(con, soc->remote_ip, soc->remote_port);
    if (con->session_cached) {
        *d++ = SESSION_ID_LEN;
        MI_CpuCopy8(con->common1.sessionID, d, SESSION_ID_LEN);
        d += SESSION_ID_LEN;
    } else {
        *d++ = 0;
    }

    i = 0;
    *d++ = 0;
    *d++ = PAIRLIST_LEN * sizeof(u16);
    for (i = 0; i < PAIRLIST_LEN; i++) {
        *d++ = pairlist[i] >> 8;
        *d++ = pairlist[i];
    }
    *d++ = 1;
    *d++ = 0;

    i = d - buf - SSL_HEADER_SIZE;
    buf[SSL_OFFSET_CONTENT_TYPE] = SSL_HANDSHAKE;
    buf[SSL_OFFSET_VERSION_MAJOR] = 3;
    buf[SSL_OFFSET_VERSION_MINOR] = 0;
    CPS_SETUSHORT1(&buf[SSL_OFFSET_RECORD_LENGTH], i);
    i -= 4;
    buf[SSL_HEADER_SIZE + 0] = SSL_HANDSHAKE_CLIENT_HELLO;
    buf[SSL_HEADER_SIZE + 1] = i >> 16;
    buf[SSL_HEADER_SIZE + 2] = i >> 8;
    buf[SSL_HEADER_SIZE + 3] = i;

    CPSi_TcpWrite2Raw(buf, i + SSL_HEADER_SIZE + 4, NULL, 0, soc);
    update_digest(con, buf + SSL_HEADER_SIZE, i + 4);
    CPSiFree(buf);
}

static void send_client_key_exchange(CPSSoc *soc)
{
    CPSSslConnection *con = soc->con;
    u16 *tmp_var;
    u16 *c;
    u16 *a;
    u16 *b;
    u16 *n;
    int digits;
    u8 *tmp;

    if (con->seen_validity) {
        CPSi_TcpWrite2Raw(alert_nocert, sizeof(alert_nocert), NULL, 0, soc);
    }

    con->master_secret[0] = 3;
    con->master_secret[1] = 0;
    set_random(con->master_secret + 2, MASTER_SECRET_LEN - 2);

    int modlen = con->modulus_len;
    digits = modlen * 2 / 2;
    tmp = CPSiAlloc(modlen);
    if (tmp == NULL) {
        con->state = SSL_STATE_ERROR;
        return;
    }

    tmp[0] = 0;
    tmp[1] = 2;
    set_random(tmp + 2, modlen - CPS_MIN_RSA_LEN);
    tmp[2 + modlen - CPS_MIN_RSA_LEN] = 0;
    MI_CpuCopy8(con->master_secret, tmp + modlen - MASTER_SECRET_LEN, MASTER_SECRET_LEN);

    tmp_var = CPSiAlloc(digits * 8);
    if (tmp_var == NULL) {
        CPSiFree(tmp);
        con->state = SSL_STATE_ERROR;
        return;
    }

    c = tmp_var;
    a = c + digits;
    b = a + digits;
    n = b + digits;

    CPSi_big_from_char(a, tmp, modlen, digits);
    CPSi_big_from_char(b, con->exponent, con->exponent_len, digits);
    CPSi_big_from_char(n, con->modulus, modlen, digits);

    u32 old_priority = enter_computebound();
    CPSi_big_power(tmp_var, a, b, digits, n);
    exit_computebound(old_priority);

    u8 *buf = CPSiAlloc(modlen + 73);
    if (buf == NULL) {
        CPSiFree(tmp);
        CPSiFree(tmp_var);
        con->state = SSL_STATE_ERROR;
        return;
    }

    u8 *d = buf;
    *d++ = SSL_HANDSHAKE;
    *d++ = 3;
    *d++ = 0;
    *d++ = (modlen + 4) >> 8;
    *d++ = modlen + 4;
    *d++ = SSL_HANDSHAKE_CLIENT_KEY_EXCHANGE;
    *d++ = modlen >> 16;
    *d++ = modlen >> 8;
    *d++ = modlen;

    if (modlen & 1) {
        *d++ = tmp_var[modlen / 2];
    }

    for (int i = modlen / 2 - 1; i >= 0; i--) {
        *d++ = tmp_var[i] >> 8;
        *d++ = tmp_var[i];
    }

    CPSi_TcpWrite2Raw(buf, modlen + 4 + SSL_HEADER_SIZE, NULL, 0, soc);
    update_digest(con, buf + SSL_HEADER_SIZE, modlen + 4);
    CPSiFree(buf);
    CPSiFree(tmp_var);
    CPSiFree(tmp);
}

static BOOL mustget_change_cipher_spec_and_finished(CPSSoc *soc)
{
    if (parse_record(soc) != SSL_STATE_CHANGE_CIPHER_SPEC_RECEIVED) {
        return TRUE;
    }
    if (parse_record(soc) != SSL_STATE_FINISHED_RECEIVED) {
        return TRUE;
    }
    return FALSE;
}

static BOOL ssl_listen_try(CPSSoc *soc)
{
    if (parse_record(soc) != SSL_STATE_CLIENT_HELLO_RECEIVED) {
        return TRUE;
    }

    if (send_server_hello(soc)) {
        create_key_block(soc->con);
        send_change_cipher_spec_and_finished(soc);
        if (mustget_change_cipher_spec_and_finished(soc)) {
            return TRUE;
        }
    } else if (parse_record(soc) != SSL_STATE_CLIENT_KEY_EXCHANGE_RECEIVED) {
        return TRUE;
    } else if (mustget_change_cipher_spec_and_finished(soc)) {
        return TRUE;
    } else {
        send_change_cipher_spec_and_finished(soc);
    }

    return FALSE;
}

void CPSi_SslListen(CPSSoc *soc)
{
    CPSSslConnection *con = soc->con;

    while (TRUE) {
        CPSi_TcpListenRaw(soc);
        con->state = SSL_STATE_INIT;
        con->rcv_mac = NULL;
        con->server = TRUE;
        CPSi_sha1_init(&con->sha1_hash);
        CPSi_md5_init(&con->md5_hash);

        BOOL result = ssl_listen_try(soc);
        if (!result) {
            con->state = SSL_STATE_ESTABLISHED;
            break;
        }

        CPSi_TcpShutdownRaw(soc);
        soc->remote_port = soc->remote_port_bound;
        soc->remote_ip = soc->remote_ip_bound;
    }
}

static u32 ssl_connect_try(CPSSoc *soc)
{
    CPSSslConnection *con = soc->con;
    int state;

    send_client_hello(soc);

    do {
        state = parse_record(soc);
        if (state == SSL_STATE_ERROR) {
            return 1;
        }
    } while (state != SSL_STATE_SERVER_HELLO_DONE_RECEIVED && !con->reuse_session);

    if (con->reuse_session) {
        create_key_block(con);
        if (mustget_change_cipher_spec_and_finished(soc)) {
            return 1;
        }

        send_change_cipher_spec_and_finished(soc);
    } else {
        send_client_key_exchange(soc);
        create_master_secret(con);

        if (con->session_cached) {
            cache_session(con, soc->remote_ip, soc->remote_port);
        }

        create_key_block(con);
        send_change_cipher_spec_and_finished(soc);

        if (mustget_change_cipher_spec_and_finished(soc)) {
            return 1;
        }
    }

    con->state = SSL_STATE_ESTABLISHED;
    return 0;
}

u32 CPSi_SslConnect(CPSSoc *soc)
{
    CPSSslConnection *con = soc->con;
    if (soc->state != SSL_STATE_SERVER_HELLO_DONE_RECEIVED && CPSi_TcpConnectRaw(soc) != 0) {
        return 1;
    }

    con->state = SSL_STATE_INIT;
    con->rcv_mac = NULL;
    con->server = FALSE;
    CPSi_sha1_init(&con->sha1_hash);
    CPSi_md5_init(&con->md5_hash);
    return ssl_connect_try(soc);
}

u8 *CPSi_SslRead(u32 *len, CPSSoc *soc)
{
    CPSSslConnection *con = soc->con;

    if (con->inbuf != NULL && !con->inbuf_decrypted) {
        if (tcp_read_raw_nbytes(&con->inbuf[con->inbuf_pnt], con->inbuf_len - con->inbuf_pnt, soc) != 0) {
            CPSiFree(con->inbuf);
            con->inbuf = NULL;
            *len = 0;
            return NULL;
        }

        parse_record_in_buf(con, con->inbuf);
        if (!con->inbuf_decrypted) {
            con->inbuf = NULL;
        }
    }

    while (con->inbuf == NULL) {
        if (parse_record(soc) == SSL_STATE_ERROR) {
            *len = 0;
            return NULL;
        }
    }

    *len = con->inbuf_len - con->inbuf_pnt;
    return con->inbuf + con->inbuf_pnt;
}

void CPSi_SslConsume(u32 len, CPSSoc *soc)
{
    CPSSslConnection *con = soc->con;

    if (len >= con->inbuf_len - con->inbuf_pnt) {
        if (con->inbuf != NULL) {
            CPSiFree(con->inbuf);
        }

        con->inbuf = NULL;
        return;
    }

    con->inbuf_pnt += len;
}

static void try_fill_record(CPSSoc *soc)
{
    BOOL got_all;
    u32 len;
    u8 *s;

    CPSSslConnection *con = soc->con;

    if (con->inbuf == NULL) {
        if (soc->rcvbufp < SSL_HEADER_SIZE) {
            return;
        }

        s = CPSi_TcpReadRaw(&len, soc);
        len = SSL_GET_USHORT(&s[SSL_OFFSET_RECORD_LENGTH]) + SSL_HEADER_SIZE;

        if (len > SSL_MAX_RECORD_SIZE + SSL_MAX_PADDING + SSL_HEADER_SIZE) {
            con->state = SSL_STATE_ERROR;
            return;
        }

        con->inbuf = CPSiAlloc(len);
        if (con->inbuf == NULL) {
            con->state = SSL_STATE_ERROR;
            return;
        }

        con->inbuf_len = len;
        con->inbuf_pnt = 0;
        con->inbuf_decrypted = FALSE;
    } else if (soc->rcvbufp == 0) {
        return;
    }

    s = CPSi_TcpReadRaw(&len, soc);

    if (len >= con->inbuf_len - con->inbuf_pnt) {
        len = con->inbuf_len - con->inbuf_pnt;
        got_all = TRUE;
    } else {
        got_all = FALSE;
    }

    MI_CpuCopy8(s, &con->inbuf[con->inbuf_pnt], len);
    CPSi_SocConsumeRaw(len, soc);

    if (got_all) {
        parse_record_in_buf(con, con->inbuf);
        if (!con->inbuf_decrypted) {
            con->inbuf = NULL;
        }
    } else {
        con->inbuf_pnt += len;
    }
}

s32 CPSi_SslGetLength(CPSSoc *soc)
{
    CPSSslConnection *con = soc->con;

    if (con->inbuf == NULL || !con->inbuf_decrypted) {
        try_fill_record(soc);
    }

    if (con->inbuf != NULL && con->inbuf_decrypted) {
        return con->inbuf_len - con->inbuf_pnt;
    }

    if (con->inbuf == NULL && (soc->state != SSL_STATE_SERVER_HELLO_DONE_RECEIVED || con->state == SSL_STATE_ERROR)) {
        return -1;
    }

    return 0;
}

u32 CPSi_SslWrite2(u8 *buf, u32 len, u8 *buf2, u32 len2, CPSSoc *soc)
{
    CPSSslConnection *con = soc->con;
    u8 *tmp;
    s32 total_len = len + len2;
    s32 this_len;
    s32 part1_len;
    s32 part2_len;
    s32 total_sent_len = 0;

    do {
        if (total_len > ssl_blklen) {
            this_len = ssl_blklen;
        } else {
            this_len = total_len;
        }

        tmp = CPSiAlloc(this_len + MAX_BLOAT);
        if (tmp == NULL) {
            break;
        }

        if (len >= this_len) {
            part1_len = this_len;
        } else {
            part1_len = len;
        }

        part2_len = this_len - part1_len;
        MI_CpuCopy8(buf, tmp + SSL_HEADER_SIZE, part1_len);
        buf += part1_len;
        len -= part1_len;

        MI_CpuCopy8(buf2, tmp + SSL_HEADER_SIZE + part1_len, part2_len);
        buf2 += part2_len;
        len2 -= part2_len;

        tmp[SSL_OFFSET_CONTENT_TYPE] = SSL_APPLICATION_DATA;
        tmp[SSL_OFFSET_VERSION_MAJOR] = 3;
        tmp[SSL_OFFSET_VERSION_MINOR] = 0;
        CPS_SETUSHORT1(&tmp[SSL_OFFSET_RECORD_LENGTH], this_len);

        s32 this_sent_len = make_ciphertext(con, tmp);
        if (CPSi_TcpWrite2Raw(tmp, this_sent_len, NULL, 0, soc) < this_sent_len) {
            this_len = 0;
        }

        CPSiFree(tmp);
        total_len -= this_len;
        total_sent_len += this_len;
    } while (total_len != 0 && this_len != 0);

    return total_sent_len;
}

void CPSi_SslShutdown(CPSSoc *soc)
{
    CPSSslConnection *con = soc->con;
    u8 tmp[27];

    if (con->state == SSL_STATE_ESTABLISHED) {
        tmp[SSL_OFFSET_CONTENT_TYPE] = SSL_ALERT;
        tmp[SSL_OFFSET_VERSION_MAJOR] = 3;
        tmp[SSL_OFFSET_VERSION_MINOR] = 0;
        CPS_SETUSHORT1(&tmp[SSL_OFFSET_RECORD_LENGTH], 2);
        tmp[SSL_HEADER_SIZE + 0] = SSL_ALERT_LEVEL_WARNING;
        tmp[SSL_HEADER_SIZE + 1] = SSL_ALERT_CLOSE_MESSAGE;
        CPSi_TcpWrite2Raw(tmp, make_ciphertext(con, tmp), NULL, 0, soc);
    }

    con->state = SSL_STATE_INIT;
}

void CPSi_SslClose(CPSSoc *soc)
{
    CPSSslConnection *con = soc->con;
    con->state = SSL_STATE_INIT;
    if (con->inbuf != NULL) {
        CPSiFree(con->inbuf);
    }
    con->inbuf = NULL;
}

void CPS_SetSsl(BOOL mode)
{
    SDK_USING_MIDDLEWARE(id_string);

    CPSSoc *soc = CPS_CURSOC;
    if (soc != NULL) {
        soc->ssl = mode;
    }
}

void CPSi_SslPeriodical(u32 now)
{
    OSIntrMode enabled = OS_DisableInterrupts();
    for (int i = 0; i < MAX_SESSION; i++) {
        CPSSslSession *p = &session[i];
        if (p->valid && (int)(now - p->when) > CPS_MilliSecondsToLTicks(120000)) {
            p->valid = FALSE;
        }
    }
    OS_RestoreInterrupts(enabled);

    OSThread *t = OS_GetThreadList();
    while (t != NULL) {
        CPSSoc *soc = OSi_GetSpecificData(t, OSi_SPECIFIC_CPS);
        if (soc != NULL && soc->thread != NULL
            && soc->ssl && soc->state == CPS_STATE_ESTABLISHED && soc->con->state < SSL_STATE_ESTABLISHED
            && (int)(now - soc->when) > CPS_MilliSecondsToLTicks(30000) && soc->block_type == CPS_BLOCK_TCPREAD) {
            soc->state = CPS_STATE_CLOSED;
            soc->block_type = CPS_BLOCK_NONE;
            OS_WakeupThreadDirect(soc->thread);
        }
        t = OS_GetNextThread(t);
    }
}

void CPSi_SslCleanup(void)
{
    MI_CpuClear8(session, sizeof(session));
}
