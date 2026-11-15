#include "nitroWiFi/ssl.h"

#include <nitro.h>

static u8 padding[64] = { 0x80 };

#define ROTL(x, amt) (((x) << (amt)) | ((x) >> (32 - (amt))))

static u32 R(int t, u32 *w)
{
    u32 temp = w[t] ^ (w[(t + 2) & 0xF] ^ (w[(t + 13) & 0xF] ^ w[t ^ 8]));
    w[t] = ROTL(temp, 1);
    return w[t];
}

static void char_from_long(u8 *d, u32 *s, u32 len)
{
    len /= 4;

    for (int i = 0; i < len; i++) {
        u32 j = *s++;
        *d++ = j >> 24;
        *d++ = j >> 16;
        *d++ = j >> 8;
        *d++ = j;
    }
}

static void long_from_char(u32 *d, u8 *s, u32 len)
{
    for (int i = 0; i < len; i += 4) {
        *d++ = (s[i] << 24) | (s[i + 1] << 16) | (s[i + 2] << 8) | s[i + 3];
    }
}

#define FUNC_CH(b, c, d)  (d ^ (b & (c ^ d)))
#define FUNC_SUM(b, c, d) (b ^ c ^ d)
#define FUNC_MAJ(b, c, d) ((b & (c | d)) | (c & d))

#define CalcRound1(a, b, c, d, e, w) (ROTL(a, 5) + FUNC_CH(b, c, d) + w + 0x5A827999 + e)
#define CalcRound2(a, b, c, d, e, w) (ROTL(a, 5) + FUNC_SUM(b, c, d) + w + 0x6ED9EBA1 + e)
#define CalcRound3(a, b, c, d, e, w) (ROTL(a, 5) + FUNC_MAJ(b, c, d) + w + 0x8F1BBCDC + e)
#define CalcRound4(a, b, c, d, e, w) (ROTL(a, 5) + FUNC_SUM(b, c, d) + w + 0xCA62C1D6 + e)

static void CPSi_sha1_block(CPSSha1Ctx *ctx, u8 *m)
{
    u32 w[16];
    u32 a;
    u32 b;
    u32 c;
    u32 d;
    u32 e;
    int i, j;

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    long_from_char(w, m, 0x40);
    i = 0;
    for (j = 0; j < 3; j++) {
        e = CalcRound1(a, b, c, d, e, w[i]);
        b = ROTL(b, 30);
        i++;
        d = CalcRound1(e, a, b, c, d, w[i]);
        a = ROTL(a, 30);
        i++;
        c = CalcRound1(d, e, a, b, c, w[i]);
        e = ROTL(e, 30);
        i++;
        b = CalcRound1(c, d, e, a, b, w[i]);
        d = ROTL(d, 30);
        i++;
        a = CalcRound1(b, c, d, e, a, w[i]);
        c = ROTL(c, 30);
        i++;
    }

    e = CalcRound1(a, b, c, d, e, w[15]);
    b = ROTL(b, 30);
    d = CalcRound1(e, a, b, c, d, R(0, w));
    a = ROTL(a, 30);
    c = CalcRound1(d, e, a, b, c, R(1, w));
    e = ROTL(e, 30);
    b = CalcRound1(c, d, e, a, b, R(2, w));
    d = ROTL(d, 30);
    a = CalcRound1(b, c, d, e, a, R(3, w));
    c = ROTL(c, 30);
    i = 4;

    for (j = 0; j < 4; j++) {
        e = CalcRound2(a, b, c, d, e, R(i, w));
        b = ROTL(b, 30);
        i++;
        d = CalcRound2(e, a, b, c, d, R(i, w));
        a = ROTL(a, 30);
        i = (i + 1) & 0xF;
        c = CalcRound2(d, e, a, b, c, R(i, w));
        e = ROTL(e, 30);
        i++;
        b = CalcRound2(c, d, e, a, b, R(i, w));
        d = ROTL(d, 30);
        i++;
        a = CalcRound2(b, c, d, e, a, R(i, w));
        c = ROTL(c, 30);
        i++;
    }

    for (j = 0; j < 4; j++) {
        e = CalcRound3(a, b, c, d, e, R(i, w));
        b = ROTL(b, 30);
        i++;
        d = CalcRound3(e, a, b, c, d, R(i, w));
        a = ROTL(a, 30);
        i++;
        c = CalcRound3(d, e, a, b, c, R(i, w));
        e = ROTL(e, 30);
        i = (i + 1) & 0xF;
        b = CalcRound3(c, d, e, a, b, R(i, w));
        d = ROTL(d, 30);
        i++;
        a = CalcRound3(b, c, d, e, a, R(i, w));
        c = ROTL(c, 30);
        i++;
    }

    for (j = 0; j < 4; j++) {
        e = CalcRound4(a, b, c, d, e, R(i, w));
        b = ROTL(b, 30);
        i++;
        d = CalcRound4(e, a, b, c, d, R(i, w));
        a = ROTL(a, 30);
        i++;
        c = CalcRound4(d, e, a, b, c, R(i, w));
        e = ROTL(e, 30);
        i++;
        b = CalcRound4(c, d, e, a, b, R(i, w));
        d = ROTL(d, 30);
        i = (i + 1) & 0xF;
        a = CalcRound4(b, c, d, e, a, R(i, w));
        c = ROTL(c, 30);
        i++;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void CPSi_sha1_init(CPSSha1Ctx *ctx)
{
    MI_CpuClear8(ctx, sizeof(CPSSha1Ctx));
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
}

void CPSi_sha1_calc(CPSSha1Ctx *ctx, void *data0, u32 datalen)
{
    u32 i;

    u8 *data = data0;
    u32 index = (ctx->count[1] >> 3) & 63;

    ctx->count[1] += datalen << 3;
    if (ctx->count[1] < datalen << 3) {
        ctx->count[0] += 1;
    }

    ctx->count[0] += datalen >> 29;

    u32 room = 64 - index;
    if (datalen >= room) {
        MI_CpuCopy8(data, &ctx->buffer[index], room);
        index = 0;
        CPSi_sha1_block(ctx, ctx->buffer);
        i = room;
        while (i + 63 < datalen) {
            CPSi_sha1_block(ctx, data + i);
            i += 64;
        }
    } else {
        i = 0;
    }

    MI_CpuCopy8(data + i, &ctx->buffer[index], datalen - i);
}

void CPSi_sha1_result(CPSSha1Ctx *ctx, u8 *digest)
{
    char_from_long(digest, &ctx->count[0], 8);
    int index = (ctx->count[1] >> 3) & 63;
    CPSi_sha1_calc(ctx, padding, index < 56 ? 56 - index : 120 - index);
    CPSi_sha1_calc(ctx, digest, 8);
    char_from_long(digest, &ctx->state[0], SHA1_HASH_SIZE);
}

void CPSi_sha1_result_prng(CPSSha1Ctx *ctx, u8 *digest)
{
    CPSi_sha1_calc(ctx, padding + 1, 44);
    char_from_long(digest, &ctx->state[0], SHA1_HASH_SIZE);
}
