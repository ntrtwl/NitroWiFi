#include "nitroWiFi/ssl.h"

#include <nitro.h>

static u8 padding[64] = { 0x80 };

static u8 itab[64] = {
    0, 1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14, 15,
    1, 6, 11, 0, 5, 10, 15, 4,
    9, 14, 3, 8, 13, 2, 7, 12,
    5, 8, 11, 14, 1, 4, 7, 10,
    13, 0, 3, 6, 9, 12, 15, 2,
    0, 7, 14, 5, 12, 3, 10, 1,
    8, 15, 6, 13, 4, 11, 2, 9
};

static u32 ktab[64] = {
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
};

static void char_from_long(u8 *d, u32 *s, u32 len)
{
    MI_CpuCopy8(s, d, len);
}

static void long_from_char(u32 *d, u8 *s, u32 len)
{
    MI_CpuCopy8(s, d, len);
}

#define ROTL(x, amt)      (((x) << (amt)) | ((x) >> (32 - (amt))))
#define FUNC_CH(b, c, d)  (d ^ (b & (c ^ d)))
#define FUNC_CH2(b, c, d) (c ^ (d & (b ^ c)))
#define FUNC_SUM(b, c, d) (b ^ c ^ d)
#define FUNC_R4(b, c, d)  (c ^ (b | ~d))

#define CalcRound1(a, b, c, d, x, i, s) (b + ROTL(FUNC_CH(b, c, d) + x[itab[i]] + ktab[i] + a, s));
#define CalcRound2(a, b, c, d, x, i, s) (b + ROTL(FUNC_CH2(b, c, d) + x[itab[i]] + ktab[i] + a, s));
#define CalcRound3(a, b, c, d, x, i, s) (b + ROTL(FUNC_SUM(b, c, d) + x[itab[i]] + ktab[i] + a, s));
#define CalcRound4(a, b, c, d, x, i, s) (b + ROTL(FUNC_R4(b, c, d) + x[itab[i]] + ktab[i] + a, s));

static void CPSi_md5_block(CPSMd5Ctx *ctx, u8 *m)
{
    u32 x[16];
    u32 a = ctx->state[0];
    u32 b = ctx->state[1];
    u32 c = ctx->state[2];
    u32 d = ctx->state[3];
    long_from_char(x, m, 64);
    int i = 0, j;

    for (j = 0; j < 4; j++) {
        a = CalcRound1(a, b, c, d, x, i, 7);
        i++;
        d = CalcRound1(d, a, b, c, x, i, 12);
        i++;
        c = CalcRound1(c, d, a, b, x, i, 17);
        i++;
        b = CalcRound1(b, c, d, a, x, i, 22);
        i++;
    }

    for (j = 0; j < 4; j++) {
        a = CalcRound2(a, b, c, d, x, i, 5);
        i++;
        d = CalcRound2(d, a, b, c, x, i, 9);
        i++;
        c = CalcRound2(c, d, a, b, x, i, 14);
        i++;
        b = CalcRound2(b, c, d, a, x, i, 20);
        i++;
    }

    for (j = 0; j < 4; j++) {
        a = CalcRound3(a, b, c, d, x, i, 4);
        i++;
        d = CalcRound3(d, a, b, c, x, i, 11);
        i++;
        c = CalcRound3(c, d, a, b, x, i, 16);
        i++;
        b = CalcRound3(b, c, d, a, x, i, 23);
        i++;
    }

    for (j = 0; j < 4; j++) {
        a = CalcRound4(a, b, c, d, x, i, 6);
        i++;
        d = CalcRound4(d, a, b, c, x, i, 10);
        i++;
        c = CalcRound4(c, d, a, b, x, i, 15);
        i++;
        b = CalcRound4(b, c, d, a, x, i, 21);
        i++;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
}

void CPSi_md5_init(CPSMd5Ctx *ctx)
{
    MI_CpuClear8(ctx, sizeof(CPSMd5Ctx));
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
}

void CPSi_md5_calc(CPSMd5Ctx *ctx, void *data0, u32 datalen)
{
    u32 i;

    u8 *data = data0;
    u32 index = (ctx->count[0] >> 3) & 63;

    ctx->count[0] += datalen << 3;
    if (ctx->count[0] < datalen << 3) {
        ctx->count[1] += 1;
    }

    ctx->count[1] += datalen >> 29;

    u32 room = 64 - index;
    if (datalen >= room) {
        MI_CpuCopy8(data, &ctx->buffer[index], room);
        index = 0;
        CPSi_md5_block(ctx, ctx->buffer);
        i = room;
        while (i + 63 < datalen) {
            CPSi_md5_block(ctx, data + i);
            i += 64;
        }
    } else {
        i = 0;
    }

    MI_CpuCopy8(data + i, &ctx->buffer[index], datalen - i);
}

void CPSi_md5_result(CPSMd5Ctx *ctx, u8 *digest)
{
    char_from_long(digest, &ctx->count[0], 8);
    int index = (ctx->count[0] >> 3) & 63;
    CPSi_md5_calc(ctx, padding, index < 56 ? 56 - index : 120 - index);
    CPSi_md5_calc(ctx, digest, 8);
    char_from_long(digest, &ctx->state[0], MD5_HASH_SIZE);
}
