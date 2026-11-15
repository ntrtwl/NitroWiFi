#include "nitroWiFi/ssl.h"

#include <nitro.h>

void CPSi_rc4_init(CPSRc4Ctx *ctx, u8 *key, int len)
{
    ctx->x = 0;
    ctx->y = 0;
    u8 *m = ctx->m;
    for (int i = 0; i < 256; i++) {
        m[i] = i;
    }

    u8 j, k;
    j = k = 0;
    for (int i = 0; i < 256; i++) {
        u8 m_i = m[i];
        j += m_i + key[k];
        m[i] = m[j];
        m[j] = m_i;
        if (++k >= len) {
            k = 0;
        }
    }
}

void CPSi_rc4_crypt(CPSRc4Ctx *ctx, u8 *data, int len)
{
    int i;

    u8 x = ctx->x;
    u8 y = ctx->y;
    u8 *m = ctx->m;
    for (i = 0; i < len; i++) {
        u8 m_x = m[++x];
        y += m_x;
        u8 m_y = m[y];
        m[x] = m_y;
        m[y] = m_x;
        data[i] ^= m[(m_x + m_y) & 255];
    }

    ctx->x = x;
    ctx->y = y;
}
