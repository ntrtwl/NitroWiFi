#include "nitroWiFi/ssl.h"

#include <limits.h>
#include <nitro.h>

#define BIGINT_SIGN_MASK (1 << 15)

#define BIGINT_BITS  (sizeof(u16) * 8)
#define BIGINT_SHIFT 4

#define BIGINT_MONT_SQUARE (u16 *)1

static int count_digits(u16 *a, int digits)
{
    while (digits != 0 && a[digits - 1] == 0) {
        digits--;
    }

    return digits;
}

int CPSi_big_sign(u16 *a, int digits)
{
    if ((a[digits - 1] & BIGINT_SIGN_MASK) != 0) {
        return -1;
    } else if (count_digits(a, digits) != 0) {
        return 1;
    } else {
        return 0;
    }
}

void CPSi_big_add(u16 *c, u16 *a, u16 *b, int digits)
{
    int i;

    int digits_a = count_digits(a, digits);
    int digits_b = count_digits(b, digits);
    if (digits_a < digits_b) {
        digits_a = digits_b;
    }
    if (digits_a != digits) {
        digits_a++;
    }

    int carry = 0;
    for (i = 0; i < digits_a; i++) {
        u32 tmp = a[i] + b[i] + carry;
        c[i] = tmp;
        carry = tmp >> BIGINT_BITS;
    }

    if (c != a && c != b) {
        MI_CpuClear8(c + i, (digits - i) * 2);
    }
}

static void CPSi_big_add_small(u16 *c, u16 *a, u16 _b, int digits)
{
    int i;
    u32 b = _b;

    for (i = 0; i < digits; i++) {
        u32 tmp = a[i] + b;
        c[i] = tmp;
        b = tmp >> BIGINT_BITS;
        if (b == 0) {
            break;
        }
    }

    if (c == a) {
        return;
    }

    for (++i; i < digits; i++) {
        c[i] = a[i];
    }
}

void CPSi_big_negate(u16 *a, int digits)
{
    for (int i = 0; i < digits; i++) {
        a[i] = ~a[i];
    }

    CPSi_big_add_small(a, a, 1, digits);
}

void CPSi_big_sub(u16 *c, u16 *a, u16 *b, int digits)
{
    int i;

    int digits_a = count_digits(a, digits);
    int digits_b = count_digits(b, digits);
    if (digits_a < digits_b) {
        digits_a = digits_b;
    }
    if (digits_a != digits) {
        digits_a++;
    }

    int borrow = 0;
    for (i = 0; i < digits_a || (i < digits && borrow != 0); i++) {
        int tmp = a[i] - b[i] + borrow;
        c[i] = tmp;
        borrow = tmp >> BIGINT_BITS;
    }

    if (c != a && c != b) {
        MI_CpuClear8(c + i, (digits - i) * 2);
    }
}

static void CPSi_big_sub_small(u16 *c, u16 *a, u16 _b, int digits)
{
    int i;
    u32 b = _b;

    for (i = 0; i < digits; i++) {
        u32 tmp = a[i] - b;
        c[i] = tmp;
        b = (tmp >> BIGINT_BITS) & 1;
        if (b == 0) {
            break;
        }
    }

    if (c == a) {
        return;
    }

    for (++i; i < digits; i++) {
        c[i] = a[i];
    }
}

static int CPSi_big_compare(u16 *a, u16 *b, int digits)
{
    for (int i = digits - 1; i >= 0; i--) {
        if (a[i] > b[i]) {
            return 1;
        }
        if (a[i] < b[i]) {
            return -1;
        }
    }

    return 0;
}

static void CPSi_big_add_part(u16 *a, u32 b, int i, int digits)
{
    for (; b != 0 && i < digits; i++) {
        u32 tmp = a[i] + b;
        a[i] = tmp;
        b = tmp >> BIGINT_BITS;
    }
}

void CPSi_big_mult(u16 *c, u16 *a, u16 *b, int digits)
{
    MI_CpuClear8(c, digits * 2);
    int digits_a = count_digits(a, digits);
    int digits_b = count_digits(b, digits);

    for (int i = 0; i < digits_b; i++) {
        for (int j = 0; j < digits_a && j < digits - i; j++) {
            CPSi_big_add_part(c, a[j] * b[i], i + j, digits);
        }
    }
}

static void CPSi_big_mult_small(u16 *c, u16 *a, u16 b, int digits)
{
    int i;

    int digits_a = count_digits(a, digits);

    u32 carry = 0;
    for (i = 0; i < digits_a; i++) {
        u32 tmp = a[i] * b + carry;
        c[i] = tmp;
        carry = tmp >> BIGINT_BITS;
    }

    if (i < digits) {
        c[i++] = carry;
    }

    MI_CpuClear8(c + i, (digits - i) * 2);
}

static void CPSi_big_sqr(u16 *c, u16 *a, int digits)
{
    int i;
    int j;
    u32 tmp;

    int digits_a = count_digits(a, digits);
    if (digits_a * 2 < digits) {
        MI_CpuClear8(c + digits_a * 2, (digits - digits_a * 2) * sizeof(u16));
    }

    for (i = 0; i < digits_a; i++) {
        j = i * 2;
        if (j >= digits) {
            break;
        }
        tmp = a[i] * a[i];
        c[j] = tmp;
        if (j == digits - 1) {
            break;
        }
        c[j + 1] = tmp >> BIGINT_BITS;
    }

    for (i = 0; i < digits_a; i++) {
        for (j = i + 1; j < digits_a && i + j < digits; j++) {
            tmp = a[j] * a[i];
            if (tmp <= (ULONG_MAX - USHRT_MAX) / 2) {
                CPSi_big_add_part(c, tmp * 2, i + j, digits);
            } else {
                CPSi_big_add_part(c, tmp, i + j, digits);
                CPSi_big_add_part(c, tmp, i + j, digits);
            }
        }
    }
}

static asm u64 get48bits_1(u16 *s)
{
    ldrh r1, [r0]
    mov r0, #0
    bx lr
}

static asm u64 get48bits_2(u16 *s)
{
    ldrh r1, [r0]
    ldrh r0, [r0, #-2]
    mov r0, r0, lsl #16
    bx lr
}

static asm u64 get48bits_3(u16 *s)
{
    ldrh r1, [r0]
    ldrh r2, [r0, #-2]
    ldrh r3, [r0, #-4]
    orr r0, r3, r2, lsl #16
    bx lr
}

static asm u64 get64bits(u16 *s)
{
    ldrh r2, [r0]
    ldrh r3, [r0, #-2]
    orr r1, r3, r2, lsl #16
    ldrh r2, [r0, #-4]
    ldrh r3, [r0, #-6]
    orr r0, r3, r2, lsl #16
    bx lr
}

void CPSi_big_div(u16 *c, u16 *a, u16 *b, u16 *r, int digits, u16 *work)
{
    int i;
    u64 msd;
    u32 guess;

    u16 *ca = work + digits;
    u16 *cca = ca + digits;
    MI_CpuClear8(ca, digits * 4);

    int digits_a = count_digits(a, digits);
    int digits_b = count_digits(b, digits);
    if (digits_a > 0 && digits_b > 0) {
        i = digits_b + (digits - digits_a) - 1;
        if (i >= digits) {
            MI_CpuCopy8(a, cca, digits * 2);
        } else {
            MI_CpuCopy8(a, ca + i, digits_a * 2);
            if (digits_b > 2) {
                msd = get48bits_3(b + digits_b - 1);
            } else if (digits_b > 1) {
                msd = get48bits_2(b + digits_b - 1);
            } else {
                msd = get48bits_1(b + digits_b - 1);
            }

            for (; i < digits; i++) {
                memmove(ca + 1, ca, (digits * 2 - 1) * 2);
                guess = get64bits(cca + digits_b) / msd;
                if (guess > USHRT_MAX) {
                    guess = USHRT_MAX;
                }

                while (TRUE) {
                    CPSi_big_mult_small(work, b, guess, digits);
                    if (CPSi_big_compare(cca, work, digits) >= 0) {
                        break;
                    }
                    guess--;
                }

                CPSi_big_sub(cca, cca, work, digits);
                *ca = guess;
            }
        }
    }

    if (c != NULL) {
        MI_CpuCopy8(ca, c, digits * 2);
    }
    if (r != NULL) {
        MI_CpuCopy8(cca, r, digits * 2);
    }
}

void CPSi_big_power(u16 *c, u16 *a, u16 *b, int digits, u16 *n)
{
    u16 *tmp = CPSiAlloc(digits * 8);
    if (tmp == NULL) {
        return;
    }

    u16 *divwork = tmp + digits;
    MI_CpuClear8(c + 1, (digits - 1) * 2);
    *c = 1;

    int i = (digits - count_digits(b, digits)) * BIGINT_BITS;
    for (; i < digits * BIGINT_BITS; i++) {
        if (b[digits - (i >> BIGINT_SHIFT) - 1] & (0x8000U >> (i % BIGINT_BITS))) {
            MI_CpuCopy8(a, c, digits * 2);
            i++;
            break;
        }
    }

    for (; i < digits * BIGINT_BITS; i++) {
        CPSi_big_sqr(tmp, c, digits);
        MI_CpuCopy8(tmp, c, digits * 2);
        if (n != NULL) {
            CPSi_big_div(NULL, c, n, c, digits, divwork);
        }
        if (b[digits - (i >> BIGINT_SHIFT) - 1] & (0x8000U >> (i % BIGINT_BITS))) {
            CPSi_big_mult(tmp, c, a, digits);
            MI_CpuCopy8(tmp, c, digits * 2);
            if (n != NULL) {
                CPSi_big_div(NULL, c, n, c, digits, divwork);
            }
        }
    }

    CPSiFree(tmp);
}

static void CPSi_big_modinv(u16 *c, u16 *a, u16 *n, int digits, u16 *tmp_var)
{
    u16 *q = tmp_var + digits;
    u16 *t = q + digits;
    u16 *u = t + digits;
    u16 *v = u + digits;
    u16 *w = v + digits;
    u16 *divwork = w + digits;

    MI_CpuCopy8(a, tmp_var, digits * 2);
    MI_CpuCopy8(n, t, digits * 2);
    *u = 1;

    while (CPSi_big_sign(tmp_var, digits) > 0) {
        CPSi_big_div(q, t, tmp_var, w, digits, divwork);
        MI_CpuCopy8(tmp_var, t, digits * 2);
        MI_CpuCopy8(w, tmp_var, digits * 2);
        CPSi_big_mult(w, q, u, digits);
        CPSi_big_sub(w, v, w, digits);
        MI_CpuCopy8(u, v, digits * 2);
        MI_CpuCopy8(w, u, digits * 2);
    }

    CPSi_big_add(v, v, n, digits);
    CPSi_big_div(NULL, v, n, c, digits, divwork);
}

static void CPSi_big_montmult(u16 *c, u16 *a, u16 *b, int digits, int rdigits, u16 *n, u16 *np, u16 *m, u16 *m2)
{
    MI_CpuCopy8(c, a, digits * 2);

    if (b == BIGINT_MONT_SQUARE) {
        CPSi_big_sqr(c, a, digits);
    } else if (b != NULL) {
        CPSi_big_mult(c, a, b, digits);
    }

    CPSi_big_mult(m, c, np, rdigits);
    MI_CpuClear8(m + rdigits, (digits - rdigits) * 2);
    CPSi_big_mult(m2, m, n, digits);
    CPSi_big_add(c, c, m2, digits);
    memmove(c, c + rdigits, (digits - rdigits) * 2);
    MI_CpuClear8(c + digits - rdigits, rdigits * 2);

    switch (CPSi_big_compare(c, n, digits)) {
    case 0:
        MI_CpuClear8(c, digits * 2);
        break;
    case 1:
        CPSi_big_sub(c, c, n, digits);
        break;
    }
}

void CPSi_big_montpower(u16 *c, u16 *m, u16 *e, int digits, u16 *n)
{
    int rdigits;
    int i;

    u16 *tmp_var = CPSiAlloc(digits * 22);
    if (tmp_var == NULL) {
        return;
    }
    MI_CpuClear8(tmp_var, digits * 22);

    u16 *ri = tmp_var + digits;
    u16 *mr = ri + digits;
    u16 *tmp = mr + digits;
    u16 *tmp2 = tmp + digits;
    u16 *tmp3 = tmp2 + digits;
    u16 *divwork = tmp3 + digits;

    rdigits = count_digits(n, digits);
    tmp_var[rdigits] = 1;

    CPSi_big_modinv(ri, tmp_var, n, digits, mr);
    CPSi_big_mult(tmp, tmp_var, ri, digits);
    CPSi_big_sub_small(ri, tmp, 1, digits);
    CPSi_big_div(ri, ri, n, NULL, digits, divwork);
    CPSi_big_mult(mr, m, tmp_var, digits);
    CPSi_big_div(NULL, mr, n, mr, digits, divwork);
    CPSi_big_div(NULL, tmp_var, n, c, digits, divwork);

    for (i = 0; i < rdigits * BIGINT_BITS; i++) {
        CPSi_big_montmult(c, tmp3, BIGINT_MONT_SQUARE, digits, rdigits, n, ri, tmp, tmp2);
        if (e[rdigits - (i >> BIGINT_SHIFT) - 1] & (0x8000U >> (i % BIGINT_BITS))) {
            CPSi_big_montmult(c, tmp3, mr, digits, rdigits, n, ri, tmp, tmp2);
        }
    }

    CPSi_big_montmult(c, tmp3, NULL, digits, rdigits, n, ri, tmp, tmp2);
    CPSiFree(tmp_var);
}

void CPSi_big_from_char(u16 *d, u8 *s, int numbytes, int digits)
{
    MI_CpuClear8(d, digits * 2);
    s += numbytes - 1;

    while (numbytes > 1) {
        *d++ = s[0] + (s[-1] << 8);
        s -= 2;
        numbytes -= 2;
    }

    if (numbytes > 0) {
        *d = *s;
    }
}

void CPSi_char_from_big(u8 *d, u16 *s, int numbytes, int digits)
{
    d += numbytes - 1;

    while (numbytes > 1) {
        *d-- = *s;
        *d-- = *s++ >> 8;
        numbytes -= 2;
    }

    if (numbytes > 0) {
        *d = *s;
    }
}
