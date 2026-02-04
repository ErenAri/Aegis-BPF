// cppcheck-suppress-file missingIncludeSystem
/*
 * TweetNaCl - A self-contained public-domain crypto library
 * Upstream reference: TweetNaCl 20140917
 * Source: https://tweetnacl.cr.yp.to/
 *
 * Slightly modified for AegisBPF:
 * - Added detached signature functions
 * - Uses /dev/urandom for randomness
 * - UBSan-safe carry math in modL
 *
 * Public domain.
 */

#include "tweetnacl.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef int64_t i64;
typedef unsigned long long u64;
typedef uint8_t u8;

static const u8 _0[16] = {0};
static const u8 _9[32] = {9};
static const i64 gf0[16] = {0};
static const i64 gf1[16] = {1};
static const i64 _121665[16] = {0xDB41, 1};
static const i64 D[16] = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
                          0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203};
static const i64 D2[16] = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
                           0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406};
static const i64 X[16] = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
                          0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169};
static const i64 Y[16] = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                          0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};
static const i64 I[16] = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
                          0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

static u64 L64(u64 x, int c) { return (x << c) | ((x & 0xffffffffffffffffULL) >> (64 - c)); }
static u64 ld32(const u8* x) { return (u64)x[0] | ((u64)x[1] << 8) | ((u64)x[2] << 16) | ((u64)x[3] << 24); }
static u64 dl64(const u8* x)
{
    u64 u = 0;
    for (int i = 0; i < 8; ++i) u = (u << 8) | x[i];
    return u;
}

static void st32(u8* x, u64 u)
{
    for (int i = 0; i < 4; ++i) {
        x[i] = u;
        u >>= 8;
    }
}

static void ts64(u8* x, u64 u)
{
    for (int i = 7; i >= 0; --i) {
        x[i] = u;
        u >>= 8;
    }
}

static int vn(const u8* x, const u8* y, int n)
{
    u64 d = 0;
    for (int i = 0; i < n; ++i) d |= x[i] ^ y[i];
    return (1 & ((d - 1) >> 8)) - 1;
}

static int crypto_verify_32(const u8* x, const u8* y) { return vn(x, y, 32); }

// cppcheck-suppress unusedFunction
static void core(u8* out, const u8* in, const u8* k, const u8* c, int h)
{
    u64 w[16], x[16], y[16], t[4];
    for (int i = 0; i < 4; ++i) {
        x[5 * i] = ld32(c + 4 * i);
        x[1 + i] = ld32(k + 4 * i);
        x[6 + i] = ld32(in + 4 * i);
        x[11 + i] = ld32(k + 16 + 4 * i);
    }
    for (int i = 0; i < 16; ++i) y[i] = x[i];
    for (int i = 0; i < 20; ++i) {
        for (int j = 0; j < 4; ++j) {
            for (int m = 0; m < 4; ++m) t[m] = x[(5 * j + 4 * m) % 16];
            t[1] ^= L64(t[0] + t[3], 7);
            t[2] ^= L64(t[1] + t[0], 9);
            t[3] ^= L64(t[2] + t[1], 13);
            t[0] ^= L64(t[3] + t[2], 18);
            for (int m = 0; m < 4; ++m) w[4 * j + (j + m) % 4] = t[m];
        }
        for (int m = 0; m < 16; ++m) x[m] = w[m];
    }
    if (h) {
        for (int i = 0; i < 16; ++i) x[i] += y[i];
        for (int i = 0; i < 4; ++i) {
            x[5 * i] -= ld32(c + 4 * i);
            x[6 + i] -= ld32(in + 4 * i);
        }
        for (int i = 0; i < 4; ++i) {
            st32(out + 4 * i, x[5 * i]);
            st32(out + 16 + 4 * i, x[6 + i]);
        }
    }
    else {
        for (int i = 0; i < 16; ++i) st32(out + 4 * i, x[i] + y[i]);
    }
}

static const u8 sigma[16] = "expand 32-byte k";

static void set25519(i64* r, const i64* a)
{
    for (int i = 0; i < 16; ++i) r[i] = a[i];
}
static void car25519(i64* o)
{
    for (int i = 0; i < 16; ++i) {
        o[(i + 1) % 16] += (i < 15 ? 1 : 38) * (o[i] >> 16);
        o[i] &= 0xffff;
    }
}
static void sel25519(i64* p, i64* q, int b)
{
    i64 c = ~(b - 1);
    for (int i = 0; i < 16; ++i) {
        i64 t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}
static void pack25519(u8* o, const i64* n)
{
    i64 m[16], t[16];
    for (int i = 0; i < 16; ++i) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; ++i) {
        o[2 * i] = t[i] & 0xff;
        o[2 * i + 1] = t[i] >> 8;
    }
}

static int neq25519(const i64* a, const i64* b)
{
    u8 c[32], d[32];
    pack25519(c, a);
    pack25519(d, b);
    return crypto_verify_32(c, d);
}

static u8 par25519(const i64* a)
{
    u8 d[32];
    pack25519(d, a);
    return d[0] & 1;
}

static void unpack25519(i64* o, const u8* n)
{
    for (int i = 0; i < 16; ++i) o[i] = n[2 * i] + ((i64)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void A(i64* o, const i64* a, const i64* b)
{
    for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}
static void Z(i64* o, const i64* a, const i64* b)
{
    for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}
static void M(i64* o, const i64* a, const i64* b)
{
    i64 t[31];
    for (int i = 0; i < 31; ++i) t[i] = 0;
    for (int i = 0; i < 16; ++i)
        for (int j = 0; j < 16; ++j) t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; ++i) o[i] = t[i];
    car25519(o);
    car25519(o);
}
static void S(i64* o, const i64* a) { M(o, a, a); }

static void inv25519(i64* o, const i64* i)
{
    i64 c[16];
    for (int a = 0; a < 16; ++a) c[a] = i[a];
    for (int a = 253; a >= 0; --a) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    for (int a = 0; a < 16; ++a) o[a] = c[a];
}

static void pow2523(i64* o, const i64* i)
{
    i64 c[16];
    for (int a = 0; a < 16; ++a) c[a] = i[a];
    for (int a = 250; a >= 0; --a) {
        S(c, c);
        if (a != 1) M(c, c, i);
    }
    for (int a = 0; a < 16; ++a) o[a] = c[a];
}

static u64 K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

int crypto_hash(u8* out, const u8* m, u64 n)
{
    u8 h[64], x[256];
    u64 b = n;

    static const u64 iv[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

    for (int i = 0; i < 8; ++i) ts64(h + 8 * i, iv[i]);

    while (n >= 128) {
        u64 a[8], w[80];
        for (int i = 0; i < 8; ++i) a[i] = dl64(h + 8 * i);
        for (int i = 0; i < 16; ++i) w[i] = dl64(m + 8 * i);
        for (int i = 16; i < 80; ++i) {
            u64 s0 = L64(w[i - 15], 63) ^ L64(w[i - 15], 56) ^ (w[i - 15] >> 7);
            u64 s1 = L64(w[i - 2], 45) ^ L64(w[i - 2], 3) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        for (int i = 0; i < 80; ++i) {
            u64 S1 = L64(a[4], 50) ^ L64(a[4], 46) ^ L64(a[4], 23);
            u64 ch = (a[4] & a[5]) ^ (~a[4] & a[6]);
            u64 t1 = a[7] + S1 + ch + K[i] + w[i];
            u64 S0 = L64(a[0], 36) ^ L64(a[0], 30) ^ L64(a[0], 25);
            u64 maj = (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
            u64 t2 = S0 + maj;
            a[7] = a[6];
            a[6] = a[5];
            a[5] = a[4];
            a[4] = a[3] + t1;
            a[3] = a[2];
            a[2] = a[1];
            a[1] = a[0];
            a[0] = t1 + t2;
        }
        for (int i = 0; i < 8; ++i) {
            a[i] += dl64(h + 8 * i);
            ts64(h + 8 * i, a[i]);
        }
        m += 128;
        n -= 128;
    }

    for (int i = 0; i < 256; ++i) x[i] = 0;
    for (u64 i = 0; i < n; ++i) x[i] = m[i];
    x[n] = 128;
    n = 256 - 128 * (n < 112);
    x[n - 9] = b >> 61;
    // cppcheck-suppress pointerOutOfBoundsCond
    ts64(x + n - 8, b << 3);

    const u8* x_ptr = x;
    while (n > 0) {
        u64 a[8], w[80];
        for (int i = 0; i < 8; ++i) a[i] = dl64(h + 8 * i);
        for (int i = 0; i < 16; ++i) w[i] = dl64(x_ptr + 8 * i);
        for (int i = 16; i < 80; ++i) {
            u64 s0 = L64(w[i - 15], 63) ^ L64(w[i - 15], 56) ^ (w[i - 15] >> 7);
            u64 s1 = L64(w[i - 2], 45) ^ L64(w[i - 2], 3) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        for (int i = 0; i < 80; ++i) {
            u64 S1 = L64(a[4], 50) ^ L64(a[4], 46) ^ L64(a[4], 23);
            u64 ch = (a[4] & a[5]) ^ (~a[4] & a[6]);
            u64 t1 = a[7] + S1 + ch + K[i] + w[i];
            u64 S0 = L64(a[0], 36) ^ L64(a[0], 30) ^ L64(a[0], 25);
            u64 maj = (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
            u64 t2 = S0 + maj;
            a[7] = a[6];
            a[6] = a[5];
            a[5] = a[4];
            a[4] = a[3] + t1;
            a[3] = a[2];
            a[2] = a[1];
            a[1] = a[0];
            a[0] = t1 + t2;
        }
        for (int i = 0; i < 8; ++i) {
            a[i] += dl64(h + 8 * i);
            ts64(h + 8 * i, a[i]);
        }
        x_ptr += 128;
        n -= 128;
    }

    for (int i = 0; i < 64; ++i) out[i] = h[i];
    return 0;
}

static void add(i64 p[4][16], i64 q[4][16])
{
    i64 a[16], b[16], c[16], d[16], t[16], e[16], f[16], g[16], h[16];
    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);
    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}

static void cswap(i64 p[4][16], i64 q[4][16], u8 b)
{
    for (int i = 0; i < 4; ++i) sel25519(p[i], q[i], b);
}

static void pack(u8* r, i64 p[4][16])
{
    i64 tx[16], ty[16], zi[16];
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= par25519(tx) << 7;
}

static void scalarmult(i64 p[4][16], i64 q[4][16], const u8* s)
{
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);
    for (int i = 255; i >= 0; --i) {
        u8 b = (s[i / 8] >> (i & 7)) & 1;
        cswap(p, q, b);
        add(q, p);
        add(p, p);
        cswap(p, q, b);
    }
}

static void scalarbase(i64 p[4][16], const u8* s)
{
    i64 q[4][16];
    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    M(q[3], X, Y);
    scalarmult(p, q, s);
}

static const u64 L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                          0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

static void modL(u8* r, i64 x[64])
{
    for (int i = 63; i >= 32; --i) {
        i64 carry = 0;
        for (int j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;
        }
        x[i - 12] += carry;
        x[i] = 0;
    }
    i64 carry = 0;
    for (int j = 0; j < 32; ++j) {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (int j = 0; j < 32; ++j) x[j] -= carry * L[j];
    for (int i = 0; i < 32; ++i) {
        x[i + 1] += x[i] >> 8;
        r[i] = x[i] & 255;
    }
}

static void reduce(u8* r)
{
    i64 x[64];
    for (int i = 0; i < 64; ++i) x[i] = (u64)r[i];
    for (int i = 0; i < 64; ++i) r[i] = 0;
    modL(r, x);
}

void randombytes(u8* x, u64 xlen)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return;
    while (xlen > 0) {
        ssize_t n = read(fd, x, xlen);
        if (n <= 0) break;
        x += n;
        xlen -= n;
    }
    close(fd);
}

int crypto_sign_keypair(u8* pk, u8* sk)
{
    u8 d[64];
    i64 p[4][16];
    randombytes(sk, 32);
    crypto_hash(d, sk, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    scalarbase(p, d);
    pack(pk, p);
    for (int i = 0; i < 32; ++i) sk[32 + i] = pk[i];
    return 0;
}

int crypto_sign(u8* sm, u64* smlen, const u8* m, u64 n, const u8* sk)
{
    u8 d[64], h[64], r[64];
    i64 x[64];
    i64 p[4][16];
    crypto_hash(d, sk, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    *smlen = n + 64;
    for (u64 i = 0; i < n; ++i) sm[64 + i] = m[i];
    for (int i = 0; i < 32; ++i) sm[32 + i] = d[32 + i];
    crypto_hash(r, sm + 32, n + 32);
    reduce(r);
    scalarbase(p, r);
    pack(sm, p);
    for (int i = 0; i < 32; ++i) sm[i + 32] = sk[i + 32];
    crypto_hash(h, sm, n + 64);
    reduce(h);
    for (int i = 0; i < 64; ++i) x[i] = 0;
    for (int i = 0; i < 32; ++i) x[i] = (u64)r[i];
    for (int i = 0; i < 32; ++i)
        for (int j = 0; j < 32; ++j) x[i + j] += h[i] * (u64)d[j];
    modL(sm + 32, x);
    return 0;
}

static int unpackneg(i64 r[4][16], const u8 p[32])
{
    i64 t[16], chk[16], num[16], den[16], den2[16], den4[16], den6[16];
    set25519(r[2], gf1);
    unpack25519(r[1], p);
    S(num, r[1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);
    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);
    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);
    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) M(r[0], r[0], I);
    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) return -1;
    if (par25519(r[0]) == (p[31] >> 7)) Z(r[0], gf0, r[0]);
    M(r[3], r[0], r[1]);
    return 0;
}

int crypto_sign_open(u8* m, u64* mlen, const u8* sm, u64 n, const u8* pk)
{
    u8 t[32], h[64];
    i64 p[4][16], q[4][16];
    *mlen = (u64)-1;
    if (n < 64) return -1;
    if (unpackneg(q, pk)) return -1;
    for (u64 i = 0; i < n; ++i) m[i] = sm[i];
    for (int i = 0; i < 32; ++i) m[i + 32] = pk[i];
    crypto_hash(h, m, n);
    reduce(h);
    scalarmult(p, q, h);
    scalarbase(q, sm + 32);
    add(p, q);
    pack(t, p);
    n -= 64;
    if (crypto_verify_32(sm, t)) {
        for (u64 i = 0; i < n; ++i) m[i] = 0;
        return -1;
    }
    for (u64 i = 0; i < n; ++i) m[i] = sm[i + 64];
    *mlen = n;
    return 0;
}

int crypto_sign_detached(u8* sig, const u8* m, unsigned long long mlen, const u8* sk)
{
    u8* sm = (u8*)malloc(mlen + 64);
    if (!sm) return -1;
    u64 smlen;
    int rc = crypto_sign(sm, &smlen, m, mlen, sk);
    // cppcheck-suppress knownConditionTrueFalse
    if (rc == 0) {
        memcpy(sig, sm, 64);
    }
    free(sm);
    return rc;
}

int crypto_sign_verify_detached(const u8* sig, const u8* m, unsigned long long mlen, const u8* pk)
{
    u8* sm = (u8*)malloc(mlen + 64);
    if (!sm) return -1;
    u8* tmp = (u8*)malloc(mlen + 64);
    if (!tmp) {
        free(sm);
        return -1;
    }
    memcpy(sm, sig, 64);
    memcpy(sm + 64, m, mlen);
    u64 tmplen;
    int rc = crypto_sign_open(tmp, &tmplen, sm, mlen + 64, pk);
    free(sm);
    free(tmp);
    return rc;
}
