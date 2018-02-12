// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Modified for CPUminer by Lucas Jones

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/mman.h>
#endif
#include "crypto/oaes_lib.h"
#include "crypto/c_keccak.h"
#include "crypto/c_groestl.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
#include "crypto/int-util.h"
#include "crypto/hash-ops.h"

#undef unlikely
#undef likely
#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))
#else
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#endif

#if USE_INT128

#if __GNUC__ == 4 && __GNUC_MINOR__ >= 4 && __GNUC_MINOR__ < 6
typedef unsigned int uint128_t __attribute__ ((__mode__ (TI)));
#else
typedef __uint128_t uint128_t;
#endif

#endif

#define MEMORY         (1 << 21) /* 2 MiB */
#define ITER           (1 << 20)
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32 /*16*/
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE)

#define VARIANT1_1(p, o) \
  do if (variant > 0) \
  { \
    uint8_t tmp = ((const uint8_t*)(&p[o]))[11]; \
    uint8_t tmp1 = (tmp>>4)&1, tmp2 = (tmp>>5)&1, tmp3 = tmp1^tmp2; \
    uint8_t tmp0 = nonce_flag ? tmp3 : tmp1 + 1; \
    ((uint8_t*)(&p[o]))[11] = (tmp & 0xef) | (tmp0<<4); \
  } while(0)

#define VARIANT1_2(p, o) VARIANT1_1(p, o)

#define VARIANT1_INIT() \
  if (variant > 0 && inlen < 43) \
  { \
    fprintf(stderr, "Cryptonight variants need at least 43 bytes of data"); \
    _exit(1); \
  } \
  const uint8_t nonce_flag = variant > 0 ? ((const uint8_t*)input)[39] & 0x01 : 0

#pragma pack(push, 1)
union cn_slow_hash_state {
	union hash_state hs;
	struct {
		uint8_t k[64];
		uint8_t init[INIT_SIZE_BYTE];
	};
};
#pragma pack(pop)

static void do_blake_hash(const void* input, size_t len, char* output) {
	blake256_hash((uint8_t*)output, input, len);
}

void do_groestl_hash(const void* input, size_t len, char* output) {
	groestl(input, len * 8, (uint8_t*)output);
}

static void do_jh_hash(const void* input, size_t len, char* output) {
	int r = jh_hash(HASH_SIZE * 8, input, 8 * len, (uint8_t*)output);
	assert((SUCCESS == r));
}

static void do_skein_hash(const void* input, size_t len, char* output) {
	int r = skein_hash(8 * HASH_SIZE, input, 8 * len, (uint8_t*)output);
	assert((SKEIN_SUCCESS == r));
}

static void (* const extra_hashes[4])(const void *, size_t, char *) = {
	do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash
};

#ifdef __x86_64__
extern int aesb_single_round(const uint8_t *in, uint8_t*out, const uint8_t *expandedKey);
extern int aesb_pseudo_round_mut(uint8_t *val, uint8_t *expandedKey);

// Credit to Wolf for optimizing this function
static inline size_t e2i(const uint8_t* a) {
	return ((uint32_t *)a)[0] & 0x1FFFF0;
}

static inline void mul_sum_xor_dst(const uint8_t* a, uint8_t* c, uint8_t* dst) {
	uint64_t hi, lo;
#ifdef __amd64
	__asm__("mul %%rdx":
	"=a" (lo), "=d" (hi):
	"a" (*(uint64_t *)a), "d" (*(uint64_t *)dst));
#else
	lo = mul128(((uint64_t*) a)[0], ((uint64_t*) dst)[0], &hi);
#endif
	lo += ((uint64_t*) c)[1];
	hi += ((uint64_t*) c)[0];

	((uint64_t*) c)[0] = ((uint64_t*) dst)[0] ^ hi;
	((uint64_t*) c)[1] = ((uint64_t*) dst)[1] ^ lo;
	((uint64_t*) dst)[0] = hi;
	((uint64_t*) dst)[1] = lo;
}

static inline void xor_blocks(uint8_t* a, const uint8_t* b) {
#if USE_INT128
	*((uint128_t*) a) ^= *((uint128_t*) b);
#else
	((uint64_t*) a)[0] ^= ((uint64_t*) b)[0];
	((uint64_t*) a)[1] ^= ((uint64_t*) b)[1];
#endif
}

static inline void xor_blocks_dst(const uint8_t* a, const uint8_t* b, uint8_t* dst) {
#if USE_INT128
	*((uint128_t*) dst) = *((uint128_t*) a) ^ *((uint128_t*) b);
#else
	((uint64_t*) dst)[0] = ((uint64_t*) a)[0] ^ ((uint64_t*) b)[0];
	((uint64_t*) dst)[1] = ((uint64_t*) a)[1] ^ ((uint64_t*) b)[1];
#endif
}
#endif /* __x86_64__ */

struct cryptonight_ctx {
	uint8_t long_state[MEMORY] __attribute((aligned(16)));
	union cn_slow_hash_state state;
	uint8_t text[INIT_SIZE_BYTE] __attribute((aligned(16)));
	uint8_t a[AES_BLOCK_SIZE] __attribute__((aligned(16)));
	uint8_t b[AES_BLOCK_SIZE] __attribute__((aligned(16)));
	uint8_t c[AES_BLOCK_SIZE] __attribute__((aligned(16)));
	oaes_ctx* aes_ctx;
};

struct cryptonight_aesni_ctx {
    uint8_t long_state[MEMORY] __attribute((aligned(16)));
    union cn_slow_hash_state state;
    uint8_t text[INIT_SIZE_BYTE] __attribute((aligned(16)));
    uint64_t a[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));
    uint64_t b[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));
    uint8_t c[AES_BLOCK_SIZE] __attribute__((aligned(16)));
    oaes_ctx* aes_ctx;
};

#ifdef __x86_64__
void cryptonight_hash_dumb(void* output, const void* input, const uint32_t inlen, struct cryptonight_ctx* ctx, int variant) {
	size_t i, j;
	keccak1600(input, inlen, (uint8_t *)&ctx->state.hs);
	if (!ctx->aes_ctx)
		ctx->aes_ctx = (oaes_ctx*) oaes_alloc();
	memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
	
	VARIANT1_INIT();

	oaes_key_import_data(ctx->aes_ctx, ctx->state.hs.b, AES_KEY_SIZE);
	for (i = 0; (i < MEMORY); i += INIT_SIZE_BYTE) {
		aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * 0], ctx->aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * 1], ctx->aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * 2], ctx->aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * 3], ctx->aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * 4], ctx->aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * 5], ctx->aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * 6], ctx->aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx->text[AES_BLOCK_SIZE * 7], ctx->aes_ctx->key->exp_data);
		memcpy(&ctx->long_state[i], ctx->text, INIT_SIZE_BYTE);
	}
	
	xor_blocks_dst(&ctx->state.k[0], &ctx->state.k[32], ctx->a);
	xor_blocks_dst(&ctx->state.k[16], &ctx->state.k[48], ctx->b);

	for (i = 0; (i < ITER / 4); ++i) {
		/* Dependency chain: address -> read value ------+
		 * written value <-+ hard function (AES or MUL) <+
		 * next address  <-+
		 */
		/* Iteration 1 */
		j = e2i(ctx->a);
		aesb_single_round(&ctx->long_state[j], ctx->c, ctx->a);
		xor_blocks_dst(ctx->c, ctx->b, &ctx->long_state[j]);
		VARIANT1_1(ctx->long_state, j);
		/* Iteration 2 */
		mul_sum_xor_dst(ctx->c, ctx->a, &ctx->long_state[e2i(ctx->c)]);
		VARIANT1_2(ctx->long_state, e2i(ctx->c));
		/* Iteration 3 */
		j = e2i(ctx->a);
		aesb_single_round(&ctx->long_state[j], ctx->b, ctx->a);
		xor_blocks_dst(ctx->b, ctx->c, &ctx->long_state[j]);
		VARIANT1_1(ctx->long_state, j);
		/* Iteration 4 */
		mul_sum_xor_dst(ctx->b, ctx->a, &ctx->long_state[e2i(ctx->b)]);
		VARIANT1_2(ctx->long_state, e2i(ctx->b));
	}

	memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
	oaes_key_import_data(ctx->aes_ctx, &ctx->state.hs.b[32], AES_KEY_SIZE);
	for (i = 0; (i < MEMORY); i += INIT_SIZE_BYTE) {
		xor_blocks(&ctx->text[0 * AES_BLOCK_SIZE], &ctx->long_state[i + 0 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx->text[0 * AES_BLOCK_SIZE], ctx->aes_ctx->key->exp_data);
		xor_blocks(&ctx->text[1 * AES_BLOCK_SIZE], &ctx->long_state[i + 1 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx->text[1 * AES_BLOCK_SIZE], ctx->aes_ctx->key->exp_data);
		xor_blocks(&ctx->text[2 * AES_BLOCK_SIZE], &ctx->long_state[i + 2 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx->text[2 * AES_BLOCK_SIZE], ctx->aes_ctx->key->exp_data);
		xor_blocks(&ctx->text[3 * AES_BLOCK_SIZE], &ctx->long_state[i + 3 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx->text[3 * AES_BLOCK_SIZE], ctx->aes_ctx->key->exp_data);
		xor_blocks(&ctx->text[4 * AES_BLOCK_SIZE], &ctx->long_state[i + 4 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx->text[4 * AES_BLOCK_SIZE], ctx->aes_ctx->key->exp_data);
		xor_blocks(&ctx->text[5 * AES_BLOCK_SIZE], &ctx->long_state[i + 5 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx->text[5 * AES_BLOCK_SIZE], ctx->aes_ctx->key->exp_data);
		xor_blocks(&ctx->text[6 * AES_BLOCK_SIZE], &ctx->long_state[i + 6 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx->text[6 * AES_BLOCK_SIZE], ctx->aes_ctx->key->exp_data);
		xor_blocks(&ctx->text[7 * AES_BLOCK_SIZE], &ctx->long_state[i + 7 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx->text[7 * AES_BLOCK_SIZE], ctx->aes_ctx->key->exp_data);
	}
	memcpy(ctx->state.init, ctx->text, INIT_SIZE_BYTE);
	keccakf((uint64_t*)(&ctx->state.hs), 24);
	/*memcpy(hash, &state, 32);*/	
	//if((ctx->state.hs.b[0] & 3) == 1) exit(0);
	extra_hashes[ctx->state.hs.b[0] & 3](&ctx->state, 200, output);
	//memcpy(output, ctx->state.hs.b, 32);
}
#endif

#ifdef __x86_64__

#include <x86intrin.h>

static inline void ExpandAESKey256_sub1(__m128i *tmp1, __m128i *tmp2)
{
	__m128i tmp4;
	*tmp2 = _mm_shuffle_epi32(*tmp2, 0xFF);
	tmp4 = _mm_slli_si128(*tmp1, 0x04);
	*tmp1 = _mm_xor_si128(*tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp1 = _mm_xor_si128(*tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp1 = _mm_xor_si128(*tmp1, tmp4);
	*tmp1 = _mm_xor_si128(*tmp1, *tmp2);
}

static inline void ExpandAESKey256_sub2(__m128i *tmp1, __m128i *tmp3)
{
	__m128i tmp2, tmp4;

	tmp4 = _mm_aeskeygenassist_si128(*tmp1, 0x00);
	tmp2 = _mm_shuffle_epi32(tmp4, 0xAA);
	tmp4 = _mm_slli_si128(*tmp3, 0x04);
	*tmp3 = _mm_xor_si128(*tmp3, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp3 = _mm_xor_si128(*tmp3, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp3 = _mm_xor_si128(*tmp3, tmp4);
	*tmp3 = _mm_xor_si128(*tmp3, tmp2);
}

// Special thanks to Intel for helping me
// with ExpandAESKey256() and its subroutines
static inline void ExpandAESKey256(char *keybuf)
{
	__m128i tmp1, tmp2, tmp3, *keys;

	keys = (__m128i *)keybuf;

	tmp1 = _mm_load_si128((__m128i *)keybuf);
	tmp3 = _mm_load_si128((__m128i *)(keybuf+0x10));

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x01);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[2] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[3] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x02);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[4] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[5] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x04);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[6] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[7] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x08);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[8] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[9] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x10);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[10] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[11] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x20);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[12] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[13] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x40);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[14] = tmp1;
}

void cryptonight_hash_aesni(void *restrict output, const void *restrict input, const uint32_t inlen, struct cryptonight_ctx *restrict ct0, int variant)
{
    struct cryptonight_aesni_ctx *ctx = (struct cryptonight_aesni_ctx *)ct0;
    uint8_t ExpandedKey[256];
    size_t i, j;

    VARIANT1_INIT();

    keccak1600(input, inlen, (uint8_t *)&ctx->state.hs);
    memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
    memcpy(ExpandedKey, ctx->state.hs.b, AES_KEY_SIZE);
    ExpandAESKey256(ExpandedKey);

    __m128i *longoutput, *expkey, *xmminput;
	longoutput = (__m128i *)ctx->long_state;
	expkey = (__m128i *)ExpandedKey;
	xmminput = (__m128i *)ctx->text;

    //for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE)
    //    aesni_parallel_noxor(&ctx->long_state[i], ctx->text, ExpandedKey);

    for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE)
    {
		for(j = 0; j < 10; j++)
		{
			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[j]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[j]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[j]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[j]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[j]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[j]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[j]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[j]);
		}
		_mm_store_si128(&(longoutput[(i >> 4)]), xmminput[0]);
		_mm_store_si128(&(longoutput[(i >> 4) + 1]), xmminput[1]);
		_mm_store_si128(&(longoutput[(i >> 4) + 2]), xmminput[2]);
		_mm_store_si128(&(longoutput[(i >> 4) + 3]), xmminput[3]);
		_mm_store_si128(&(longoutput[(i >> 4) + 4]), xmminput[4]);
		_mm_store_si128(&(longoutput[(i >> 4) + 5]), xmminput[5]);
		_mm_store_si128(&(longoutput[(i >> 4) + 6]), xmminput[6]);
		_mm_store_si128(&(longoutput[(i >> 4) + 7]), xmminput[7]);
    }

	for (i = 0; i < 2; i++)
    {
	    ctx->a[i] = ((uint64_t *)ctx->state.k)[i] ^  ((uint64_t *)ctx->state.k)[i+4];
	    ctx->b[i] = ((uint64_t *)ctx->state.k)[i+2] ^  ((uint64_t *)ctx->state.k)[i+6];
    }

	__m128i b_x = _mm_load_si128((__m128i *)ctx->b);
    uint64_t a[2] __attribute((aligned(16))), b[2] __attribute((aligned(16)));
    a[0] = ctx->a[0];
    a[1] = ctx->a[1];

	for(i = 0; __builtin_expect(i < 0x80000, 1); i++)
	{
	__m128i c_x = _mm_load_si128((__m128i *)&ctx->long_state[a[0] & 0x1FFFF0]);
	__m128i a_x = _mm_load_si128((__m128i *)a);
	uint64_t c[2];
	c_x = _mm_aesenc_si128(c_x, a_x);

	_mm_store_si128((__m128i *)c, c_x);
	__builtin_prefetch(&ctx->long_state[c[0] & 0x1FFFF0], 0, 1);

	b_x = _mm_xor_si128(b_x, c_x);
	_mm_store_si128((__m128i *)&ctx->long_state[a[0] & 0x1FFFF0], b_x);
	VARIANT1_1(ctx->long_state, a[0] & 0x1FFFF0);

	uint64_t *nextblock = (uint64_t *)&ctx->long_state[c[0] & 0x1FFFF0];
	uint64_t b[2];
	b[0] = nextblock[0];
	b[1] = nextblock[1];

	{
	  uint64_t hi, lo;
	 // hi,lo = 64bit x 64bit multiply of c[0] and b[0]

	  __asm__("mulq %3\n\t"
		  : "=d" (hi),
		"=a" (lo)
		  : "%a" (c[0]),
		"rm" (b[0])
		  : "cc" );

	  a[0] += hi;
	  a[1] += lo;
	}
	uint64_t *dst = (uint64_t *)&ctx->long_state[c[0] & 0x1FFFF0];
	dst[0] = a[0];
	dst[1] = a[1];

	a[0] ^= b[0];
	a[1] ^= b[1];
	b_x = c_x;
	VARIANT1_2(ctx->long_state, c[0] & 0x1FFFF0);
	__builtin_prefetch(&ctx->long_state[a[0] & 0x1FFFF0], 0, 3);
	}

    memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
    memcpy(ExpandedKey, &ctx->state.hs.b[32], AES_KEY_SIZE);
    ExpandAESKey256(ExpandedKey);

    //for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE)
    //    aesni_parallel_xor(&ctx->text, ExpandedKey, &ctx->long_state[i]);

    for (i = 0; __builtin_expect(i < MEMORY, 1); i += INIT_SIZE_BYTE)
	{
		xmminput[0] = _mm_xor_si128(longoutput[(i >> 4)], xmminput[0]);
		xmminput[1] = _mm_xor_si128(longoutput[(i >> 4) + 1], xmminput[1]);
		xmminput[2] = _mm_xor_si128(longoutput[(i >> 4) + 2], xmminput[2]);
		xmminput[3] = _mm_xor_si128(longoutput[(i >> 4) + 3], xmminput[3]);
		xmminput[4] = _mm_xor_si128(longoutput[(i >> 4) + 4], xmminput[4]);
		xmminput[5] = _mm_xor_si128(longoutput[(i >> 4) + 5], xmminput[5]);
		xmminput[6] = _mm_xor_si128(longoutput[(i >> 4) + 6], xmminput[6]);
		xmminput[7] = _mm_xor_si128(longoutput[(i >> 4) + 7], xmminput[7]);

		for(j = 0; j < 10; j++)
		{
			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[j]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[j]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[j]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[j]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[j]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[j]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[j]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[j]);
		}

	}

    memcpy(ctx->state.init, ctx->text, INIT_SIZE_BYTE);
	keccakf(ctx->state.hs.w, 24);
    extra_hashes[ctx->state.hs.b[0] & 3](&ctx->state, 200, output);
}
#elif defined(__aarch64__)

struct cryptonight_aesv8_ctx {
    uint8_t long_state[MEMORY] __attribute((aligned(16)));
    union cn_slow_hash_state state;
    uint8_t text[INIT_SIZE_BYTE] __attribute((aligned(16)));
    uint64_t a[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));
    uint64_t b[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));
    uint64_t c[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));
    oaes_ctx* aes_ctx;
};

/* ARMv8-A optimized with NEON and AES instructions.
 * Copied from the x86-64 AES-NI implementation. It has much the same
 * characteristics as x86-64: there's no 64x64=128 multiplier for vectors,
 * and moving between vector and regular registers stalls the pipeline.
 */
#include <arm_neon.h>

#define TOTALBLOCKS (MEMORY / AES_BLOCK_SIZE)
#define U64(x) ((uint64_t *) (x))

#define state_index(x) (((*((uint64_t *)x) >> 4) & (TOTALBLOCKS - 1)) << 4)
#define __mul() __asm__("mul %0, %1, %2\n\t" : "=r"(lo) : "r"(ctx->c[0]), "r"(ctx->b[0]) ); \
  __asm__("umulh %0, %1, %2\n\t" : "=r"(hi) : "r"(ctx->c[0]), "r"(ctx->b[0]) );

#define pre_aes() \
  j = state_index(ctx->a); \
  _c = vld1q_u8(&ctx->long_state[j]); \
  _a = vld1q_u8((const uint8_t *)ctx->a); \

#define post_aes() \
  vst1q_u8((uint8_t *)ctx->c, _c); \
  _b = veorq_u8(_b, _c); \
  vst1q_u8(&ctx->long_state[j], _b); \
  VARIANT1_1(ctx->long_state, j); \
  j = state_index(ctx->c); \
  p = U64(&ctx->long_state[j]); \
  ctx->b[0] = p[0]; ctx->b[1] = p[1]; \
  { uint64_t hi, lo; \
  __mul(); \
  ctx->a[0] += hi; ctx->a[1] += lo; }\
  p = U64(&ctx->long_state[j]); \
  p[0] = ctx->a[0];  p[1] = ctx->a[1]; \
  ctx->a[0] ^= ctx->b[0]; ctx->a[1] ^= ctx->b[1]; \
  _b = _c; \
  VARIANT1_2(ctx->long_state, j); \


/* Note: this was based on a standard 256bit key schedule but
 * it's been shortened since Cryptonight doesn't use the full
 * key schedule. Don't try to use this for vanilla AES.
*/
static void aes_expand_key(const uint8_t *key, uint8_t *expandedKey) {
static const int rcon[] = {
    0x01,0x01,0x01,0x01,
    0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,    // rotate-n-splat
    0x1b,0x1b,0x1b,0x1b };
__asm__(
"	eor	v0.16b,v0.16b,v0.16b\n"
"	ld1	{v3.16b},[%0],#16\n"
"	ld1	{v1.4s,v2.4s},[%2],#32\n"
"	ld1	{v4.16b},[%0]\n"
"	mov	w2,#5\n"
"	st1	{v3.4s},[%1],#16\n"
"\n"
"1:\n"
"	tbl	v6.16b,{v4.16b},v2.16b\n"
"	ext	v5.16b,v0.16b,v3.16b,#12\n"
"	st1	{v4.4s},[%1],#16\n"
"	aese	v6.16b,v0.16b\n"
"	subs	w2,w2,#1\n"
"\n"
"	eor	v3.16b,v3.16b,v5.16b\n"
"	ext	v5.16b,v0.16b,v5.16b,#12\n"
"	eor	v3.16b,v3.16b,v5.16b\n"
"	ext	v5.16b,v0.16b,v5.16b,#12\n"
"	eor	v6.16b,v6.16b,v1.16b\n"
"	eor	v3.16b,v3.16b,v5.16b\n"
"	shl	v1.16b,v1.16b,#1\n"
"	eor	v3.16b,v3.16b,v6.16b\n"
"	st1	{v3.4s},[%1],#16\n"
"	b.eq	2f\n"
"\n"
"	dup	v6.4s,v3.s[3]		// just splat\n"
"	ext	v5.16b,v0.16b,v4.16b,#12\n"
"	aese	v6.16b,v0.16b\n"
"\n"
"	eor	v4.16b,v4.16b,v5.16b\n"
"	ext	v5.16b,v0.16b,v5.16b,#12\n"
"	eor	v4.16b,v4.16b,v5.16b\n"
"	ext	v5.16b,v0.16b,v5.16b,#12\n"
"	eor	v4.16b,v4.16b,v5.16b\n"
"\n"
"	eor	v4.16b,v4.16b,v6.16b\n"
"	b	1b\n"
"\n"
"2:\n" : : "r"(key), "r"(expandedKey), "r"(rcon));
}

/* An ordinary AES round is a sequence of SubBytes, ShiftRows, MixColumns, AddRoundKey. There
 * is also an InitialRound which consists solely of AddRoundKey. The ARM instructions slice
 * this sequence differently; the aese instruction performs AddRoundKey, SubBytes, ShiftRows.
 * The aesmc instruction does the MixColumns. Since the aese instruction moves the AddRoundKey
 * up front, and Cryptonight's hash skips the InitialRound step, we have to kludge it here by
 * feeding in a vector of zeros for our first step. Also we have to do our own Xor explicitly
 * at the last step, to provide the AddRoundKey that the ARM instructions omit.
 */
static inline void aes_pseudo_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey, int nblocks)
{
	const uint8x16_t *k = (const uint8x16_t *)expandedKey, zero = {0};
	uint8x16_t tmp;
	int i;

	for (i=0; i<nblocks; i++)
	{
		uint8x16_t tmp = vld1q_u8(in + i * AES_BLOCK_SIZE);
		tmp = vaeseq_u8(tmp, zero);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[0]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[1]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[2]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[3]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[4]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[5]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[6]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[7]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[8]);
		tmp = vaesmcq_u8(tmp);
		tmp = veorq_u8(tmp,  k[9]);
		vst1q_u8(out + i * AES_BLOCK_SIZE, tmp);
	}
}

static inline void aes_pseudo_round_xor(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey, const uint8_t *xor, int nblocks)
{
	const uint8x16_t *k = (const uint8x16_t *)expandedKey;
	const uint8x16_t *x = (const uint8x16_t *)xor;
	uint8x16_t tmp;
	int i;

	for (i=0; i<nblocks; i++)
	{
		uint8x16_t tmp = vld1q_u8(in + i * AES_BLOCK_SIZE);
		tmp = vaeseq_u8(tmp, x[i]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[0]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[1]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[2]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[3]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[4]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[5]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[6]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[7]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[8]);
		tmp = vaesmcq_u8(tmp);
		tmp = veorq_u8(tmp,  k[9]);
		vst1q_u8(out + i * AES_BLOCK_SIZE, tmp);
	}
}

void cryptonight_hash_aesni(void *restrict output, const void *restrict input, const uint32_t inlen, struct cryptonight_ctx *restrict ct0, int variant)
{
    struct cryptonight_aesv8_ctx *ctx = (struct cryptonight_aesv8_ctx *)ct0;
    uint8_t expandedKey[240];
    uint8x16_t _a, _b, _c;
    const uint8x16_t zero = {0};
    size_t i, j;
    uint64_t *p = NULL;

    VARIANT1_INIT();

    /* CryptoNight Step 1:  Use Keccak1600 to initialize the 'state' (and 'text') buffers from the data. */

    keccak1600(input, inlen, (uint8_t *)&ctx->state.hs);
    memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);

    /* CryptoNight Step 2:  Iteratively encrypt the results from Keccak to fill
     * the 2MB large random access buffer.
     */

    aes_expand_key(ctx->state.hs.b, expandedKey);
    for(i = 0; i < MEMORY / INIT_SIZE_BYTE; i++)
    {
        aes_pseudo_round(ctx->text, ctx->text, expandedKey, INIT_SIZE_BLK);
        memcpy(&ctx->long_state[i * INIT_SIZE_BYTE], ctx->text, INIT_SIZE_BYTE);
    }

    U64(ctx->a)[0] = U64(&ctx->state.k[0])[0] ^ U64(&ctx->state.k[32])[0];
    U64(ctx->a)[1] = U64(&ctx->state.k[0])[1] ^ U64(&ctx->state.k[32])[1];
    U64(ctx->b)[0] = U64(&ctx->state.k[16])[0] ^ U64(&ctx->state.k[48])[0];
    U64(ctx->b)[1] = U64(&ctx->state.k[16])[1] ^ U64(&ctx->state.k[48])[1];

    /* CryptoNight Step 3:  Bounce randomly 1 million times through the mixing buffer,
     * using 500,000 iterations of the following mixing function.  Each execution
     * performs two reads and writes from the mixing buffer.
     */

    _b = vld1q_u8((const uint8_t *)ctx->b);


    for(i = 0; i < ITER / 2; i++)
    {
        pre_aes();
        _c = vaeseq_u8(_c, zero);
        _c = vaesmcq_u8(_c);
        _c = veorq_u8(_c, _a);
        post_aes();
    }

    /* CryptoNight Step 4:  Sequentially pass through the mixing buffer and use 10 rounds
     * of AES encryption to mix the random data back into the 'text' buffer.  'text'
     * was originally created with the output of Keccak1600. */

    memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);

    aes_expand_key(&ctx->state.hs.b[32], expandedKey);
    for(i = 0; i < MEMORY / INIT_SIZE_BYTE; i++)
    {
        // add the xor to the pseudo round
        aes_pseudo_round_xor(ctx->text, ctx->text, expandedKey, &ctx->long_state[i * INIT_SIZE_BYTE], INIT_SIZE_BLK);
    }

    /* CryptoNight Step 5:  Apply Keccak to the state again, and then
     * use the resulting data to select which of four finalizer
     * hash functions to apply to the data (Blake, Groestl, JH, or Skein).
     * Use this hash to squeeze the state array down
     * to the final 256 bit hash output.
     */

    memcpy(ctx->state.init, ctx->text, INIT_SIZE_BYTE);
    keccakf((uint64_t*)(&ctx->state.hs), 24);
    extra_hashes[ctx->state.hs.b[0] & 3](&ctx->state, 200, output);
}
#endif /* __x86_64__ */

struct cryptonight_ctx* cryptonight_ctx(){
	struct cryptonight_ctx *ret;
#ifdef _WIN32
	ret = calloc(1, sizeof(*ret));
#else
	ret = mmap(0, sizeof(*ret), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB|MAP_POPULATE, 0, 0);
	if (ret == MAP_FAILED)
		ret = calloc(1, sizeof(*ret));
	if (ret) {
		madvise(ret, sizeof(*ret), MADV_RANDOM|MADV_WILLNEED|MADV_HUGEPAGE);
		if (!geteuid())
			mlock(ret, sizeof(*ret));
	}
#endif
	return ret;
}
