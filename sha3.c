#include <stdint.h>
#include <stddef.h>

// Reusable SHA3 context with externally supplied Keccak state
struct sha3_ctx {
    uint64_t *state;
    size_t rate;
    size_t pos;

    const uint8_t *in;
    size_t inlen;

    uint8_t *out;
};

int sha3_ctx_get_mem(struct sha3_ctx *ctx, uint64_t *state, size_t size_mem);
int sha3_ctx_init(struct sha3_ctx *ctx, const uint8_t *in, size_t inlen, uint8_t *out);
void sha3_256(struct sha3_ctx *ctx);
void sha3_512(struct sha3_ctx *ctx);

static void sha3_absorb(struct sha3_ctx *ctx);
static void sha3_finalize(struct sha3_ctx *ctx);
static void sha3_squeeze(struct sha3_ctx *ctx, uint8_t outlen);

int sha3_ctx_get_mem(struct sha3_ctx *ctx, uint64_t *state, size_t size_mem)
{
	if(!ctx || !state || size_mem != 25) { return -1; }
	ctx->state = state;
    ctx->rate = 0;
    ctx->pos = 0;
    ctx->in = NULL;
    ctx->inlen = 0;
    ctx->out = NULL;
	return 0;
}

int sha3_ctx_init(struct sha3_ctx *ctx, const uint8_t *in, size_t inlen, uint8_t *out)
{
	if (!ctx || !ctx->state || (inlen && !in) || !out) { return -1; }
	
	// 25 lanes x 8 bytes
    volatile uint8_t *p = (volatile uint8_t *)ctx->state;
    size_t len = 200;
    while (len--) { *p++ = 0; }
    
    ctx->rate = 0;
    ctx->pos = 0;
	
    ctx->in = in;
    ctx->inlen = inlen;
    ctx->out = out;
    
    return 0;
}

void sha3_256(struct sha3_ctx *ctx)
{
    ctx->rate = 136;
    ctx->pos = 0;

    sha3_absorb(ctx);
    sha3_finalize(ctx);
    sha3_squeeze(ctx, 32);
}

void sha3_512(struct sha3_ctx *ctx)
{
    ctx->rate = 72;
    ctx->pos = 0;

    sha3_absorb(ctx);
    sha3_finalize(ctx);
    sha3_squeeze(ctx, 64);
}

// Absorb input into the rate portion of the Keccak state
static void sha3_absorb(struct sha3_ctx *ctx)
{
    uint8_t *s = (uint8_t *)ctx->state;

    while (ctx->inlen > 0)
    {
        size_t n = ctx->rate - ctx->pos;

        if (n > ctx->inlen) { n = ctx->inlen; }

        for (size_t i = 0; i < n; i++) { s[ctx->pos + i] ^= ctx->in[i]; }

        ctx->pos += n;
        ctx->in += n;
        ctx->inlen -= n;

        // Permute after absorbing a complete rate block
        if (ctx->pos == ctx->rate)
        {
            keccak_f1600(ctx->state);
            ctx->pos = 0;
        }
    }
}

// Apply sha3 domain separation and pad10*1 padding
static void sha3_finalize(struct sha3_ctx *ctx)
{
    uint8_t *s = (uint8_t *)ctx->state;

    s[ctx->pos] ^= 0x06;     // SHA3 domain separator
    s[ctx->rate - 1] ^= 0x80;// Final padding bit

    keccak_f1600(ctx->state);
}

// Extract output from the rate portion, permuting as needed
static void sha3_squeeze(struct sha3_ctx *ctx, uint8_t outlen)
{
    const uint8_t *s = (const uint8_t *)ctx->state;

    for (size_t i = 0; i < outlen; i++)
    {
        ctx->out[i] = s[i];
    }
}



