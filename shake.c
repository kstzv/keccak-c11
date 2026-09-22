#include <stdint.h>
#include <stddef.h>

// Reusable SHAKE context with externally supplied Keccak state
struct shake_ctx {
    uint64_t *state;
    size_t rate;
    size_t pos;

    const uint8_t *in;
    size_t inlen;

    uint8_t *out;
    size_t outlen;
};

void shake_ctx_init(struct shake_ctx *ctx, uint64_t *state, const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);
void shake_ctx_zero(struct shake_ctx *ctx);
void shake128(struct shake_ctx *ctx);
void shake256(struct shake_ctx *ctx);

static void shake_absorb(struct shake_ctx *ctx);
static void shake_finalize(struct shake_ctx *ctx);
static void shake_squeeze(struct shake_ctx *ctx);


void shake_ctx_init(struct shake_ctx *ctx, uint64_t *state, const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
    ctx->state = state;
    ctx->rate = 0;
    ctx->pos = 0;

    ctx->in = in;
    ctx->inlen = inlen;

    ctx->out = out;
    ctx->outlen = outlen;
}

// Clear the 1600-bit Keccak state and reset the context
void shake_ctx_zero(struct shake_ctx *ctx)
{
    if (ctx == NULL || ctx->state == NULL) { return; }

    // 25 lanes x 8 bytes
    volatile uint8_t *p = (volatile uint8_t *)ctx->state;
    size_t len = 200;
    while (len--) { *p++ = 0; }
    ctx->in = NULL;
    ctx->inlen = 0;
    ctx->out = NULL;
    ctx->outlen = 0;
    ctx->pos = 0;
    ctx->rate = 0;
}

void shake128(struct shake_ctx *ctx)
{
    ctx->rate = 168;

    // Continue squeezing an already finalized state
    if (ctx->pos != 0) 
    {
        shake_squeeze(ctx);
        return;
    }

    shake_absorb(ctx);
    shake_finalize(ctx);

    ctx->pos = 0;

    shake_squeeze(ctx);
}

void shake256(struct shake_ctx *ctx)
{
    ctx->rate = 136;

    // Continue squeezing an already finalized state
    if (ctx->pos != 0) 
    {
        shake_squeeze(ctx);
        return;
    }

    shake_absorb(ctx);
    shake_finalize(ctx);

    ctx->pos = 0;

    shake_squeeze(ctx);
}

// Absorb input into the rate portion of the Keccak state
static void shake_absorb(struct shake_ctx *ctx)
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

// Apply SHAKE domain separation and pad10*1 padding
static void shake_finalize(struct shake_ctx *ctx)
{
    uint8_t *s = (uint8_t *)ctx->state;

    s[ctx->pos] ^= 0x1F;     // SHAKE domain separator
    s[ctx->rate - 1] ^= 0x80;// Final padding bit

    keccak_f1600(ctx->state);
}

// Extract output from the rate portion, permuting as needed
static void shake_squeeze(struct shake_ctx *ctx)
{
    uint8_t *s = (uint8_t *)ctx->state;

    size_t local_outlen = ctx->outlen;
    uint8_t *local_ptr_out = ctx->out;

    while (local_outlen > 0)
    {
        // Generate the next output block when the rate is exhausted
        if (ctx->pos == ctx->rate)
        {
            keccak_f1600(ctx->state);
            ctx->pos = 0;
        }

        size_t n = ctx->rate - ctx->pos;

        if (n > local_outlen) { n = local_outlen; }

        for (size_t i = 0; i < n; i++) { local_ptr_out[i] = s[ctx->pos + i]; }

        ctx->pos += n;
        local_ptr_out += n;
        local_outlen -= n;
    }
}



