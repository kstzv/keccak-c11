#include <stdint.h>
#include <stddef.h>

struct shake_ctx {
    uint64_t (*state)[2];

    size_t rate;
    size_t pos;

    const uint8_t *in[2];
    size_t inlen;

    uint8_t *out[2];
    size_t outlen;
};

void shake_ctx_init(struct shake_ctx *ctx, uint64_t *state, size_t inlen, size_t outlen);
void shake_get_first_msg(struct shake_ctx *ctx, const uint8_t *in, uint8_t *out);
void shake_get_second_msg(struct shake_ctx *ctx, const uint8_t *in, uint8_t *out);

void shake_ctx_zero(struct shake_ctx *ctx);
void shake128(struct shake_ctx *ctx);
void shake256(struct shake_ctx *ctx);

static void shake_absorb(struct shake_ctx *ctx);
static void shake_finalize(struct shake_ctx *ctx);
static void shake_squeeze(struct shake_ctx *ctx);

void shake_ctx_init(struct shake_ctx *ctx, uint64_t *state, size_t inlen, size_t outlen)
{
	ctx->state = (uint64_t (*)[2])state;
	ctx->rate = 0;
	ctx->pos = 0;
	ctx->inlen = inlen;
	ctx->outlen = outlen;
}

void shake_get_first_msg(struct shake_ctx *ctx, const uint8_t *in, uint8_t *out)
{
	ctx->in[0] = in;
	ctx->out[0] = out;
}

void shake_get_second_msg(struct shake_ctx *ctx, const uint8_t *in, uint8_t *out)
{
	ctx->in[1] = in;
	ctx->out[1] = out;
}

void shake_ctx_zero(struct shake_ctx *ctx)
{
    if (ctx == NULL || ctx->state == NULL) { return; }

    volatile uint8_t *p = (volatile uint8_t *)ctx->state;
    size_t len = 400;
    while (len--) { *p++ = 0; }
    ctx->in[0] = NULL;
    ctx->in[1] = NULL;
    ctx->inlen = 0;
    ctx->out[0] = NULL;
    ctx->out[1] = NULL;
    ctx->outlen = 0;
    ctx->pos = 0;
    ctx->rate = 0;
}

void shake128(struct shake_ctx *ctx)
{
    ctx->rate = 168;

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

static inline uint64_t load64_le(const uint8_t *p)
{
    return ((uint64_t)p[0]      ) |
           ((uint64_t)p[1] <<  8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static inline void keccak_xor_bytes(uint8_t *s, const uint8_t *in, size_t len)
{
    for (size_t i = 0; i < len; i++) { s[i] ^= in[i]; }
}

static void shake_absorb(struct shake_ctx *ctx)
{
    size_t input_counter = 0;
    size_t output_counter = 0;
    size_t rate_words = ctx->rate / 8;

    while (input_counter < ctx->inlen)
    {
        if (output_counter == rate_words)
        {
            keccak_f1600_x2(ctx->state);
            output_counter = 0;
            ctx->pos = 0;
        }

        size_t remaining = ctx->inlen - input_counter;

        if (remaining < 8)
        {
            keccak_xor_bytes((uint8_t *)&ctx->state[output_counter][0], ctx->in[0], remaining);

            keccak_xor_bytes((uint8_t *)&ctx->state[output_counter][1], ctx->in[1], remaining);

            ctx->in[0] += remaining;
            ctx->in[1] += remaining;

            input_counter += remaining;
            ctx->pos += remaining;

            break;
        }

        ctx->state[output_counter][0] ^= load64_le(ctx->in[0]);
        ctx->state[output_counter][1] ^= load64_le(ctx->in[1]);

        ctx->in[0] += 8;
        ctx->in[1] += 8;

        input_counter += 8;
        output_counter++;

        ctx->pos += 8;
    }

    if (ctx->pos == ctx->rate)
    {
        keccak_f1600_x2(ctx->state);
        ctx->pos = 0;
    }
}

static void shake_finalize(struct shake_ctx *ctx)
{
    size_t word = ctx->pos >> 3;
    size_t byte = ctx->pos & 7;

    size_t last_word = (ctx->rate - 1) >> 3;
    size_t last_byte = (ctx->rate - 1) & 7;

    uint64_t ds = (uint64_t)0x1f << (byte * 8);
    uint64_t end = (uint64_t)0x80 << (last_byte * 8);

    ctx->state[word][0] ^= ds;
    ctx->state[word][1] ^= ds;

    ctx->state[last_word][0] ^= end;
    ctx->state[last_word][1] ^= end;

    keccak_f1600_x2(ctx->state);

    ctx->pos = 0;
}

static inline void store64_le(uint8_t *out, uint64_t x)
{
    out[0] = (uint8_t)(x);
    out[1] = (uint8_t)(x >> 8);
    out[2] = (uint8_t)(x >> 16);
    out[3] = (uint8_t)(x >> 24);
    out[4] = (uint8_t)(x >> 32);
    out[5] = (uint8_t)(x >> 40);
    out[6] = (uint8_t)(x >> 48);
    out[7] = (uint8_t)(x >> 56);
}

static inline void store_partial_le(uint8_t *out, uint64_t word, size_t byte, size_t len)
{
    for (size_t i = 0; i < len; i++) { out[i] = (uint8_t)(word >> ((byte + i) * 8)); }
}

static void shake_squeeze(struct shake_ctx *ctx)
{
    size_t output_counter = 0;

    while (output_counter < ctx->outlen)
    {
        if (ctx->pos == ctx->rate)
        {
            keccak_f1600_x2(ctx->state);
            ctx->pos = 0;
        }

        size_t word = ctx->pos >> 3;
        size_t byte = ctx->pos & 7;
        size_t remaining = ctx->outlen - output_counter;

        // Fast path: the position is aligned to the start of a word, and at least 8 bytes need to be output
        if (byte == 0 && remaining >= 8)
        {
            store64_le(ctx->out[0], ctx->state[word][0]);
            store64_le(ctx->out[1], ctx->state[word][1]);

            ctx->out[0] += 8;
            ctx->out[1] += 8;

            output_counter += 8;
            ctx->pos += 8;

            continue;
        }

        // Partial output: 1–7 bytes or continuation after a previous unaligned squeeze()
        size_t n = 8 - byte;

        if (n > remaining) { n = remaining; }

        if (n > ctx->rate - ctx->pos) { n = ctx->rate - ctx->pos; }

        store_partial_le(ctx->out[0], ctx->state[word][0], byte, n);

        store_partial_le(ctx->out[1], ctx->state[word][1], byte, n);

        ctx->out[0] += n;
        ctx->out[1] += n;

        output_counter += n;
        ctx->pos += n;
    }
}
		
	
	
	
	
	
	
	
	
	
		
