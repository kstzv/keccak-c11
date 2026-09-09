#include <stdint.h>

static size_t shake_absorb(uint64_t *state, uint8_t *in, size_t inlen, size_t pos, size_t rate);
static void shake_finalize(uint64_t *state, size_t pos, size_t rate);
static size_t shake_squeeze(uint64_t *state, uint8_t *out, size_t outlen, size_t pos, size_t rate);

void secure_zero(void *ptr, size_t len);

size_t shake128(uint64_t *state, uint8_t *in, size_t inlen, uint8_t *out, size_t outlen, size_t start_pos)
{
	size_t rate = 168;
	if(start_pos != 0) { return shake_squeeze(state, out, outlen, start_pos, rate); }
	
	size_t pos = start_pos;
	pos = shake_absorb(state, in, inlen, pos, rate);
	
	shake_finalize(state, pos, rate);
	pos = 0;
	
	return shake_squeeze(state, out, outlen, pos, rate);
}

size_t shake256(uint64_t *state, uint8_t *in, size_t inlen, uint8_t *out, size_t outlen, size_t start_pos)
{
	size_t rate = 136;
	if(start_pos != 0) { return shake_squeeze(state, out, outlen, start_pos, rate); }
	
	size_t pos = 0;
	pos = shake_absorb(state, in, inlen, pos, rate);
	
	shake_finalize(state, pos, rate);
	pos = 0;
	
	return shake_squeeze(state, out, outlen, pos, rate);
}

void secure_zero(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;

    while (len--) { *p++ = 0; }
}

static size_t shake_absorb(uint64_t *state, uint8_t *in, size_t inlen, size_t pos, size_t rate)
{
    uint8_t *s = (uint8_t *)state;

    while (inlen > 0) 
    {
        size_t n = rate - pos;

        if (n > inlen) { n = inlen; }

        for (size_t i = 0; i < n; i++) { s[pos + i] ^= in[i]; }

        pos  += n;
        in   += n;
        inlen-= n;

        if (pos == rate) 
        {
            keccak_f1600(state);
            pos = 0;
        }
    }
    
    return pos;
}
		

static void shake_finalize(uint64_t *state, size_t pos, size_t rate)
{
    uint8_t *s = (uint8_t *)state;

    s[pos] ^= 0x1F;
    s[rate - 1] ^= 0x80;

    keccak_f1600(state);
}

static size_t shake_squeeze(uint64_t *state, uint8_t *out, size_t outlen, size_t pos, size_t rate)
{
    uint8_t *s = (uint8_t *)state;

    while (outlen > 0)
    {
		if (pos == rate)
		{
			keccak_f1600(state);
			pos = 0;
		}
        size_t n = rate - pos;

        if (n > outlen) { n = outlen; }

        for (size_t i = 0; i < n; i++) { out[i] = s[pos + i]; }

        pos += n;
        out += n;
        outlen -= n;
    }
    
    return pos;
}



