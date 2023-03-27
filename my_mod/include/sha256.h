#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/time.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/init.h>

#define SHA256_BLOCK_SIZE 32

typedef unsigned char BYTE;
typedef unsigned int  WORD;

typedef struct {
	BYTE ctxdata[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_CTX;

extern void SHA256_Init(SHA256_CTX *ctx);
extern void SHA256_Update(SHA256_CTX *ctx, const BYTE data[], WORD len);
extern void SHA256_Final(SHA256_CTX *ctx, BYTE hash[]);