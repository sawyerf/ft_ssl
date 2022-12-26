#include "ft_ssl.h"
#include <byteswap.h>

void sha384InitHash(t_hash64 *hash) {
	hash->H0 = 0xcbbb9d5dc1059ed8;
	hash->H1 = 0x629a292a367cd507;
	hash->H2 = 0x9159015a3070dd17;
	hash->H3 = 0x152fecd8f70e5939;
	hash->H4 = 0x67332667ffc00b31;
	hash->H5 = 0x8eb44a8768581511;
	hash->H6 = 0xdb0c2e0d64f98fa7;
	hash->H7 = 0x47b5481dbefa4fa4;
}

void sha384PrintHash(t_hash64 *hash) {
	ft_printf("%016lx%016lx%016lx%016lx%016lx%016lx",
		hash->H0,
		hash->H1,
		hash->H2,
		hash->H3,
		hash->H4,
		hash->H5
	);
}