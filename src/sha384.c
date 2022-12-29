#include "ft_ssl.h"

void sha384InitHash(t_hash *hash) {
	hash->HH0 = 0xcbbb9d5dc1059ed8;
	hash->HH1 = 0x629a292a367cd507;
	hash->HH2 = 0x9159015a3070dd17;
	hash->HH3 = 0x152fecd8f70e5939;
	hash->HH4 = 0x67332667ffc00b31;
	hash->HH5 = 0x8eb44a8768581511;
	hash->HH6 = 0xdb0c2e0d64f98fa7;
	hash->HH7 = 0x47b5481dbefa4fa4;
}

void sha384PrintHash(t_hash *hash) {
	ft_printf("%016lx%016lx%016lx%016lx%016lx%016lx",
		hash->HH0,
		hash->HH1,
		hash->HH2,
		hash->HH3,
		hash->HH4,
		hash->HH5
	);
}