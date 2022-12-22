#include "ft_ssl.h"

void sha224InitHash(t_hash *hash) {
	hash->H0 = 0xc1059ed8;
	hash->H1 = 0x367cd507;
	hash->H2 = 0x3070dd17;
	hash->H3 = 0xf70e5939;
	hash->H4 = 0xffc00b31;
	hash->H5 = 0x68581511;
	hash->H6 = 0x64f98fa7;
	hash->H7 = 0xbefa4fa4;
}