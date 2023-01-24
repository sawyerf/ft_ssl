#include "ft_ssl.h"

extern t_router routesHash[];

void pbkdf2(char *password, unsigned long salt, t_hash *hash) {
	size_t	lenPass = ft_strlen(password);
	char	buffer[HASH32_SIZE + 4];
	unsigned index = 1;

	ft_bzero(hash, sizeof(t_hash));
	
	// =========== TEST ===========
	unsigned char kkk[] = "1234567890ABCDEF";
	hmacSha256(hash, (void*)kkk, 16, "lol", 3);
	sha256PrintHash(hash);
	ft_printf("\n");
	exit(1);
	// =========== TEST ===========

	ft_bzero(hash, sizeof(t_hash));
	ft_memcpy(buffer, &salt, 8);
	ft_memcpy(buffer + 8, &index, 4);
	hmacSha256(hash, buffer, 8 + 4, password, lenPass);
	for (index = 2; index <= 1000; index++) {
		ft_memcpy(buffer, &hash->H0, HASH32_SIZE);
		ft_memcpy(buffer + HASH32_SIZE, &index, 4);
		hmacSha256(hash, buffer, HASH32_SIZE + 4, password, lenPass);
	}
}