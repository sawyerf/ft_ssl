#include "ft_ssl.h"

extern t_router routesHash[];

void turboXor(unsigned char *dst, unsigned char *src) {
	for (int index = 0; index < 8 * 4; index++) {
		dst[index] ^= src[index];
	}
}

void pbkdf2(char *password, unsigned long salt, t_hash *hash, unsigned int iter) {
	size_t	lenPass = ft_strlen(password);
	char	buffer[HASH32_SIZE + 4];
	unsigned int index = swap32(1);
	t_hash	tmp;

	ft_bzero(hash, sizeof(t_hash));
	salt = swap64(salt);
	ft_memcpy(buffer, &salt, 8);
	ft_memcpy(buffer + 8, &index, 4);
	hmacSha256(&tmp, password, lenPass, buffer, 8 + 4);
	turboXor((void*)hash, (void*)&tmp);

	for (index = 1; index < iter; index++) {
		ft_memcpy(buffer, &tmp.H0, HASH32_SIZE);
		hmacSha256(&tmp, password, lenPass, buffer, HASH32_SIZE);
		turboXor((void*)hash, (void*)&tmp);
	}
}