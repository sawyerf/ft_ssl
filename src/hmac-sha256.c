#include "ft_ssl.h"

#define BLOC_SIZE 64

extern t_router routesHash[];

void	hmacConcat(t_hash *hash, char *key, size_t lenKey, char *message, size_t lenMes, char c) {
	char	buffer[BLOC_SIZE];
	size_t index = 0;

	ft_memset(buffer, 0, BLOC_SIZE);
	ft_memcpy(buffer, key, lenKey);
	for (; index < BLOC_SIZE; index++)
		buffer[index] = buffer[index] ^ c;

	sha256InitHash(hash);
	// Hash Key
	sha256EncodeBloc(hash, buffer);

	// Hash message
	index = 0;
	while (lenMes - index >= BLOC_SIZE) {
		sha256EncodeBloc(hash, message);
		message += BLOC_SIZE;
		index += BLOC_SIZE;
	}
	ft_bzero(buffer, BLOC_SIZE);
	ft_memcpy(buffer, message, lenMes - index);
	sha256Padding((void*)buffer, lenMes + BLOC_SIZE, hash);
}

void	swap32cpy(unsigned int *dst, unsigned int *src) {
	for (int index = 0; index < 8; index++) {
		dst[index] = swap32(src[index]);
	}
}

void	hmacSha256(t_hash *hash, char *key, size_t lenKey, char *message, size_t lenMes) {
	unsigned int buffer[8];
	t_hash tmp;

	
	if (lenKey > BLOC_SIZE) {
		getArg(key, lenKey, &tmp, routesHash + 2);
		// ft_printf("%s\n", routesHash[2].name);
		swap32cpy((void*)&tmp, (void*)&tmp);
		key = (char*)&tmp;
		lenKey = 32;
	}
	hmacConcat(hash, key, lenKey, message, lenMes, 0x36);
	swap32cpy(buffer, (void*)hash);
	hmacConcat(hash, key, lenKey, (void*)buffer, HASH32_SIZE, 0x5c);
	swap32cpy((void*)hash, (void*)hash);
}