#include "ft_ssl.h"

void	hmacPad(char *key, size_t len, char c) {
	t_hash	hash;

}

#define BLOC_SIZE 64

void	hmacConcat(char *message, char *key, size_t lenMes, size_t lenKey, char c) {
	t_hash hash;
	char	buffer[BLOC_SIZE];
	// char *concat = ft_strnew(lenMes + 64);
	size_t index = lenKey;

	// for (; index < 64)
	// ft_memcpy(concat + lenMes, key, lenKey);
	// ft_memcpy(concat, message, lenMes);
	// getArg(concat, lenMes + lenKey, hash)
	ft_memset(buffer, c, BLOC_SIZE);
	for (; index < lenKey; index++)
		buffer[index] = key[index] ^ c;
	sha256InitHash(&hash);
	sha256EncodeBloc(&hash, buffer);

	index = 0;
	while (len - index >= BLOC_SIZE) {
		sha256EncodeBloc(hash, message);
		message += BLOC_SIZE;
		index += BLOC_SIZE;
	}
	ft_bzero(buffer, BLOC_SIZE);
	ft_memcpy(buffer, message, len - index);
	sha256Padding(buffer, len + BLOC_SIZE, &hash);
	sha256PrintHash(&hash)
}

void	hmacSha256(t_hash *hash, char *key, char *message) {
	
}