#include "libft.h"
#include "ft_ssl.h"

unsigned long decodeCBC(t_des *des, unsigned long data, unsigned long *keys) {
	unsigned long cipherText;

	cipherText = desEncrypt(data, keys);
	cipherText ^= des->iv;
	des->iv = data;
	return (cipherText);
}

unsigned long encodeCBC(t_des *des, unsigned long data, unsigned long *keys) {
	unsigned long cipherText;

	data ^= des->iv;
	cipherText = desEncrypt(data, keys);
	des->iv = cipherText;
	return (cipherText);
}