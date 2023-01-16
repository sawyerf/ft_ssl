#include "libft.h"
#include "ft_ssl.h"

// TODO: No padding
unsigned long decodeCFB(t_des *des, unsigned long cipherText, unsigned long *keys) {
	unsigned long plainText;

	plainText = desEncrypt(des->iv, keys);
	des->iv = cipherText;
	plainText ^= cipherText;
	return (plainText);
}

unsigned long encodeCFB(t_des *des, unsigned long plainText, unsigned long *keys) {
	unsigned long cipherText;

	cipherText = desEncrypt(des->iv, keys);
	cipherText ^= plainText;
	des->iv = cipherText;
	return (cipherText);
}