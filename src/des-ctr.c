#include "libft.h"
#include "ft_ssl.h"

unsigned long indexCTR = 0;

// TODO: Found a way to check
unsigned long decodeCTR(t_des *des, unsigned long cipherText, unsigned long *keys) {
	unsigned long plainText;

	plainText = desEncrypt(indexCTR ^ des->iv, keys);
	plainText ^= cipherText;
	indexCTR++;
	return (plainText);
}

unsigned long encodeCTR(t_des *des, unsigned long plainText, unsigned long *keys) {
	unsigned long cipherText;

	cipherText = desEncrypt(indexCTR ^ des->iv, keys);
	cipherText ^= plainText;
	indexCTR++;
	return (cipherText);
}