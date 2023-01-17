#include "libft.h"
#include "ft_ssl.h"

// TODO: Verify
unsigned long decodeOFB(t_des *des, unsigned long cipherText, unsigned long *keys) {
	unsigned long plainText;

	plainText = desEncrypt(des->iv, keys);
	des->iv = plainText;
	plainText ^= cipherText;
	return (plainText);
}

unsigned long encodeOFB(t_des *des, unsigned long plainText, unsigned long *keys) {
	unsigned long cipherText;

	cipherText = desEncrypt(des->iv, keys);
	des->iv = cipherText;
	cipherText ^= plainText;
	return (cipherText);
}