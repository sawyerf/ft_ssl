#include "libft.h"
#include "ft_ssl.h"

void revTabLong(unsigned long *tab, int size) {
	unsigned long tmp;

	for (int index = 0; index < size / 2; index++) {
		tmp = tab[index];
		tab[index] = tab[size - 1 - index];
		tab[size - 1 - index] = tmp;
	}
}

#define DES_SIZE_READ 3 * 4

void desECB_Router(char **argv) {
	t_des	desO;
	t_optpars opt;
	unsigned long keys[16], data[DES_SIZE_READ], cipherText[DES_SIZE_READ];
	ssize_t len = 0, prevLen = 0;

	ft_bzero(&desO, sizeof(t_des));
	ft_bzero(cipherText, DES_SIZE_READ * 8);

	optionsDesECB(argv, &opt, &desO);

	generateKey(desO.key, keys);
	if (desO.isDecode) {
		revTabLong(keys, 16);
	}
	while ((len = turboRead(desO.fdInput, data, 8 * DES_SIZE_READ, desO.isDecode & desO.isBase64)) >= 0) {
		int index;

		if (desO.isDecode && !len && prevLen) prevLen -= ((unsigned char*)cipherText)[prevLen - 1];
		if (!desO.isDecode && desO.isBase64) {
			base64Encode((char *)cipherText, prevLen, desO.fdOutput);
		} else {
			write(desO.fdOutput, cipherText, prevLen);
		}

		prevLen = len;
		if (!desO.isDecode && len != 8 * DES_SIZE_READ) {
			prevLen = desPadding(data, len);
		}
		
		if (desO.isDecode && desO.isBase64) prevLen = base64DecodeRC((unsigned char *)data, len, (unsigned char *)data);
		for (index = 0; index < prevLen / 8; index++) {
			if (desO.isDecode) {
				cipherText[index] = desEncrypt(data[index], keys);
			} else {
				data[index] ^= desO.iv;
				cipherText[index] = desEncrypt(data[index], keys);
				desO.iv = cipherText[index];
			}
		}
		if (len != 8 * DES_SIZE_READ) break;
	}
	unsigned char padding = ((unsigned char*)cipherText)[prevLen - 1];
	if (desO.isDecode && prevLen && (padding > 8 || padding > prevLen | !padding)) {
		ft_dprintf(2, "Wrong padding\n", prevLen, padding, padding);
		exit(1);
	}
	if (desO.isDecode && prevLen && (((unsigned char*)cipherText)[prevLen - 1] <= len)) prevLen -= ((unsigned char*)cipherText)[prevLen - 1];
	if (!desO.isDecode && desO.isBase64) {
		base64Encode((char *)cipherText, prevLen, desO.fdOutput);
	} else {
		write(desO.fdOutput, cipherText, prevLen);
	}
}