#include "libft.h"
#include "ft_ssl.h"

void optionsDesECB(char **argv, char *key, t_optpars *optpars) {
	t_opt	*opt;
	unsigned char ret;
	char *keyStr = NULL;

	ft_bzero(optpars, sizeof(t_optpars));
	opt_init(&opt);
	opt_addvar2(&opt, "-k", (void*)&keyStr, OPT_STR);
	opt_addvar2(&opt, "-d", NULL, 0);
	opt_addvar2(&opt, "-a", NULL, 0);
	opt_addvar2(&opt, "-e", NULL, 0); // TODO
	opt_addvar2(&opt, "-i", NULL, 0); // TODO
	opt_addvar2(&opt, "-o", NULL, 0); // TODO
	ret = opt_parser(opt, argv, optpars, "ft_ssl");
	opt_free(&opt);
	if (ret)
		exit(ret);
	if (!keyStr) {
		ft_dprintf(2, "key: bad Format");
		exit(1);
	}
	ft_memset(key, '0', 16);
	ft_memcpy(key, keyStr, ft_strlen(keyStr) <= 16 ? ft_strlen(keyStr) : 16);
	key[16] = 0;
}

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
	t_optpars opt;
	char	keyStr[17];
	unsigned long key, keys[16], data[DES_SIZE_READ], cipherText[DES_SIZE_READ];
	int isDecode, isBase64;
	ssize_t len = 0, prevLen = 0;

	optionsDesECB(argv, keyStr, &opt);
	isDecode = ft_tabfind(opt.opt, "-d");
	isBase64 = ft_tabfind(opt.opt, "-a");
	key = atoi_hex(keyStr);

	generateKey(key, keys);
	if (isDecode) {
		revTabLong(keys, 16);
	}
	while ((len = turboRead(0, data, 8 * DES_SIZE_READ, isDecode & isBase64)) >= 0) {
		int index;

		if (isDecode && !len && prevLen) prevLen -= ((unsigned char*)cipherText)[prevLen - 1];
		if (!isDecode && isBase64) {
			base64Encode((char *)cipherText, prevLen, 1);
		} else {
			write(1, cipherText, prevLen);
		}

		prevLen = len;
		if (!isDecode && len != 8 * DES_SIZE_READ) {
			prevLen = desPadding(data, len);
		}
		if (isDecode && isBase64) prevLen = base64DecodeRC((unsigned char *)data, len, (unsigned char *)data);
		for (index = 0; index < prevLen / 8; index++) {
			if (isDecode) {
				cipherText[index] = desEncrypt(data[index], keys);
			} else {
				cipherText[index] = desEncrypt(data[index], keys);
			}
		}
		if (len != 8 * DES_SIZE_READ) break;
	}
	if (isDecode && prevLen && ((unsigned char*)cipherText)[prevLen - 1] <= 8) prevLen -= ((unsigned char*)cipherText)[prevLen - 1];
	if (!isDecode && isBase64) {
		base64Encode((char *)cipherText, prevLen, 1);
	} else {
		write(1, cipherText, prevLen);
	}
}