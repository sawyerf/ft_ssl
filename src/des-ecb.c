#include "libft.h"
#include "ft_ssl.h"
#include <fcntl.h> 

void optionsDesECB(char **argv, t_optpars *optpars, char *key, int *isDecode, int *fdInput, int *fdOutput) {
	t_opt	*opt;
	unsigned char ret;
	char *keyStr = NULL;
	char *input, *output;

	ft_bzero(optpars, sizeof(t_optpars));
	opt_init(&opt);
	opt_addvar2(&opt, "-k", (void*)&keyStr, OPT_STR);
	opt_addvar2(&opt, "-d", NULL, 0);
	opt_addvar2(&opt, "-a", NULL, 0);
	opt_addvar2(&opt, "-e", NULL, 0);
	opt_addvar2(&opt, "-i", (void**)&input, OPT_STR); // TODO
	opt_addvar2(&opt, "-o", (void**)&output, OPT_STR); // TODO
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

	*isDecode = 1;
	if (ft_tabfind(optpars->opt, "-e") || !ft_tabfind(optpars->opt, "-d")) {
		*isDecode = 0;
	}
	if (input && (*fdInput = open(input, O_RDONLY)) < 0) {
		ft_dprintf(2, "ERROR: Can't open file `%s'\n", input);
		exit(1);
	}
	if (output && (*fdOutput = open(output, O_RDWR | O_CREAT, 0644)) < 0) {
		ft_dprintf(2, "ERROR: Can't open file `%s'\n", output);
		exit(1);
	}
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
	int fdInput = 0, fdOutput = 1;
	ssize_t len = 0, prevLen = 0;

	optionsDesECB(argv, &opt, keyStr, &isDecode, &fdInput, &fdOutput);
	isBase64 = ft_tabfind(opt.opt, "-a");
	key = atoi_hex(keyStr);

	bzero(cipherText, DES_SIZE_READ * 8);
	generateKey(key, keys);
	if (isDecode) {
		revTabLong(keys, 16);
	}
	while ((len = turboRead(fdInput, data, 8 * DES_SIZE_READ, isDecode & isBase64)) >= 0) {
		int index;

		if (isDecode && !len && prevLen) prevLen -= ((unsigned char*)cipherText)[prevLen - 1];
		if (!isDecode && isBase64) {
			base64Encode((char *)cipherText, prevLen, fdOutput);
		} else {
			write(fdOutput, cipherText, prevLen);
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
	unsigned char padding = ((unsigned char*)cipherText)[prevLen - 1];
	if (isDecode && prevLen && (padding > 8 || padding > prevLen | !padding)) {
		ft_dprintf(2, "Wrong padding\n", prevLen, padding, padding);
		exit(1);
	}
	if (isDecode && prevLen && (((unsigned char*)cipherText)[prevLen - 1] <= len)) prevLen -= ((unsigned char*)cipherText)[prevLen - 1];
	if (!isDecode && isBase64) {
		base64Encode((char *)cipherText, prevLen, fdOutput);
	} else {
		write(fdOutput, cipherText, prevLen);
	}
}