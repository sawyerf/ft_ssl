#include "libft.h"
#include "ft_ssl.h"

void optionsDesECB(char **argv, char **key, t_optpars *optpars) {
	t_opt	*opt;
	unsigned char ret;

	ft_bzero(optpars, sizeof(t_optpars));
	opt_init(&opt);
	opt_addvar2(&opt, "-k", (void*)key, OPT_STR);
	opt_addvar2(&opt, "-d", NULL, 0);
	ret = opt_parser(opt, argv, optpars, "ft_ssl");
	opt_free(&opt);
	if (ret)
		exit(ret);
	if (!*key || ft_strlen(*key) != 16) {
		ft_dprintf(2, "key: bad Format");
		exit(1);
	}
	// isDebug = ft_tabfind(optpars->opt, "-v") > 0;
}

void revTabLong(unsigned long *tab, int size) {
	unsigned long tmp;

	for (int index = 0; index < size / 2; index++) {
		tmp = tab[index];
		tab[index] = tab[size - 1 - index];
		tab[size - 1 - index] = tmp;
	}
}

void desECB_Router(char **argv) {
	t_optpars opt;
	char	*keyStr = NULL;
	unsigned long key, keys[16], data[3], cipherText[3];
	int isDecode;
	ssize_t len = 0, prevLen = 0;
	int oneTwoThree = 0;

	optionsDesECB(argv, &keyStr, &opt);
	isDecode = ft_tabfind(opt.opt, "-d");
	key = atoi_hex(keyStr);

	generateKey(key, keys);
	if (isDecode) {
		revTabLong(keys, 16);
	}
	while ((len = turboRead(0, data, 8 * 3)) >= 0) {
		int index;

		// if (isDecode && !len) break;
		if (isDecode && !len) prevLen -= ((unsigned char*)cipherText)[prevLen - 1];
		write(1, cipherText, prevLen);

		prevLen = len;
		if (!isDecode && len != 8*3) {
			prevLen = desPadding(data, len);
		}
		for (index = 0; index < prevLen / 8; index++) {
			if (isDecode) {
				// base64DecodeRC((unsigned char*)data, len, (unsigned char*)data);
				cipherText[index] = desEncrypt(data[index], keys);
			} else {
				cipherText[index] = desEncrypt(data[index], keys);
			}
		}
		// if (!ft_tabfind(opt.opt, "-d")) base64Encode((char *)cipherText, len, 1);
		if (len != 8*3) break;
	}
	if (isDecode && prevLen) prevLen -= ((unsigned char*)cipherText)[prevLen - 1];
	write(1, cipherText, prevLen);
}