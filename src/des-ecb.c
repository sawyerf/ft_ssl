#include "libft.h"
#include "ft_ssl.h"
#include <fcntl.h> 
#include <stdlib.h>
#include <time.h>

void optionsDesECB(char **argv, t_optpars *optpars, t_des *desO) {
	t_opt	*opt;
	unsigned char ret;
	char *keyStr = NULL;
	char	*input = NULL,
			*output = NULL,
			*ivStr = NULL,
			*passStr = NULL,
			*saltStr = NULL;

	ft_bzero(optpars, sizeof(t_optpars));
	opt_init(&opt);
	opt_addvar2(&opt, "-k", (void**)&keyStr, OPT_STR);
	opt_addvar2(&opt, "-d", NULL, 0);
	opt_addvar2(&opt, "-a", NULL, 0);
	opt_addvar2(&opt, "-e", NULL, 0);
	opt_addvar2(&opt, "-i", (void**)&input, OPT_STR);
	opt_addvar2(&opt, "-o", (void**)&output, OPT_STR);
	opt_addvar2(&opt, "-v", (void**)&ivStr, OPT_STR); // TODO
	opt_addvar2(&opt, "-p", (void**)&passStr, OPT_STR); // TODO
	opt_addvar2(&opt, "-s", (void**)&saltStr, OPT_STR); // TODO
	ret = opt_parser(opt, argv, optpars, "ft_ssl");
	opt_free(&opt);
	if (ret)
		exit(ret);
	if (!keyStr) {
		t_hash hash;
		unsigned long salt;

		if (!saltStr) {
			srandom(time(NULL));
			salt = random() | random() << 32;
		} else {
			char saltStr2[17];
			ft_memset(saltStr2, '0', 16);
			ft_memcpy(saltStr2, saltStr, ft_strlen(saltStr2) <= 16 ? ft_strlen(saltStr2) : 16);
			saltStr2[16] = 0;
			salt = atoi_hex(saltStr2);
		}
		if (!passStr) {
			// TODO: Ask paddword
			exit(1);
		}
		pbkdf2(passStr, salt, &hash);
		desO->key = hash.HH0;
		desO->iv = hash.HH1;
		ft_printf("salt=%lX\nkey=%lX\niv=%lX\n", salt, desO->key, desO->iv);
	} else {
		if (!isHex(keyStr)) {
			ft_dprintf(2, "key: Bad format\n");
			exit(1);
		}
		ft_memset(desO->keyStr, '0', 16);
		ft_memcpy(desO->keyStr, keyStr, ft_strlen(keyStr) <= 16 ? ft_strlen(keyStr) : 16);
		desO->keyStr[16] = 0;
		desO->key = atoi_hex(desO->keyStr);
	}

	desO->isBase64 = ft_tabfind(optpars->opt, "-a");
	desO->isDecode = 1;
	if (ft_tabfind(optpars->opt, "-e") || !ft_tabfind(optpars->opt, "-d")) {
		desO->isDecode = 0;
	}
	desO->fdOutput = 1;
	if (input && (desO->fdInput = open(input, O_RDONLY)) < 0) {
		ft_dprintf(2, "ERROR: Can't open file `%s'\n", input);
		exit(1);
	}
	if (output && (desO->fdOutput = open(output, O_RDWR | O_CREAT, 0644)) < 0) {
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
				cipherText[index] = desEncrypt(data[index], keys);
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