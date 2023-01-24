#include "libft.h"
#include "ft_ssl.h"
#include <fcntl.h> 
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

unsigned long keyToLong(char *key, char *name) {
	char keyStr[17];

	if (!isHex(key)) {
		ft_dprintf(2, "%s: Bad format\n", name);
		exit(1);
	}
	ft_memset(keyStr, '0', 16);
	ft_memcpy(keyStr, key, ft_strlen(key) <= 16 ? ft_strlen(key) : 16);
	keyStr[16] = 0;
	return atoi_hex(keyStr);
}

void setKey(t_des *desO, char *keyArg, char *passArg, char *saltArg, char *ivArg) {
	if (keyArg) desO->key = keyToLong(keyArg, "Key");
	if (ivArg)  desO->iv = keyToLong(ivArg, "IV");
	if (!keyArg || !ivArg) {
		t_hash hash;
		unsigned long salt;

		if (!saltArg) {
			srandom(time(NULL));
			salt = random() | random() << 32;
		} else {
			salt = keyToLong(saltArg, "Salt");
		}
		if (passArg) {
			pbkdf2(passArg, salt, &hash);
		} else if (keyArg) {
			pbkdf2("", salt, &hash);
		} else {
			passArg = getpass("Password: ");
			pbkdf2(passArg, salt, &hash);
			free(passArg);
		}
		if (!keyArg) desO->key = (unsigned long)hash.H0 << 32 | hash.H1;
		if (!ivArg)  desO->iv = (unsigned long)hash.H2 << 32 | hash.H3;
		ft_dprintf(2, "salt=%016lx\nkey=%016lX\niv=%016lX\n", salt, desO->key, desO->iv);
	}
	desO->iv = swap64(desO->iv);
}

void optionsDes(char **argv, t_optpars *optpars, t_des *desO) {
	t_opt	*opt;
	unsigned char ret;
	char	*keyArg = NULL,
	    	*input = NULL,
			*output = NULL,
			*ivArg = NULL,
			*passArg = NULL,
			*saltArg = NULL;

	ft_bzero(optpars, sizeof(t_optpars));
	opt_init(&opt);
	opt_addvar2(&opt, "-k", (void**)&keyArg, OPT_STR);
	opt_addvar2(&opt, "-d", NULL, 0);
	opt_addvar2(&opt, "-a", NULL, 0);
	opt_addvar2(&opt, "-e", NULL, 0);
	opt_addvar2(&opt, "-i", (void**)&input, OPT_STR);
	opt_addvar2(&opt, "-o", (void**)&output, OPT_STR);
	opt_addvar2(&opt, "-v", (void**)&ivArg, OPT_STR); // TODO
	opt_addvar2(&opt, "-p", (void**)&passArg, OPT_STR); // TODO
	opt_addvar2(&opt, "-s", (void**)&saltArg, OPT_STR); // TODO
	ret = opt_parser(opt, argv, optpars, "ft_ssl");
	opt_free(&opt);
	if (ret)
		exit(ret);

	setKey(desO, keyArg, passArg, saltArg, ivArg);
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

void routerDES(char **argv, t_router_des *route) {
	t_des	desO;
	t_optpars opt;
	unsigned long keys[16], data[DES_SIZE_READ], cipherText[DES_SIZE_READ];
	ssize_t len = 0, prevLen = 0;

	ft_bzero(&desO, sizeof(t_des));
	ft_bzero(cipherText, DES_SIZE_READ * 8);

	optionsDes(argv, &opt, &desO);

	generateKey(desO.key, keys);
	if (desO.isDecode && route->isPadding) {
		revTabLong(keys, 16);
	}
	while ((len = turboRead(desO.fdInput, data, 8 * DES_SIZE_READ, desO.isDecode & desO.isBase64)) >= 0) {
		int index;

		if (desO.isDecode && !len && prevLen && route->isPadding) prevLen -= ((unsigned char*)cipherText)[prevLen - 1];
		if (!desO.isDecode && desO.isBase64) {
			base64Encode((unsigned char *)cipherText, prevLen, desO.fdOutput);
		} else {
			write(desO.fdOutput, cipherText, prevLen);
		}

		prevLen = len;
		if (!desO.isDecode && len != 8 * DES_SIZE_READ && route->isPadding) {
			prevLen = desPadding(data, len);
		}
		
		if (desO.isDecode && desO.isBase64) prevLen = base64Decode((unsigned char *)data, len, (char *)data);
		for (index = 0; index < (prevLen + (8 - (prevLen % 8)) % 8) / 8; index++) {
			if (desO.isDecode) {
				cipherText[index] = route->decode(&desO, data[index], keys);
			} else {
				cipherText[index] = route->encode(&desO, data[index], keys);
			}
		}
		if (len != 8 * DES_SIZE_READ) break;
	}
	unsigned char padding = ((unsigned char*)cipherText)[prevLen - 1];
	if (desO.isDecode && prevLen && (padding > 8 || (ssize_t)padding > (prevLen | !padding)) && route->isPadding) {
		ft_dprintf(2, "Wrong padding\n", prevLen, padding, padding);
		exit(1);
	}
	if (desO.isDecode && prevLen && (((unsigned char*)cipherText)[prevLen - 1] <= len) && route->isPadding) prevLen -= ((unsigned char*)cipherText)[prevLen - 1];
	if (!desO.isDecode && desO.isBase64) {
		base64Encode((unsigned char *)cipherText, prevLen, desO.fdOutput);
	} else {
		write(desO.fdOutput, cipherText, prevLen);
	}
}