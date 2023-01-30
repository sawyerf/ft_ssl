#include "libft.h"
#include "ft_ssl.h"
#include <fcntl.h> 
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

typedef struct	s_read {
	unsigned long salted[2];
	unsigned long cipherText[DES_SIZE_READ];
	ssize_t prevLen;
	ssize_t	sizeRead;
}				t_read;

t_read g_read;

void revTabLong(unsigned long *tab, int size) {
	unsigned long tmp;

	for (int index = 0; index < size / 2; index++) {
		tmp = tab[index];
		tab[index] = tab[size - 1 - index];
		tab[size - 1 - index] = tmp;
	}
}

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

void setKey(t_router_des *route, t_optpars *optpars, t_des *desO, char *keyArg, char *passArg, char *saltArg, char *ivArg) {
	unsigned long salt;
	int isLol = 0;
	int isGetPass = 0;
	unsigned long data[DES_SIZE_READ];

	if (keyArg) desO->key = keyToLong(keyArg, "Key");
	if (ivArg)  desO->iv = swap64(keyToLong(ivArg, "IV"));
	if (!keyArg || !ivArg) {
		t_hash hash;
		int isIV = ft_strcmp("des-ecb", route->name);

		if (!passArg && !keyArg) {
			passArg = getpass("Password: ");
			isGetPass = 1;
		}
		if (!saltArg && desO->isDecode && isIV) {
			ft_bzero(data, 8 * DES_SIZE_READ);
			isLol = 1;

			int len = turboRead(desO->fdInput, data, 32, desO->isDecode & desO->isBase64);
			g_read.prevLen = len;
			if (desO->isBase64) g_read.prevLen = base64Decode((unsigned char *)data, len, (char *)data);
			// print_hex((void*)data, g_read.prevLen);
			if (g_read.prevLen >= 16 && !ft_strncmp("Salted__", (void*)data, 8)) {
				salt = swap64(data[1]);
				g_read.prevLen -= 16;
				ft_memcpy(data, data + 2, g_read.prevLen);
			} else {
				ft_dprintf(2, "Error: Need Salt\n");
				exit(1);
			}
		} else if (!saltArg) {
			srandom(time(NULL));
			salt = random() | random() << 32;
			if (isIV) ft_memcpy(g_read.salted, "Salted__", 8);
			g_read.salted[1] = swap64(salt);
			g_read.sizeRead = 8;
		} else {
			salt = keyToLong(saltArg, "Salt");
		}
		if (passArg) {
			pbkdf2(passArg, salt, &hash, desO->iterArg);
			if (isGetPass) free(passArg);
		} else {
			pbkdf2("", salt, &hash, desO->iterArg);
		}
		if (!keyArg) {
			ft_memcpy(&desO->key, &hash.H0, 2 * 4);
			desO->key = swap64(desO->key);
		}
		if (!ivArg) {
			ft_memcpy(&desO->iv, &hash.H2, 2 * 4);
		}
		if (!ft_tabfind(optpars->opt, "-q")) ft_dprintf(2, "salt=%016lX\nkey=%016lX\niv=%016lX\n", salt, desO->key, desO->iv);
	}
	generateKey(desO->key, desO->keys);
	if (desO->isDecode && route->isPadding) {
		revTabLong(desO->keys, 16);
	}
	if (isLol) {
		for (int index = 0; index < (g_read.prevLen + (8 - (g_read.prevLen % 8)) % 8) / 8; index++) {
			g_read.cipherText[index] = route->decode(desO, data[index], desO->keys);
		}
	}
}

void optionsDes(char **argv, t_optpars *optpars, t_des *desO, t_router_des *route) {
	t_opt	*opt;
	unsigned char ret;
	char	*input = NULL,
			*output = NULL;

	ft_bzero(optpars, sizeof(t_optpars));
	opt_init(&opt);
	desO->iterArg = 1000;
	opt_addvar2(&opt, "-k", (void**)&desO->keyArg, OPT_STR);
	opt_addvar2(&opt, "-d", NULL, 0);
	opt_addvar2(&opt, "-a", NULL, 0);
	opt_addvar2(&opt, "-e", NULL, 0);
	opt_addvar2(&opt, "-q", NULL, 0);
	opt_addvar2(&opt, "-i", (void**)&input, OPT_STR);
	opt_addvar2(&opt, "-o", (void**)&output, OPT_STR);
	opt_addvar2(&opt, "-v", (void**)&desO->ivArg, OPT_STR);
	opt_addvar2(&opt, "-p", (void**)&desO->passArg, OPT_STR);
	opt_addvar2(&opt, "-s", (void**)&desO->saltArg, OPT_STR);
	opt_addvar(&opt,  "--iter", (void*)&desO->iterArg, OPT_INT);
	ret = opt_parser(opt, argv, optpars, "ft_ssl");
	opt_free(&opt);
	if (ret)
		exit(ret);

	if (desO->iterArg <= 0) {
		ft_dprintf(2, "Non-positive number `%d' for option --iter\n", desO->iterArg);
		exit(1);
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
	if (output && (desO->fdOutput = open(output, O_RDWR | O_CREAT | O_TRUNC, 0644)) < 0) {
		ft_dprintf(2, "ERROR: Can't open file `%s'\n", output);
		exit(1);
	}
	setKey(route, optpars, desO, desO->keyArg, desO->passArg, desO->saltArg, desO->ivArg);
}

void printDes(t_des *desO, t_router_des *route, int isEnd) {
	unsigned char padding = ((unsigned char*)g_read.cipherText)[g_read.prevLen - 1];

	if (isEnd && desO->isDecode && route->isPadding && g_read.prevLen) {
		if (padding > 8 || (ssize_t)padding > g_read.prevLen) {
			ft_dprintf(2, "Wrong padding\n", g_read.prevLen, padding, padding);
			exit(1);
		}
		g_read.prevLen -= padding;
	}
	if (g_read.salted[0] && (g_read.prevLen || isEnd)) {
		unsigned long tmp;

		tmp = g_read.cipherText[0];
		ft_memcpy(g_read.cipherText, g_read.salted, 16);
		ft_memcpy(g_read.cipherText + 2, &tmp, g_read.prevLen);
		g_read.prevLen += 16;
		g_read.salted[0] = 0;
	}
	if (!desO->isDecode && desO->isBase64) {
		base64Encode((unsigned char *)g_read.cipherText, g_read.prevLen, desO->fdOutput);
		if (g_read.prevLen) ft_dprintf(desO->fdOutput, "\n");
	} else {
		write(desO->fdOutput, g_read.cipherText, g_read.prevLen);
	}
}

void routerDES(char **argv, t_router_des *route) {
	t_des	desO;
	t_optpars opt;
	ssize_t len = 0;
	unsigned long data[DES_SIZE_READ];

	ft_bzero(&desO, sizeof(t_des));
	ft_bzero(&g_read, sizeof(t_read));

	g_read.sizeRead = 8 * DES_SIZE_READ;
	optionsDes(argv, &opt, &desO, route);
	while ((len = turboRead(desO.fdInput, data, g_read.sizeRead, desO.isDecode & desO.isBase64)) >= 0) {
		int index;

		if (desO.isDecode && !len) break;
		printDes(&desO, route, 0);
		g_read.prevLen = len;
		if (len != g_read.sizeRead && !desO.isDecode && route->isPadding) {
			g_read.prevLen = desPadding(data, len);
		}
		if (desO.isDecode && desO.isBase64) g_read.prevLen = base64Decode((unsigned char *)data, len, (char *)data);
		for (index = 0; index < (g_read.prevLen + (8 - (g_read.prevLen % 8)) % 8) / 8; index++) {
			if (desO.isDecode) {
				g_read.cipherText[index] = route->decode(&desO, data[index], desO.keys);
			} else {
				g_read.cipherText[index] = route->encode(&desO, data[index], desO.keys);
			}
		}
		if (len != g_read.sizeRead) break;
		g_read.sizeRead = 8 * DES_SIZE_READ;
	}
	printDes(&desO, route, 1);
}