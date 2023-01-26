#include "libft.h"
#include "ft_ssl.h"
#include <fcntl.h> 
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

typedef struct	s_read {
	unsigned long cipherText[DES_SIZE_READ];
	ssize_t prevLen;
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

void setKey(t_router_des *route, t_des *desO, char *keyArg, char *passArg, char *saltArg, char *ivArg) {
	unsigned long salt;
	int isLol = 0;
	unsigned long data[DES_SIZE_READ];

	if (keyArg) desO->key = keyToLong(keyArg, "Key");
	if (ivArg)  desO->iv = swap64(keyToLong(ivArg, "IV"));
	if (!keyArg || !ivArg) {
		t_hash hash;

		if (!passArg && !keyArg) {
			passArg = getpass("Password: ");
		}
		if (!saltArg && desO->isDecode) {
			ft_bzero(data, 8 * DES_SIZE_READ);
			isLol = 1;

			int len = turboRead(desO->fdInput, data, 32, desO->isDecode & desO->isBase64);
			g_read.prevLen = len;
			if (desO->isBase64) g_read.prevLen = base64Decode((unsigned char *)data, len, (char *)data);
			if (g_read.prevLen >= 16 && !ft_strncmp("Salted__", (void*)data, 8)) {
				salt = swap64(data[1]);
				g_read.prevLen -= 16;
				ft_memcpy(data, data + 2, g_read.prevLen);
			} else {
				ft_dprintf(2, "Error: Need Salt");
				exit(1);
			}
		} else if (!saltArg) {
			srandom(time(NULL));
			salt = swap64(random() | random() << 32);
			write(desO->fdOutput, "Salted__", 8);
			write(desO->fdOutput, &salt, 8);
			salt = swap64(salt);
		} else {
			salt = swap64(keyToLong(saltArg, "Salt"));
		}
		if (passArg) {
			pbkdf2(passArg, salt, &hash, 1000);
		} else {
			pbkdf2("", salt, &hash, 1000);
		}
		if (!keyArg) {
			ft_memcpy(&desO->key, &hash.H0, 2 * 4);
			desO->key = swap64(desO->key);
		}
		if (!ivArg) {
			ft_memcpy(&desO->iv, &hash.H2, 2 * 4);
		}
	}
	ft_dprintf(2, "salt=%016lX\nkey=%016lX\niv=%016lX\n", salt, desO->key, desO->iv);
	generateKey(desO->key, desO->keys);
	if (desO->isDecode && route->isPadding) {
		revTabLong(desO->keys, 16);
	}
	if (isLol) {
		for (int index = 0; index < (g_read.prevLen + (8 - (g_read.prevLen % 8)) % 8) / 8; index++) {
			g_read.cipherText[index] = route->decode(desO, data[index], desO->keys);
			print_hex((void*)g_read.cipherText, g_read.prevLen);
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
	opt_addvar2(&opt, "-k", (void**)&desO->keyArg, OPT_STR);
	opt_addvar2(&opt, "-d", NULL, 0);
	opt_addvar2(&opt, "-a", NULL, 0);
	opt_addvar2(&opt, "-e", NULL, 0);
	opt_addvar2(&opt, "-i", (void**)&input, OPT_STR);
	opt_addvar2(&opt, "-o", (void**)&output, OPT_STR);
	opt_addvar2(&opt, "-v", (void**)&desO->ivArg, OPT_STR);
	opt_addvar2(&opt, "-p", (void**)&desO->passArg, OPT_STR);
	opt_addvar2(&opt, "-s", (void**)&desO->saltArg, OPT_STR);
	ret = opt_parser(opt, argv, optpars, "ft_ssl");
	opt_free(&opt);
	if (ret)
		exit(ret);

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
	setKey(route, desO, desO->keyArg, desO->passArg, desO->saltArg, desO->ivArg);
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
	if (!desO->isDecode && desO->isBase64) {
		base64Encode((unsigned char *)g_read.cipherText, g_read.prevLen, desO->fdOutput);
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

	optionsDes(argv, &opt, &desO, route);
	while ((len = turboRead(desO.fdInput, data, 8 * DES_SIZE_READ, desO.isDecode & desO.isBase64)) >= 0) {
		int index;

		if (desO.isDecode && !len) break;
		printDes(&desO, route, 0);
		g_read.prevLen = len;
		if (len != 8 * DES_SIZE_READ && !desO.isDecode && route->isPadding) {
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
		if (len != 8 * DES_SIZE_READ) break;
	}
	printDes(&desO, route, 1);
}