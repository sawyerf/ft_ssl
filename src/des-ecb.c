#include "libft.h"
#include "ft_ssl.h"

void optionsDesECB(char **argv, char **key, t_optpars *optpars) {
	t_opt	*opt;
	unsigned char ret;

	ft_bzero(optpars, sizeof(t_optpars));
	opt_init(&opt);
	opt_addvar2(&opt, "-k", (void*)key, OPT_STR);
	ret = opt_parser(opt, argv, optpars, "ft_ssl");
	opt_free(&opt);
	if (ret)
		exit(ret);
	// isDebug = ft_tabfind(optpars->opt, "-v") > 0;
}

void desECB_Router(char **argv) {
	t_optpars opt;
	char	*keyStr = NULL;
	unsigned long key, keys[16], data[3], cipherText[3];
	int len = 0;

	optionsDesECB(argv, &keyStr, &opt);
	if (!keyStr || ft_strlen(keyStr) != 16) {
		ft_dprintf(2, "key: bad Format");
		exit(1);
	}
	key = atoi_hex(keyStr);

	generateKey(key, keys);
	while ((len = turboRead(0, data, 8 * 3)) > 0) {
		int index;

		if (len != 8*3) {
			desPadding(data, len);
			len = len + (8 - len % 8);
		}
		for (index = 0; index < len / 8; index++) {
			cipherText[index] = desEncrypt(data[index], keys);
		}
		base64Encode((char *)cipherText, len, 1);
		if (len != 8*3) break;
	}
}