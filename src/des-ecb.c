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
	unsigned long key;
	unsigned long keys[16];

	optionsDesECB(argv, &keyStr, &opt);
	if (!keyStr || ft_strlen(keyStr) != 16) {
		ft_dprintf(2, "key: bad Format");
		exit(1);
	}
	key = atoi_hex(keyStr);
	generateKey(key, keys);
	int len = ft_strlen(opt.arg[0]);
	for (int index = 0; index < len; index += 8) {
		unsigned long lol = desEncrypt(((unsigned long *)(opt.arg[0] + index))[0], keys);
		// ft_printf("%d\n", lol);
	}
}